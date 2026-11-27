module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Std.Data.HashMap
public import Std.Data.HashSet

@[expose] public section

/-!
# SMT terms

A term is a literal or a reference `vN` to an SMT-LIB definition. Definitions
are hash-consed on their text, so an unchanged value is never re-encoded.

Every definition carries an interval. Constructors fold literals and decide
comparisons from intervals. Hard assertions (actions' guards and
observations) narrow intervals globally and propagate the narrowing to the
operands of the asserted term (`narrow`), so a value pinned by an observation
becomes a literal and everything computed from it afterwards folds. This is
only a simplifier: every narrowing is implied by the hard assertions, and the
emitted script contains all of them.

Bounds and enabled initial invariants are hard constraints for each attempt.
Interval ends are `Option Int`, where `none` is unbounded.
-/

namespace Consensus.MidTrace.Smt

/-- `f` on two interval ends; unbounded if either is. -/
def both (f : Int → Int → Int) (a b : Option Int) : Option Int := do
  return f (← a) (← b)

/-- `a < b` for finite ends; `false` if either is unbounded. -/
def ltB : Option Int → Option Int → Bool
  | some a, some b => a < b
  | _, _ => false

/-- `a <= b` for finite ends; `false` if either is unbounded. -/
def leB : Option Int → Option Int → Bool
  | some a, some b => a <= b
  | _, _ => false

inductive Tm where
  | int (value : Int)
  | bool (value : Bool)
  | ref (id : Nat)
deriving BEq, Hashable, Inhabited, Repr

def Tm.smt : Tm → String
  | .int value => if value < 0 then s!"(- {-value})" else toString value
  | .bool value => if value then "true" else "false"
  | .ref id => s!"v{id}"

/-- How a definition relates to other terms, for propagating narrowings. -/
inductive Shape where
  | none
  | not (x : Nat)
  /-- `x <= k` -/
  | le (x : Nat) (k : Int)
  /-- `k <= x` -/
  | ge (x : Nat) (k : Int)
  | eq (x : Nat) (k : Int)
  | eqv (x y : Nat)
  | and (parts : Array Nat)
  | or (parts : Array Nat)
  | add (x : Nat) (k : Int)
  /-- `x + y` -/
  | sum (x y : Nat)
  | ite (c : Nat) (a b : Tm)
deriving Inhabited

structure Info where
  isBool : Bool
  lo : Option Int
  hi : Option Int
  shape : Shape := .none
  /-- A simpler equal term, found after the definition was emitted. -/
  equal : Option Tm := none
  /-- Values strictly inside `[lo, hi]` that are excluded. -/
  holes : Array Int := #[]
deriving Inhabited

/-- The only value of `i`, if it has one. -/
def Info.value? (i : Info) : Option Int :=
  match i.lo, i.hi with
  | some lo, some hi => if lo == hi then some lo else none
  | _, _ => none

/-- Moves the bounds of `i` past excluded values; `none` if no value remains. -/
def Info.tighten (i : Info) : Option Info :=
  Id.run do
    let mut lo := i.lo
    let mut hi := i.hi
    while lo.any fun l => hi.all (l <= ·) && i.holes.contains l do
      lo := lo.map (· + 1)
    while hi.any fun h => lo.all (· <= h) && i.holes.contains h do
      hi := hi.map (· - 1)
    if ltB hi lo then return none
    return some
      { i with lo, hi, holes := i.holes.filter fun h => lo.all (· < h) && hi.all (h < ·) }

structure Enc where
  infos : Array Info := #[]
  cons : Std.HashMap String Nat := {}
  out : Array String := #[]
  /-- Narrow intervals with hard assertions. -/
  refine : Bool := true
  /-- The instruction being encoded, zero-based. -/
  instruction : Nat := 0
  /-- The first hard assertion found false while encoding. -/
  falsified : Option (Nat × String) := none
  /--
  The instruction at which, and why, the encoding cannot represent the trace; the verdict
  is then unknown.
  -/
  unsupported : Option (Nat × String) := none
  /-- Branch selectors explicitly marked for backbone probes. -/
  selectors : Std.HashSet Nat := {}
  /-- A probe variable whose undecided comparisons with literals are recorded in `hits`. -/
  watch : Option Nat := none
  hits : Array Int := #[]

abbrev M := StateM Enc

def emit (line : String) : M Unit :=
  modify fun enc => { enc with out := enc.out.push line }

def info (id : Nat) : M Info := do
  return (← get).infos[id]!

def setInfo (id : Nat) (value : Info) : M Unit :=
  modify fun enc => { enc with infos := enc.infos.set! id value }

def literal (isBool : Bool) (value : Int) : Tm :=
  if isBool then .bool (value == 1) else .int value

def NORM_DEPTH : Nat := 4

/--
The simplest known form of `t`. Definitions whose operands have since become
known are re-evaluated up to `depth` levels and aliased to the result.
-/
partial def normD (depth : Nat) (t : Tm) : M Tm := do
  let .ref id := t | return t
  let i ← info id
  if let some target := i.equal then
    let result ← normD depth target
    unless result == target do
      setInfo id { i with equal := some result }
    return result
  if let some value := i.value? then return literal i.isBool value
  if depth == 0 then return t
  let resolved : Option Tm ←
    match i.shape with
    | .ite c a b =>
        match ← normD (depth - 1) (.ref c) with
        | .bool true => pure (some a)
        | .bool false => pure (some b)
        | _ => pure none
    | .not x =>
        match ← normD (depth - 1) (.ref x) with
        | .bool value => pure (some (.bool !value))
        | _ => pure none
    | .add x k =>
        match ← normD (depth - 1) (.ref x) with
        | .int value => pure (some (.int (value + k)))
        | _ => pure none
    | .le x k | .ge x k | .eq x k =>
        let x' ← normD (depth - 1) (.ref x)
        let (lo, hi, holes) ←
          match x' with
          | .int value => pure (some value, some value, #[])
          | .bool value =>
              pure (if value then (some 1, some 1, #[]) else (some 0, some 0, #[]))
          | .ref other => do
              let o ← info other
              pure (o.lo, o.hi, o.holes)
        match i.shape with
        | .le _ _ =>
            pure
              (if hi.any (· <= k) then
                  some (.bool true)
                else if lo.any (k < ·) then
                  some (.bool false)
                else
                  none)
        | .ge _ _ =>
            pure
              (if lo.any (k <= ·) then
                  some (.bool true)
                else if hi.any (· < k) then
                  some (.bool false)
                else
                  none)
        | _ =>
            pure
              (if lo == some k && hi == some k then
                  some (.bool true)
                else if lo.any (k < ·) || hi.any (· < k) || holes.contains k then
                  some (.bool false)
                else
                  none)
    | _ => pure none
  match resolved with
  | some target =>
      let result ← normD depth target
      setInfo id { (← info id) with equal := some result }
      return result
  | none => return t

def norm (t : Tm) : M Tm := normD NORM_DEPTH t

/-- `t` as `base + offset`, with `base` not itself an offset term. -/
def offsetOf (t : Tm) : M (Tm × Int) := do
  let t ← norm t
  let .ref id := t | return (t, 0)
  match (← info id).shape with
  | .add x k => return (← norm (.ref x), k)
  | _ => return (t, 0)

/-- The interval of `t`; `none` ends are unbounded. -/
def range (t : Tm) : M (Option Int × Option Int) := do
  match ← norm t with
  | .int value => return (some value, some value)
  | .bool value => return if value then (some 1, some 1) else (some 0, some 0)
  | .ref id =>
      let i ← info id
      return (i.lo, i.hi)

def isBoolTm (t : Tm) : M Bool := do
  match t with
  | .bool _ => return true
  | .int _ => return false
  | .ref id => return (← info id).isBool

def define (isBool : Bool) (text : String) (lo hi : Option Int) (shape : Shape := .none)
    : M Tm := do
  if let (some l, some h) := (lo, hi) then
    if l == h then return literal isBool l
  let enc ← get
  if let some id := enc.cons[text]? then return .ref id
  let id := enc.infos.size
  let sort := if isBool then "Bool" else "Int"
  set
    {
      enc with
        infos := enc.infos.push { isBool, lo, hi, shape }
        cons := enc.cons.insert text id
        out := enc.out.push s!"(define-fun v{id} () {sort} {text})"
    }
  return .ref id

/-- A Boolean definition. -/
def defineBool (text : String) (shape : Shape := .none) : M Tm :=
  define true text (some 0) (some 1) shape

/-- A fresh constant; integers get their finite bounds asserted. -/
def declare (isBool : Bool) (lo hi : Option Int := none) : M Tm := do
  let enc ← get
  let id := enc.infos.size
  let lo := if isBool then some 0 else lo
  let hi := if isBool then some 1 else hi
  let mut out := enc.out.push s!"(declare-const v{id} {if isBool then "Bool" else "Int"})"
  if !isBool then
    if let some lo := lo then out := out.push s!"(assert (<= {(Tm.int lo).smt} v{id}))"
    if let some hi := hi then out := out.push s!"(assert (<= v{id} {(Tm.int hi).smt}))"
  set { enc with infos := enc.infos.push { isBool, lo, hi }, out }
  return .ref id

def declareBool : M Tm := declare true

/-! ## Constructors -/

def notT (a : Tm) : M Tm := do
  match ← norm a with
  | .bool value => return .bool !value
  | .int _ => return .bool false
  | .ref id =>
      match (← info id).shape with
      | .not x => norm (.ref x)
      | _ => defineBool s!"(not v{id})" (.not id)

def refIds (parts : Array Tm) : Array Nat :=
  parts.filterMap
    fun part =>
      match part with
      | .ref id => some id
      | _ => none

def andL (items : List Tm) : M Tm := do
  let mut parts : Array Tm := #[]
  for item in items do
    match ← norm item with
    | .bool true => pure ()
    | .bool false => return .bool false
    | t =>
        unless parts.contains t do
          parts := parts.push t
  match parts.size with
  | 0 => return .bool true
  | 1 => return parts[0]!
  | _ =>
      defineBool ("(and " ++ " ".intercalate (parts.map (·.smt)).toList ++ ")")
        (.and (refIds parts))

def orL (items : List Tm) : M Tm := do
  let mut parts : Array Tm := #[]
  for item in items do
    match ← norm item with
    | .bool false => pure ()
    | .bool true => return .bool true
    | t =>
        unless parts.contains t do
          parts := parts.push t
  match parts.size with
  | 0 => return .bool false
  | 1 => return parts[0]!
  | _ =>
      defineBool ("(or " ++ " ".intercalate (parts.map (·.smt)).toList ++ ")")
        (.or (refIds parts))

def impliesT (a b : Tm) : M Tm := do
  orL [← notT a, b]

/-- Records an undecided comparison of the watched probe with a literal. -/
def noteHit (a b : Tm) : M Unit := do
  let some p := (← get).watch | return
  match a, b with
  | .ref x, .int k | .int k, .ref x =>
      if x == p then modify fun enc => { enc with hits := enc.hits.push k }
  | _, _ => pure ()

/-- `a <= b` -/
def le (a b : Tm) : M Tm := do
  let (a, b) ←
    match ← offsetOf a, ← offsetOf b with
    | (x, i), (y, j) =>
        if x == y then
          pure (.int i, .int j)
        else
          match x, y with
          | .int x, _ => pure (.int (x + i - j), y)
          | _, .int y => pure (x, .int (y + j - i))
          | _, _ => pure (← norm a, ← norm b)
  if a == b then return .bool true
  let (la, ha) ← range a
  let (lb, hb) ← range b
  if leB ha lb then return .bool true
  if ltB hb la then return .bool false
  let shape :=
    match a, b with
    | .ref x, .int k => Shape.le x k
    | .int k, .ref x => Shape.ge x k
    | _, _ => .none
  noteHit a b
  defineBool s!"(<= {a.smt} {b.smt})" shape

def eqT (a b : Tm) : M Tm := do
  let (a, b) ←
    match ← offsetOf a, ← offsetOf b with
    | (x, i), (y, j) =>
        if x == y then
          pure (.int i, .int j)
        else
          match x, y with
          | .int x, .ref _ => pure (.int (x + i - j), y)
          | .ref _, .int y => pure (x, .int (y + j - i))
          | _, _ => pure (← norm a, ← norm b)
  if a == b then return .bool true
  match a, b with
  | .bool x, .bool y => return .bool (x == y)
  | .int x, .int y => return .bool (x == y)
  | .bool true, t | t, .bool true => return t
  | .bool false, t | t, .bool false => notT t
  | _, _ =>
      let (la, ha) ← range a
      let (lb, hb) ← range b
      if ltB ha lb || ltB hb la then return .bool false
      let excluded ←
        match a, b with
        | .ref x, .int k | .int k, .ref x => pure ((← info x).holes.contains k)
        | _, _ => pure false
      if excluded then return .bool false
      let (a, b) := if b.smt < a.smt then (b, a) else (a, b)
      let shape :=
        match a, b with
        | .ref x, .int k => Shape.eq x k
        | .int k, .ref x => Shape.eq x k
        | .ref x, .ref y => Shape.eqv x y
        | _, _ => .none
      noteHit a b
      defineBool s!"(= {a.smt} {b.smt})" shape

def eqK (a : Tm) (k : Int) : M Tm := eqT a (.int k)

def iteT (c a b : Tm) : M Tm := do
  match ← norm c with
  | .bool true => norm a
  | .bool false => norm b
  | .int _ => norm b
  | .ref cid =>
      let c := Tm.ref cid
      -- `ite c (ite c x _) (ite c _ y)` is `ite c x y`.
      let branch (t : Tm) (then_ : Bool) : M Tm := do
        let t ← norm t
        let .ref id := t | return t
        match (← info id).shape with
        | .ite c' x y => if c' == cid then norm (if then_ then x else y) else return t
        | _ => return t
      let a ← branch a true
      let b ← branch b false
      if a == b then return a
      if ← isBoolTm a then
        match a, b with
        | .bool true, .bool false => return c
        | .bool false, .bool true => notT c
        | .bool true, _ => orL [c, b]
        | .bool false, _ => andL [← notT c, b]
        | _, .bool true => orL [← notT c, a]
        | _, .bool false => andL [c, a]
        | _, _ => defineBool s!"(ite {c.smt} {a.smt} {b.smt})" (.ite cid a b)
      else
        let (la, ha) ← range a
        let (lb, hb) ← range b
        define false s!"(ite {c.smt} {a.smt} {b.smt})" (both min la lb) (both max ha hb)
          (.ite cid a b)

def addK (a : Tm) (k : Int) : M Tm := do
  let (a, k) ←
    match ← offsetOf a with
    | (.ref x, j) => pure (Tm.ref x, k + j)
    | _ => pure (← norm a, k)
  if k == 0 then return a
  match a with
  | .int value => return .int (value + k)
  | .ref id =>
      let (lo, hi) ← range a
      define false s!"(+ {a.smt} {(Tm.int k).smt})" (lo.map (· + k)) (hi.map (· + k))
        (.add id k)
  | _ => return a

def addT (a b : Tm) : M Tm := do
  match ← norm a, ← norm b with
  | .int x, b => addK b x
  | a, .int y => addK a y
  | a, b =>
      let (la, ha) ← range a
      let (lb, hb) ← range b
      let shape :=
        match a, b with
        | .ref x, .ref y => Shape.sum x y
        | _, _ => .none
      define false s!"(+ {a.smt} {b.smt})" (both (· + ·) la lb) (both (· + ·) ha hb) shape

def subT (a b : Tm) : M Tm := do
  match ← norm a, ← norm b with
  | a, .int y => addK a (-y)
  | a, b =>
      if a == b then return .int 0
      let (la, ha) ← range a
      let (lb, hb) ← range b
      define false s!"(- {a.smt} {b.smt})" (both (· - ·) la hb) (both (· - ·) ha lb)

def maxT (a b : Tm) : M Tm := do
  iteT (← le a b) b a

def minT (a b : Tm) : M Tm := do
  iteT (← le a b) a b

/-- `k * a` -/
def mulK (a : Tm) (k : Int) : M Tm := do
  match ← norm a with
  | .int value => return .int (value * k)
  | a =>
      if k == 0 then return .int 0
      if k == 1 then return a
      let (lo, hi) ← range a
      let (lo, hi) := if k > 0 then (lo, hi) else (hi, lo)
      define false s!"(* {(Tm.int k).smt} {a.smt})" (lo.map (· * k)) (hi.map (· * k))

/-- `t` clamped to `[lo, hi]`; it equals `t` whenever `t` is in `[lo, hi]`. -/
def clampT (t : Tm) (lo hi : Int) : M Tm := do
  let t ← norm t
  let (l, h) ← range t
  if l.any (lo <= ·) && h.any (· <= hi) then return t
  let lo' := l.elim lo fun l => max lo (min l hi)
  let hi' := h.elim hi fun h => min hi (max h lo)
  define false
    s!"(ite (<= {t.smt} {(Tm.int lo).smt}) {(Tm.int lo).smt} (ite (<= {(Tm.int hi).smt} {t.smt}) {(Tm.int hi).smt} {t.smt}))"
    (some lo') (some hi')

/-- The number of true terms in `bits`. -/
def countT (bits : Array Tm) : M Tm := do
  let mut known : Int := 0
  let mut parts : Array String := #[]
  for bit in bits do
    match ← norm bit with
    | .bool true => known := known + 1
    | .bool false => pure ()
    | t => parts := parts.push s!"(ite {t.smt} 1 0)"
  if parts.isEmpty then return .int known
  let sum := "(+ " ++ " ".intercalate parts.toList ++ s!" {known})"
  define false sum (some known) (some (known + parts.size))

def doubleT (a : Tm) : M Tm := do
  match ← norm a with
  | .int value => return .int (2 * value)
  | a =>
      let (lo, hi) ← range a
      define false s!"(* 2 {a.smt})" (lo.map (2 * ·)) (hi.map (2 * ·))

/-! ## Narrowing -/

mutual
  /-- Narrows `t` to `[lo, hi]`; `false` if that is empty. -/
  partial def narrowTm (t : Tm) (lo hi : Option Int) : M Bool := do
    match ← norm t with
    | .int value => return lo.all (· <= value) && hi.all (value <= ·)
    | .bool value =>
        let bit : Int := if value then 1 else 0
        return lo.all (· <= bit) && hi.all (bit <= ·)
    | .ref id => narrow id lo hi

  partial def narrow (id : Nat) (lo hi : Option Int) : M Bool := do
    let i ← info id
    let some n :=
      ({ i with lo := lo.merge max i.lo, hi := hi.merge min i.hi } : Info).tighten
    | return false
    let nlo := n.lo
    let nhi := n.hi
    if nlo == i.lo && nhi == i.hi then return true
    setInfo id n
    if i.isBool then
      if nlo != nhi then return true
      let value := nlo == some 1
      let bit : Option Int := some (if value then 0 else 1)
      match i.shape with
      | .not x => narrow x bit bit
      | .and parts =>
          if value then
            parts.allM fun part => narrow part (some 1) (some 1)
          else
            return true
      | .or parts =>
          if value then
            return true
          else
            parts.allM fun part => narrow part (some 0) (some 0)
      | .le x k => if value then narrow x none (some k) else narrow x (some (k + 1)) none
      | .ge x k => if value then narrow x (some k) none else narrow x none (some (k - 1))
      | .eq x k =>
          if value then
            narrow x (some k) (some k)
          else
            exclude x k
      | .eqv x y =>
          if value then
            let ox ← info x
            let oy ← info y
            return (← narrow x oy.lo oy.hi) && (← narrow y ox.lo ox.hi)
          else
            return true
      | .ite c a b => narrowIte c a b nlo nhi
      | _ => return true
    else
      match i.shape with
      | .add x k => narrow x (nlo.map (· - k)) (nhi.map (· - k))
      | .ite c a b => narrowIte c a b nlo nhi
      | _ => return true

  /-- Excludes `k` from the values of `x`; `false` if none remain. -/
  partial def exclude (x : Nat) (k : Int) : M Bool := do
    let o ← info x
    if o.lo.any (k < ·) || o.hi.any (· < k) || o.holes.contains k then return true
    if o.lo.all (· < k) && o.hi.all (k < ·) then
      setInfo x { o with holes := o.holes.push k }
      return true
    let some n := ({ o with holes := o.holes.push k } : Info).tighten | return false
    setInfo x { o with holes := n.holes }
    narrow x n.lo n.hi

  partial def narrowIte (c : Nat) (a b : Tm) (lo hi : Option Int) : M Bool := do
    let (la, ha) ← range a
    let (lb, hb) ← range b
    if ltB ha lo || ltB hi la then
      return (← narrow c (some 0) (some 0)) && (← narrowTm b lo hi)
    else if ltB hb lo || ltB hi lb then
      return (← narrow c (some 1) (some 1)) && (← narrowTm a lo hi)
    else
      return true
end

/-! ## Assertions -/

def falsify (description : String) : M Unit :=
  modify
    fun enc =>
      if enc.falsified.isSome then
        enc
      else
        { enc with falsified := some (enc.instruction, description) }

def unsupported (what : String) : M Unit :=
  modify
    fun enc =>
      if enc.unsupported.isSome then
        enc
      else
        { enc with unsupported := some (enc.instruction, what) }

/-- A hard assertion: an action's guard or an observation. -/
def require (t : Tm) (description : String) : M Unit := do
  let t ← norm t
  if t == .bool true then return
  emit s!"(assert {t.smt})"
  if t == .bool false then
    falsify description
  else if (← get).refine then
    unless ← narrowTm t (some 1) (some 1) do
      falsify description

end Consensus.MidTrace.Smt
