module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Std.Data.HashMap
public import CCFRaft.Replay

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

Assumptions are guarded by two literals, `cap` (capacities are not exceeded)
and `inv` (the initial state satisfies cheap protocol invariants), and are
passed to `check-sat-assuming`, so an `unsat` core says whether a verdict
relied on them.
-/

namespace CCFRaft.MidTrace.Smt

open Lean

def INF : Int := 4611686018427387904

def clampInf (value : Int) : Int :=
  if value >= INF then INF else if value <= -INF then -INF else value

inductive Tm where
  | int (value : Int)
  | bool (value : Bool)
  | ref (id : Nat)
deriving BEq, Hashable, Inhabited, Repr

def Tm.smt : Tm → String
  | .int value => if value < 0 then s!"(- {-value})" else toString value
  | .bool value => if value then "true" else "false"
  | .ref id => s!"v{id}"

def Tm.isLit : Tm → Bool
  | .ref _ => false
  | _ => true

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
  | ite (c : Nat) (a b : Tm)
deriving Inhabited

structure Info where
  isBool : Bool
  lo : Int
  hi : Int
  shape : Shape := .none
  /-- A simpler equal term, found after the definition was emitted. -/
  equal : Option Tm := none
deriving Inhabited

/-- A log entry; effects other than one reconfiguration or retirement record are not modelled. -/
structure SEntry where
  term : Tm
  sig : Tm
  /-- Index into the transaction names; meaningless for signatures. -/
  tx : Tm
  /-- Has a reconfiguration effect (never for a signature). -/
  cfg : Tm
  cfgBits : Array Tm
  /-- Has a retired-committed effect (never for a signature). -/
  rc : Tm
  rcBits : Array Tm
deriving BEq, Inhabited

structure Label where
  name : String
  instruction : Nat
  description : String

structure Enc where
  infos : Array Info := #[]
  cons : Std.HashMap String Nat := {}
  out : Array String := #[]
  /-- Narrow intervals with hard assertions. -/
  refine : Bool := true
  /-- Name hard assertions so that they appear in unsat cores. -/
  named : Bool := false
  /-- The instruction being encoded, zero-based. -/
  instruction : Nat := 0
  labels : Array Label := #[]
  /-- The first hard assertion found false while encoding. -/
  falsified : Option (Nat × String) := none
  /-- Why the encoding cannot represent the trace; the verdict is then unknown. -/
  unsupported : Option String := none
  capLit : Tm := .bool true
  invLit : Tm := .bool true
  nextId : Nat := 1
  /-- Entries of lazily materialized message entry lists, by list and log index. -/
  entries : Std.HashMap (Nat × Nat) SEntry := {}
  declared : Nat := 0
  defined : Nat := 0

abbrev OpM := StateM Enc

def emit (line : String) : OpM Unit :=
  modify fun enc => { enc with out := enc.out.push line }

def freshId : OpM Nat := do
  let enc ← get
  set { enc with nextId := enc.nextId + 1 }
  return enc.nextId

def info (id : Nat) : OpM Info := do
  return (← get).infos[id]!

def setInfo (id : Nat) (value : Info) : OpM Unit :=
  modify fun enc => { enc with infos := enc.infos.set! id value }

def literal (isBool : Bool) (value : Int) : Tm :=
  if isBool then .bool (value == 1) else .int value

def NORM_DEPTH : Nat := 4

/--
The simplest known form of `t`. Definitions whose operands have since become
known are re-evaluated up to `depth` levels and aliased to the result.
-/
partial def normD (depth : Nat) (t : Tm) : OpM Tm := do
  let .ref id := t | return t
  let i ← info id
  if let some target := i.equal then
    let result ← normD depth target
    unless result == target do
      setInfo id { i with equal := some result }
    return result
  if i.lo == i.hi then return literal i.isBool i.lo
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
        let (lo, hi) ←
          match x' with
          | .int value => pure (value, value)
          | .bool value => pure (if value then (1, 1) else (0, 0))
          | .ref other => do
              let o ← info other
              pure (o.lo, o.hi)
        match i.shape with
        | .le _ _ =>
            pure
              (if hi <= k then
                  some (.bool true)
                else if lo > k then
                  some (.bool false)
                else
                  none)
        | .ge _ _ =>
            pure
              (if lo >= k then
                  some (.bool true)
                else if hi < k then
                  some (.bool false)
                else
                  none)
        | _ =>
            pure
              (if lo == k && hi == k then
                  some (.bool true)
                else if k < lo || hi < k then
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

def norm (t : Tm) : OpM Tm := normD NORM_DEPTH t

def range (t : Tm) : OpM (Int × Int) := do
  match ← norm t with
  | .int value => return (value, value)
  | .bool value => return if value then (1, 1) else (0, 0)
  | .ref id =>
      let i ← info id
      return (i.lo, i.hi)

def isBoolTm (t : Tm) : OpM Bool := do
  match t with
  | .bool _ => return true
  | .int _ => return false
  | .ref id => return (← info id).isBool

def define (isBool : Bool) (text : String) (lo hi : Int) (shape : Shape := .none)
    : OpM Tm := do
  if lo == hi then return literal isBool lo
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
        defined := enc.defined + 1
    }
  return .ref id

/-- A fresh constant; integers get their bounds asserted. -/
def declare (isBool : Bool) (lo : Int := -INF) (hi : Int := INF) : OpM Tm := do
  let enc ← get
  let id := enc.infos.size
  let lo := if isBool then 0 else lo
  let hi := if isBool then 1 else hi
  let mut out := enc.out.push s!"(declare-const v{id} {if isBool then "Bool" else "Int"})"
  if !isBool then
    if lo > -INF then out := out.push s!"(assert (<= {(Tm.int lo).smt} v{id}))"
    if hi < INF then out := out.push s!"(assert (<= v{id} {(Tm.int hi).smt}))"
  set
    {
      enc with
        infos := enc.infos.push { isBool, lo, hi }
        out
        declared := enc.declared + 1
    }
  return .ref id

def declareBool : OpM Tm := declare true

def declareNat : OpM Tm := declare false 0 INF

/-! ## Constructors -/

def notT (a : Tm) : OpM Tm := do
  match ← norm a with
  | .bool value => return .bool !value
  | .int _ => return .bool false
  | .ref id =>
      match (← info id).shape with
      | .not x => norm (.ref x)
      | _ => define true s!"(not v{id})" 0 1 (.not id)

def refIds (parts : Array Tm) : Array Nat :=
  parts.filterMap
    fun part =>
      match part with
      | .ref id => some id
      | _ => none

def andL (items : List Tm) : OpM Tm := do
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
      define true ("(and " ++ " ".intercalate (parts.map (·.smt)).toList ++ ")") 0 1
        (.and (refIds parts))

def orL (items : List Tm) : OpM Tm := do
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
      define true ("(or " ++ " ".intercalate (parts.map (·.smt)).toList ++ ")") 0 1
        (.or (refIds parts))

def impliesT (a b : Tm) : OpM Tm := do
  orL [← notT a, b]

/-- `a <= b` -/
def le (a b : Tm) : OpM Tm := do
  let a ← norm a
  let b ← norm b
  if a == b then return .bool true
  let (la, ha) ← range a
  let (lb, hb) ← range b
  if ha <= lb then return .bool true
  if la > hb then return .bool false
  let shape :=
    match a, b with
    | .ref x, .int k => Shape.le x k
    | .int k, .ref x => Shape.ge x k
    | _, _ => .none
  define true s!"(<= {a.smt} {b.smt})" 0 1 shape

def lt (a b : Tm) : OpM Tm := do
  notT (← le b a)

def eqT (a b : Tm) : OpM Tm := do
  let a ← norm a
  let b ← norm b
  if a == b then return .bool true
  match a, b with
  | .bool x, .bool y => return .bool (x == y)
  | .int x, .int y => return .bool (x == y)
  | .bool true, t | t, .bool true => return t
  | .bool false, t | t, .bool false => notT t
  | _, _ =>
      let (la, ha) ← range a
      let (lb, hb) ← range b
      if ha < lb || hb < la then return .bool false
      let (a, b) := if b.smt < a.smt then (b, a) else (a, b)
      let shape :=
        match a, b with
        | .ref x, .int k => Shape.eq x k
        | .int k, .ref x => Shape.eq x k
        | .ref x, .ref y => Shape.eqv x y
        | _, _ => .none
      define true s!"(= {a.smt} {b.smt})" 0 1 shape

def eqK (a : Tm) (k : Int) : OpM Tm := eqT a (.int k)

def iteT (c a b : Tm) : OpM Tm := do
  match ← norm c with
  | .bool true => norm a
  | .bool false => norm b
  | .int _ => norm b
  | .ref cid =>
      let c := Tm.ref cid
      let a ← norm a
      let b ← norm b
      if a == b then return a
      if ← isBoolTm a then
        match a, b with
        | .bool true, .bool false => return c
        | .bool false, .bool true => notT c
        | .bool true, _ => orL [c, b]
        | .bool false, _ => andL [← notT c, b]
        | _, .bool true => orL [← notT c, a]
        | _, .bool false => andL [c, a]
        | _, _ => define true s!"(ite {c.smt} {a.smt} {b.smt})" 0 1 (.ite cid a b)
      else
        let (la, ha) ← range a
        let (lb, hb) ← range b
        define false s!"(ite {c.smt} {a.smt} {b.smt})" (min la lb) (max ha hb)
          (.ite cid a b)

def addK (a : Tm) (k : Int) : OpM Tm := do
  let a ← norm a
  if k == 0 then return a
  match a with
  | .int value => return .int (value + k)
  | .ref id =>
      let (lo, hi) ← range a
      let lo := if lo <= -INF then -INF else clampInf (lo + k)
      let hi := if hi >= INF then INF else clampInf (hi + k)
      define false s!"(+ {a.smt} {(Tm.int k).smt})" lo hi (.add id k)
  | _ => return a

def addT (a b : Tm) : OpM Tm := do
  match ← norm a, ← norm b with
  | .int x, b => addK b x
  | a, .int y => addK a y
  | a, b =>
      let (la, ha) ← range a
      let (lb, hb) ← range b
      define false s!"(+ {a.smt} {b.smt})" (clampInf (la + lb)) (clampInf (ha + hb))

def subT (a b : Tm) : OpM Tm := do
  match ← norm a, ← norm b with
  | a, .int y => addK a (-y)
  | a, b =>
      if a == b then return .int 0
      let (la, ha) ← range a
      let (lb, hb) ← range b
      define false s!"(- {a.smt} {b.smt})" (clampInf (la - hb)) (clampInf (ha - lb))

def maxT (a b : Tm) : OpM Tm := do
  iteT (← le a b) b a

def minT (a b : Tm) : OpM Tm := do
  iteT (← le a b) a b

/-- The number of true terms in `bits`. -/
def countT (bits : Array Tm) : OpM Tm := do
  let mut known : Int := 0
  let mut parts : Array String := #[]
  for bit in bits do
    match ← norm bit with
    | .bool true => known := known + 1
    | .bool false => pure ()
    | t => parts := parts.push s!"(ite {t.smt} 1 0)"
  if parts.isEmpty then return .int known
  let sum := "(+ " ++ " ".intercalate parts.toList ++ s!" {known})"
  define false sum known (known + parts.size)

def doubleT (a : Tm) : OpM Tm := do
  match ← norm a with
  | .int value => return .int (2 * value)
  | a =>
      let (lo, hi) ← range a
      define false s!"(* 2 {a.smt})" (clampInf (2 * lo)) (clampInf (2 * hi))

/-! ## Narrowing -/

mutual
  /-- Narrows `t` to `[lo, hi]`; `false` if that is empty. -/
  partial def narrowTm (t : Tm) (lo hi : Int) : OpM Bool := do
    match ← norm t with
    | .int value => return lo <= value && value <= hi
    | .bool value =>
        let bit : Int := if value then 1 else 0
        return lo <= bit && bit <= hi
    | .ref id => narrow id lo hi

  partial def narrow (id : Nat) (lo hi : Int) : OpM Bool := do
    let i ← info id
    let nlo := max lo i.lo
    let nhi := min hi i.hi
    if nlo > nhi then return false
    if nlo == i.lo && nhi == i.hi then return true
    setInfo id { i with lo := nlo, hi := nhi }
    if i.isBool then
      if nlo != nhi then return true
      let value := nlo == 1
      match i.shape with
      | .not x => narrow x (if value then 0 else 1) (if value then 0 else 1)
      | .and parts =>
          if value then parts.allM fun part => narrow part 1 1 else return true
      | .or parts =>
          if value then return true else parts.allM fun part => narrow part 0 0
      | .le x k => if value then narrow x (-INF) k else narrow x (k + 1) INF
      | .ge x k => if value then narrow x k INF else narrow x (-INF) (k - 1)
      | .eq x k =>
          if value then
            narrow x k k
          else
            let o ← info x
            if o.lo == k then
              narrow x (k + 1) INF
            else if o.hi == k then
              narrow x (-INF) (k - 1)
            else
              return true
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
      | .add x k =>
          narrow x (if nlo <= -INF then -INF else nlo - k)
            (if nhi >= INF then INF else nhi - k)
      | .ite c a b => narrowIte c a b nlo nhi
      | _ => return true

  partial def narrowIte (c : Nat) (a b : Tm) (lo hi : Int) : OpM Bool := do
    let (la, ha) ← range a
    let (lb, hb) ← range b
    if ha < lo || hi < la then
      return (← narrow c 0 0) && (← narrowTm b lo hi)
    else if hb < lo || hi < lb then
      return (← narrow c 1 1) && (← narrowTm a lo hi)
    else
      return true
end

/-! ## Assertions -/

def falsify (description : String) : OpM Unit :=
  modify
    fun enc =>
      if enc.falsified.isSome then
        enc
      else
        { enc with falsified := some (enc.instruction, description) }

def unsupported (what : String) : OpM Unit :=
  modify
    fun enc =>
      if enc.unsupported.isSome then
        enc
      else
        { enc with unsupported := some s!"instruction {enc.instruction + 1}: {what}" }

/-- A hard assertion: an action's guard or an observation. -/
def require (t : Tm) (description : String) : OpM Unit := do
  let t ← norm t
  let enc ← get
  if t == .bool true then return
  if enc.named then
    -- A guard literal per assertion lets `get-unsat-assumptions` name the core.
    let name := (← declareBool).smt
    emit s!"(assert (=> {name} {t.smt}))"
    modify
      fun enc =>
        {
          enc with
            labels :=
              enc.labels.push { name, instruction := enc.instruction, description }
        }
  else
    emit s!"(assert {t.smt})"
  if t == .bool false then
    falsify description
  else if enc.refine then
    unless ← narrowTm t 1 1 do
      falsify description

/-- An assumption that capacities are not exceeded. -/
def assumeCap (t : Tm) : OpM Unit := do
  let t ← norm t
  unless t == .bool true do
    emit s!"(assert (=> {(← get).capLit.smt} {t.smt}))"

/-- An assumption that the initial state satisfies a protocol invariant. -/
def assumeInv (t : Tm) : OpM Unit := do
  let t ← norm t
  unless t == .bool true do
    emit s!"(assert (=> {(← get).invLit.smt} {t.smt}))"

end CCFRaft.MidTrace.Smt
