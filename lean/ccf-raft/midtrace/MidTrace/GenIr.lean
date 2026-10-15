module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import MidTrace.SmtCore

@[expose] public section

/-!
# A mechanical intermediate form

A model is encoded into a hash-consed DAG of typed nodes over booleans,
integers and arrays (`Int -> elem`, nested arrays allowed). Constructors only
fold literals and share equal nodes; they never consult intervals or the
trace, so the encoding of a step has a size that depends on the step alone.
The encoding is exact: its models are the initial states (within the declared
bounds) from which every action and observation holds.

* Arrays: unknown base arrays (`arrVar`, with element bounds), `store`,
  `ite`, `lam` (an array defined pointwise by a body over a bound index),
  `scan` (a prefix recurrence: `s[0] = init`, `s[k] = step(k, s[k-1])`), and
  `zero` (every cell is `0`, `false` or `zero`).
* Folds over an index range `[lo, hi]` with a body over the bound index:
  `last`/`first` (the value at the largest/smallest index whose condition
  holds, else a default), `any`, `all`.
* Commands, in trace order: hard requirements (guards and observations),
  assumptions guarded by `cap` or `inv`, and instruction markers.
* Cell axioms: a property of the cells of base arrays at every index (with
  small offsets), instantiated by the lowering wherever cells are used.

Lowering (`GenLower`) turns this into scalar SMT terms.
-/

namespace CCFRaft.MidTrace.Gen

open Lean
open CCFRaft.MidTrace.Smt (Tm INF)

inductive Srt where
  | bool
  | int
  /-- Total functions `Int -> elem`. -/
  | arr (elem : Srt)
deriving BEq, Hashable, Inhabited, Repr

def Srt.elem : Srt → Srt
  | .arr elem => elem
  | other => other

inductive FoldKind where
  | last
  | first
  | any
  | all
  /-- `default` plus the sum of the values whose condition holds. -/
  | sum
  /-- The largest of `default` and the values whose condition holds. -/
  | max
deriving BEq, Hashable, Inhabited, Repr

inductive Op where
  /-- A scalar unknown with bounds. -/
  | var (lo hi : Int)
  /-- An unknown array; scalar cells (at any depth) have these bounds. -/
  | arrVar (lo hi : Int)
  /-- The array whose cells are all `0`, `false` or `zero`. -/
  | zero (srt : Srt)
  /-- A bound index (or accumulator) variable: `bvar level boolean`. Binders
  take the next level, so structurally equal binders share their nodes. -/
  | bvar
  | not
  | and
  | or
  | ite
  | eq
  | le
  | add
  | sub
  | mul2
  | min
  | max
  | count
  /-- `select a i` -/
  | select
  /-- `store a i v` -/
  | store
  /-- `lam k body` -/
  | lam
  /-- `fold k lo hi cond value default` -/
  | fold (kind : FoldKind)
  /-- `scan k acc init step` -/
  | scan
deriving BEq, Hashable, Inhabited, Repr

structure Node where
  op : Op
  args : Array Tm
  srt : Srt
  /-- Bound variables the node depends on, ascending. -/
  bvs : Array Nat
  /-- The instruction being encoded when the node was created. -/
  instr : Nat
deriving Inhabited

structure Axiom where
  bases : Array Nat
  bv : Nat
  /-- The body reads the bases at `bv + offset` for these offsets only. -/
  offsets : Array Int
  body : Tm
  /-- Hard (well-formedness of the representation) rather than an `inv` assumption. -/
  hard : Bool
  description : String
deriving Inhabited

inductive Cmd where
  /-- The start of an instruction; `action` distinguishes actions from observations. -/
  | instr (index : Nat) (action : Bool)
  | require (t : Tm) (description : String) (background : Bool)
  | assume (cap : Bool) (t : Tm)
deriving Inhabited

structure Ir where
  nodes : Array Node := #[]
  cons : Std.HashMap (Op × Array Tm) Nat := {}
  cmds : Array Cmd := #[]
  axioms : Array Axiom := #[]
  instruction : Nat := 0
  /-- Binder nesting depth while building a binder's body. -/
  depth : Nat := 0
  falsified : Option (Nat × String) := none
  unsupported : Option String := none

abbrev GM := StateM Ir

def srtOf (t : Tm) : GM Srt := do
  match t with
  | .int _ => return .int
  | .bool _ => return .bool
  | .ref id => return (← get).nodes[id]!.srt

def isBoolTm (t : Tm) : GM Bool := do
  return (← srtOf t) == .bool

def bvsOf (t : Tm) : GM (Array Nat) := do
  match t with
  | .ref id => return (← get).nodes[id]!.bvs
  | _ => return #[]

def unionBvs (a b : Array Nat) : Array Nat :=
  if b.isEmpty then
    a
  else if a.isEmpty then
    b
  else
    (b.foldl (fun acc x => if acc.contains x then acc else acc.push x) a).qsort (· < ·)

/-- A hash-consed node; `bound` lists the variables the node binds. -/
def mk (op : Op) (args : Array Tm) (srt : Srt) (bound : Array Nat := #[]) : GM Tm := do
  if let some id := (← get).cons[(op, args)]? then return .ref id
  let mut bvs := #[]
  for arg in args do
    bvs := unionBvs bvs (← bvsOf arg)
  bvs := bvs.filter fun b => !bound.contains b
  modifyGet
    fun ir =>
      let id := ir.nodes.size
      let bvs := if op == .bvar then #[id] else bvs
      (
        .ref id,
        {
          ir with
            nodes := ir.nodes.push { op, args, srt, bvs, instr := ir.instruction }
            cons := ir.cons.insert (op, args) id
        }
      )

/-- A node that is never shared. -/
def fresh (op : Op) (srt : Srt) : GM Tm := do
  modifyGet
    fun ir =>
      let id := ir.nodes.size
      (
        .ref id,
        {
          ir with
            nodes :=
              ir.nodes.push { op, args := #[], srt, bvs := #[], instr := ir.instruction }
        }
      )

def norm (t : Tm) : GM Tm := pure t

/-! ## Unknowns -/

def declare (isBool : Bool) (lo : Int := -INF) (hi : Int := INF) : GM Tm :=
  if isBool then fresh (.var 0 1) .bool else fresh (.var lo hi) .int

def declareBool : GM Tm := declare true

def declareNat : GM Tm := declare false 0 INF

/-- An unknown array of sort `srt`, whose scalar cells lie in `[lo, hi]`. -/
def declareArr (srt : Srt) (lo : Int := -INF) (hi : Int := INF) : GM Tm :=
  fresh (.arrVar lo hi) srt

def zeroArr (srt : Srt) : GM Tm := mk (.zero srt) #[] srt

/-! ## Scalars -/

def notT (a : Tm) : GM Tm := do
  match a with
  | .bool value => return .bool !value
  | .int _ => return .bool false
  | .ref id =>
      let node := (← get).nodes[id]!
      if node.op == .not then return node.args[0]! else mk .not #[a] .bool

def andL (items : List Tm) : GM Tm := do
  let mut parts : Array Tm := #[]
  for item in items do
    match item with
    | .bool true => pure ()
    | .bool false => return .bool false
    | t =>
        unless parts.contains t do
          parts := parts.push t
  match parts.size with
  | 0 => return .bool true
  | 1 => return parts[0]!
  | _ => mk .and parts .bool

def orL (items : List Tm) : GM Tm := do
  let mut parts : Array Tm := #[]
  for item in items do
    match item with
    | .bool false => pure ()
    | .bool true => return .bool true
    | t =>
        unless parts.contains t do
          parts := parts.push t
  match parts.size with
  | 0 => return .bool false
  | 1 => return parts[0]!
  | _ => mk .or parts .bool

def impliesT (a b : Tm) : GM Tm := do
  orL [← notT a, b]

def le (a b : Tm) : GM Tm := do
  if a == b then return .bool true
  match a, b with
  | .int x, .int y => return .bool (decide (x <= y))
  | _, _ => mk .le #[a, b] .bool

def lt (a b : Tm) : GM Tm := do
  notT (← le b a)

def eqT (a b : Tm) : GM Tm := do
  if a == b then return .bool true
  match a, b with
  | .bool x, .bool y => return .bool (x == y)
  | .int x, .int y => return .bool (x == y)
  | .bool true, t | t, .bool true => return t
  | .bool false, t | t, .bool false => notT t
  | _, _ =>
      let (a, b) := if b.smt < a.smt then (b, a) else (a, b)
      mk .eq #[a, b] .bool

def eqK (a : Tm) (k : Int) : GM Tm := eqT a (.int k)

def iteT (c a b : Tm) : GM Tm := do
  match c with
  | .bool true => return a
  | .bool false | .int _ => return b
  | _ =>
      if a == b then return a
      let srt ← srtOf a
      if srt == .bool then
        match a, b with
        | .bool true, .bool false => return c
        | .bool false, .bool true => notT c
        | .bool true, _ => orL [c, b]
        | .bool false, _ => andL [← notT c, b]
        | _, .bool true => orL [← notT c, a]
        | _, .bool false => andL [c, a]
        | _, _ => mk .ite #[c, a, b] .bool
      else
        mk .ite #[c, a, b] srt

def addK (a : Tm) (k : Int) : GM Tm := do
  if k == 0 then return a
  match a with
  | .int value => return .int (value + k)
  | _ => mk .add #[a, .int k] .int

def addT (a b : Tm) : GM Tm := do
  match a, b with
  | .int x, b => addK b x
  | a, .int y => addK a y
  | a, b => mk .add #[a, b] .int

def subT (a b : Tm) : GM Tm := do
  if a == b then return .int 0
  match a, b with
  | a, .int y => addK a (-y)
  | a, b => mk .sub #[a, b] .int

def maxT (a b : Tm) : GM Tm := do
  if a == b then return a
  match a, b with
  | .int x, .int y => return .int (max x y)
  | _, _ =>
      let (a, b) := if b.smt < a.smt then (b, a) else (a, b)
      mk .max #[a, b] .int

def minT (a b : Tm) : GM Tm := do
  if a == b then return a
  match a, b with
  | .int x, .int y => return .int (min x y)
  | _, _ =>
      let (a, b) := if b.smt < a.smt then (b, a) else (a, b)
      mk .min #[a, b] .int

def countT (bits : Array Tm) : GM Tm := do
  let mut known : Int := 0
  let mut parts := #[]
  for bit in bits do
    match bit with
    | .bool true => known := known + 1
    | .bool false => pure ()
    | t => parts := parts.push t
  if parts.isEmpty then return .int known
  addK (← mk .count parts .int) known

def doubleT (a : Tm) : GM Tm := do
  match a with
  | .int value => return .int (2 * value)
  | a => mk .mul2 #[a] .int

/-! ## Arrays and folds -/

def select (a i : Tm) : GM Tm := do
  mk .select #[a, i] (← srtOf a).elem

def store (a i v : Tm) : GM Tm := do
  mk .store #[a, i, v] (← srtOf a)

def bvarId (t : Tm) : Nat :=
  match t with
  | .ref id => id
  | _ => 0

/-- Runs `body` with `count` new binders of sorts `srts`, at the next levels. -/
def binders {α : Type} (srts : Array Srt) (body : Array Tm → GM α) : GM α := do
  let level := (← get).depth
  let mut vars := #[]
  for h : i in [0:srts.size] do
    let srt := srts[i]
    vars := vars.push (← mk .bvar #[.int (level + i), .bool (srt == .bool)] srt)
  modify fun ir => { ir with depth := level + srts.size }
  let result ← body vars
  modify fun ir => { ir with depth := level }
  return result

/-- The array whose cell `k` is `body k`. -/
def lam (elem : Srt) (body : Tm → GM Tm) : GM Tm := do
  let (k, b) ← binders #[.int] fun vs => do return (vs[0]!, ← body vs[0]!)
  mk .lam #[k, b] (.arr elem) (bound := #[bvarId k])

/-- `s[k] = init` for `k <= 0`, else `step k s[k-1]`. -/
def scan (elem : Srt) (init : Tm) (step : Tm → Tm → GM Tm) : GM Tm := do
  let (k, acc, b) ←
    binders #[.int, elem] fun vs => do return (vs[0]!, vs[1]!, ← step vs[0]! vs[1]!)
  mk .scan #[k, acc, init, b] (.arr elem) (bound := #[bvarId k, bvarId acc])

def foldWith (kind : FoldKind) (lo hi : Tm) (cond value : Tm → GM Tm) (default : Tm)
    : GM Tm := do
  let (k, c, v) ←
    binders #[.int] fun vs => do return (vs[0]!, ← cond vs[0]!, ← value vs[0]!)
  let srt ← if kind == .any || kind == .all then pure Srt.bool else srtOf default
  mk (.fold kind) #[k, lo, hi, c, v, default] srt (bound := #[bvarId k])

/-- The value at the largest `k` in `[lo, hi]` satisfying `cond`, else `default`. -/
def foldLast (lo hi : Tm) (cond value : Tm → GM Tm) (default : Tm) : GM Tm :=
  foldWith .last lo hi cond value default

/-- The value at the smallest `k` in `[lo, hi]` satisfying `cond`, else `default`. -/
def foldFirst (lo hi : Tm) (cond value : Tm → GM Tm) (default : Tm) : GM Tm :=
  foldWith .first lo hi cond value default

def foldAny (lo hi : Tm) (cond : Tm → GM Tm) : GM Tm :=
  foldWith .any lo hi cond (fun _ => pure (.bool false)) (.bool false)

def foldAll (lo hi : Tm) (cond : Tm → GM Tm) : GM Tm :=
  foldWith .all lo hi cond (fun _ => pure (.bool true)) (.bool true)

/-- `default` plus the sum of `value k` over `k` in `[lo, hi]` satisfying `cond`. -/
def foldSum (lo hi : Tm) (cond value : Tm → GM Tm) (default : Tm := .int 0) : GM Tm :=
  foldWith .sum lo hi cond value default

/-- The largest of `default` and `value k` over `k` in `[lo, hi]` satisfying `cond`. -/
def foldMax (lo hi : Tm) (cond value : Tm → GM Tm) (default : Tm) : GM Tm :=
  foldWith .max lo hi cond value default

/-- A property of the cells of `bases` at every index `k`, reading only `k + offsets`. -/
def axiomCells (bases : Array Tm) (offsets : Array Int) (body : Tm → GM Tm) (hard : Bool)
    (description : String)
    : GM Unit := do
  let (k, b) ← binders #[.int] fun vs => do return (vs[0]!, ← body vs[0]!)
  modify
    fun ir =>
      {
        ir with
          axioms :=
            ir.axioms.push
              {
                bases := bases.map bvarId
                bv := bvarId k
                offsets
                body := b
                hard
                description
              }
      }

/-! ## Commands -/

/-- A requirement that is false whatever the initial state. -/
def falsify (description : String) : GM Unit :=
  modify
    fun ir =>
      if ir.falsified.isSome then
        ir
      else
        {
          ir with
            falsified := some (ir.instruction, description)
            cmds := ir.cmds.push (.require (.bool false) description false)
        }

def unsupported (what : String) : GM Unit :=
  modify
    fun ir =>
      if ir.unsupported.isSome then
        ir
      else
        { ir with unsupported := some s!"instruction {ir.instruction + 1}: {what}" }

def require (t : Tm) (description : String) (background : Bool := false) : GM Unit := do
  if t == .bool true then return
  if t == .bool false then return ← falsify description
  modify fun ir => { ir with cmds := ir.cmds.push (.require t description background) }

def assumeCap (t : Tm) : GM Unit := do
  unless t == .bool true do
    modify fun ir => { ir with cmds := ir.cmds.push (.assume true t) }

def assumeInv (t : Tm) : GM Unit := do
  unless t == .bool true do
    modify fun ir => { ir with cmds := ir.cmds.push (.assume false t) }

def setInstruction (index : Nat) (action : Bool) : GM Unit :=
  modify
    fun ir =>
      { ir with instruction := index, cmds := ir.cmds.push (.instr index action) }

/-! ## Inspection -/

def Op.name : Op → String
  | .var lo hi => s!"var[{lo},{hi}]"
  | .arrVar lo hi => s!"arrVar[{lo},{hi}]"
  | .zero _ => "zero"
  | .bvar => "bvar"
  | .not => "not"
  | .and => "and"
  | .or => "or"
  | .ite => "ite"
  | .eq => "="
  | .le => "<="
  | .add => "+"
  | .sub => "-"
  | .mul2 => "*2"
  | .min => "min"
  | .max => "max"
  | .count => "count"
  | .select => "select"
  | .store => "store"
  | .lam => "lam"
  | .fold .last => "fold-last"
  | .fold .first => "fold-first"
  | .fold .any => "fold-any"
  | .fold .all => "fold-all"
  | .fold .sum => "fold-sum"
  | .fold .max => "fold-max"
  | .scan => "scan"

def Ir.dump (ir : Ir) : String :=
  Id.run do
    let mut lines := #[]
    let mut ni := 0
    for cmd in ir.cmds do
      match cmd with
      | .instr i _ =>
          while ni < ir.nodes.size && ir.nodes[ni]!.instr < i do
            let node := ir.nodes[ni]!
            let args := " ".intercalate (node.args.map (·.smt)).toList
            lines := lines.push s!"(v{ni} ({node.op.name} {args}))"
            ni := ni + 1
          lines := lines.push s!"; instruction {i + 1}"
      | .require t description _ =>
          lines := lines.push s!"(require {t.smt}) ; {description}"
      | .assume cap t =>
          lines := lines.push s!"(assume {if cap then "cap" else "inv"} {t.smt})"
    while ni < ir.nodes.size do
      let node := ir.nodes[ni]!
      let args := " ".intercalate (node.args.map (·.smt)).toList
      lines := lines.push s!"(v{ni} ({node.op.name} {args}))"
      ni := ni + 1
    return "\n".intercalate lines.toList ++ "\n"

end CCFRaft.MidTrace.Gen
