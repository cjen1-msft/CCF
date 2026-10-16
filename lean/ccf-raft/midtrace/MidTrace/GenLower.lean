module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import MidTrace.GenIr

@[expose] public section

/-!
# Lowering the intermediate form

Generic, equisatisfiable rewrites from `GenIr` to scalar SMT terms, applied in
command order so that each one sees the intervals narrowed by earlier hard
requirements (`SmtCore`):

* Demand-driven cells: an array is never expanded; a read of cell `k` walks
  the array's definition (`store` chains skip stores whose index interval
  excludes `k`; `lam` substitutes; `scan` unrolls from the last known cell),
  and base arrays get one fresh constant per cell actually read.
* Reads at a symbolic index become a case split over the index's interval.
* Folds are unrolled over the interval of their bounds; `last`/`first`/
  `any`/`all` stop at the first literal decision.
* `ite` lowers only the live branch when the condition is known.
* Cell axioms are instantiated for the cells that are read, once every cell
  they mention exists (eagerly for single-offset axioms). This is
  equisatisfiable when every instance can be satisfied by its unread cells
  whatever the read ones are.

Intervals are sound in every model (they come from declared bounds and hard
requirements), so each rewrite preserves satisfiability both ways. An
interval too wide to split makes the result `unsupported`, never approximate.
-/

namespace CCFRaft.MidTrace.Gen

open Lean
open CCFRaft.MidTrace.Smt (Tm INF OpM)

/-- A lowered array. -/
inductive AV where
  /-- A `store`, `lam` or `scan` node, with the values of its free bound variables. -/
  | node (id : Nat) (env : Array Tm)
  /-- The cells of base array `id` below outer indices `path`. -/
  | base (id : Nat) (path : Array Int)
  | zero (srt : Srt)
  | ite (c : Tm) (a b : Nat)
deriving BEq, Hashable, Inhabited

inductive Val where
  | s (t : Tm)
  /-- An interned `AV`. -/
  | a (av : Nat)
deriving BEq, Hashable, Inhabited

/-- How a scan behaves over a region `[lo, hi]` inside a gap. -/
inductive ScanSum where
  /-- `s[k] = step(k, start)`: each step overwrites the effect of earlier ones. -/
  | absorb (start : Tm)
  /-- `s[k] = start + (k - lo + 1) * d` -/
  | additive (start d : Tm)
deriving Inhabited

structure ScanState where
  /-- Cells `[0, top]` are computed or summarized. -/
  top : Int := 0
  /-- Summarized regions, ascending. -/
  regions : Array (Int × Int × ScanSum) := #[]
  /-- A scan `(av, m)` whose cells below `m` equal these. -/
  seed : Option (Nat × Int) := none
deriving Inhabited

/-! ## Incremental folds and scans

A binder's template is its body with the subterms that do not depend on the binder's own
variables (holes) cut out. Two binders with the same template differ only in their holes,
so where the holes agree their bodies agree: a fold reuses the per-index results of an
earlier fold with the same template outside the indices where the holes may differ, and
a scan reuses the cells of an earlier scan below the first such index. Only the shape of
the IR is consulted, so this works for any model.
-/

/-- An argument of a template node. -/
inductive TArg where
  | lit (t : Tm)
  | node (id : Nat)
  | hole
deriving BEq, Hashable, Inhabited

/-- How a template uses a hole, relative to the binder's index `k`. -/
inductive HoleUse where
  /-- An array read at `k + c`. -/
  | read (c : Int)
  /-- A scalar compared with `k + c`. -/
  | cmp (c : Int)
  | exact
deriving Inhabited

structure Tmpl where
  id : Nat
  /-- The holes in depth-first order, repeated as often as they occur, with their uses. -/
  holes : Array (Tm × HoleUse)
deriving Inhabited

/-- Sorted, disjoint index intervals; `none` stands for every index. -/
abbrev Delta := Option (Array (Int × Int))

/-- The per-index results of a fold. -/
structure FoldMemo where
  holes : Array Val
  /-- Indices whose items are current, as sorted disjoint intervals. -/
  cover : Array (Int × Int)
  /-- The unguarded condition at covered indices where it is not neutral. -/
  items : Std.TreeMap Int Tm
deriving Inhabited

inductive GapFill where
  /-- Every gap cell is zero, `false` or the zero array. -/
  | zero
  /-- The cells of a gap share one unknown. -/
  | uniform
deriving BEq, Inhabited

structure LState where
  /--
  Sorted, disjoint intervals of explicit indices; empty when gaps are off. Cells of base
  arrays at other indices are gap cells (`GapFill`).
  -/
  explicit : Array (Int × Int) := #[]
  fill : GapFill := .zero
  gapCells : Std.HashMap (Nat × Array Int × Nat) Val := {}
  scans : Std.HashMap Nat ScanState := {}
  /-- Regions summarized by probing, and gap parts enumerated instead (instruction, width). -/
  probed : Nat := 0
  enumerated : Array (Nat × Int) := #[]
  avs : Array AV := #[]
  avCons : Std.HashMap AV Nat := {}
  /-- Lowered closed nodes. -/
  memo : Std.HashMap Nat Val := {}
  /-- Lowered nodes under bound variables, by their values; cleared per command. -/
  bound : Std.HashMap (Nat × Array Tm) Val := {}
  cells : Std.HashMap (Nat × Int) Val := {}
  /-- Top-level scalar cells of base arrays that exist. -/
  materialized : Std.HashSet (Nat × Int) := {}
  /-- Base array, outer path, index, constant. -/
  baseCells : Array (Nat × Array Int × Int × Tm) := #[]
  axiomDone : Std.HashSet (Nat × Int) := {}
  axiomsByBase : Std.HashMap Nat (Array Nat) := {}
  /-- The SMT term count at the start of each instruction. -/
  sizes : Array (Nat × Nat) := #[]
  /-- Reads and folds split over more than `WIDE` cases: instruction, node, width. -/
  wide : Array (Nat × Nat × Int) := #[]
  /-- Reuse fold results and scan cells across binders with the same template. -/
  reuse : Bool := true
  tcons : Std.HashMap (Op × Array TArg) Nat := {}
  /-- Templates of binder nodes; `none` when too large. -/
  tmpls : Std.HashMap Nat (Option Tmpl) := {}
  /-- Recent fold results by template and environment, latest last. -/
  foldMemos : Std.HashMap (Nat × Array Tm) (Array FoldMemo) := {}
  /-- Recent scans and their holes by template and environment, latest last. -/
  scanMemos : Std.HashMap (Nat × Array Tm) (Array (Nat × Array Val)) := {}
  /-- Where two arrays may differ, with the depth this was computed at. -/
  deltas : Std.HashMap (Nat × Nat) (Delta × Nat) := {}
  /-- The overwrite each array makes on the one below it, if any. -/
  steps : Std.HashMap Nat (Option (Option (Array (Int × Int)) × Nat)) := {}
  /-- Fold indices evaluated, and reused or skipped. -/
  points : Nat := 0
  reusedPoints : Nat := 0
  seededScans : Nat := 0

abbrev LM := ReaderT Ir (StateT LState OpM)

abbrev BEnv := Std.HashMap Nat Tm

/-- Splits at least this wide are recorded in `LState.wide`. -/
def WIDE : Int := 16

/-- The widest case split for a read or fold. -/
def SPLIT_LIMIT : Int := 100000

/-- Gap parts at most this wide are enumerated rather than probed. -/
def SMALL : Int := 32

/-- How often a probed region may be split around the literals its probe hit. -/
def SPLIT_DEPTH : Nat := 4

/-- The key standing for every index of gap `g` in base cell paths. -/
def gapKey (g : Nat) : Int := -2 * INF - g

/-- The index of the first interval of `xs` that ends at or after `k`. -/
def firstEnding (xs : Array (Int × Int)) (k : Int) : Nat :=
  Id.run do
    let mut lo := 0
    let mut hi := xs.size
    while lo < hi do
      let mid := (lo + hi) / 2
      if xs[mid]!.2 < k then lo := mid + 1 else hi := mid
    return lo

/-- The gap holding `k`: gap `g` lies just below interval `g` of `xs`. -/
def gapOf (xs : Array (Int × Int)) (k : Int) : Option Nat :=
  if xs.isEmpty then
    none
  else
    let i := firstEnding xs k
    if i < xs.size && xs[i]!.1 <= k then none else some i

/-- `k`, or the key of its gap. -/
def cellKey (xs : Array (Int × Int)) (k : Int) : Int :=
  match gapOf xs k with
  | some g => gapKey g
  | none => k

/-- A part of an index range. -/
inductive Piece where
  | pts (lo hi : Int)
  | gap (g : Nat) (lo hi : Int)

/-- `[lo, hi]` cut into explicit runs and parts of gaps, ascending. -/
def pieces (xs : Array (Int × Int)) (lo hi : Int) : Array Piece :=
  Id.run do
    if hi < lo then return #[]
    if xs.isEmpty then return #[.pts lo hi]
    let mut out := #[]
    let mut k := lo
    let mut i := firstEnding xs lo
    while k <= hi do
      if i < xs.size then
        let (a, b) := xs[i]!
        if a <= k then
          let e := min hi b
          out := out.push (.pts k e)
          k := e + 1
          i := i + 1
        else
          let e := min hi (a - 1)
          out := out.push (.gap i k e)
          k := e + 1
      else
        out := out.push (.gap i k hi)
        k := hi + 1
    return out

def explicitCount (ps : Array Piece) : Int :=
  ps.foldl
    (fun n piece =>
      match piece with
      | .pts a b => n + (b - a + 1)
      | .gap .. => n)
    0

/-- `[lo, hi]` without `points`, cut at them: points and the regions between, ascending. -/
def cutAround (lo hi : Int) (points : Array Int) : Array (Bool × Int × Int) :=
  Id.run do
    let points := (points.filter fun k => lo <= k && k <= hi).qsort (· < ·)
    let mut out := #[]
    let mut k := lo
    for p in points do
      if p < k then continue
      if k < p then out := out.push (false, k, p - 1)
      out := out.push (true, p, p)
      k := p + 1
    if k <= hi then out := out.push (false, k, hi)
    return out

def intern (av : AV) : LM Nat := do
  if let some id := (← get).avCons[av]? then return id
  modifyGet
    fun s =>
      (
        s.avs.size,
        { s with avs := s.avs.push av, avCons := s.avCons.insert av s.avs.size }
      )

def avOf (id : Nat) : LM AV := do
  return (← get).avs[id]!

def srtAfter (srt : Srt) : Nat → Srt
  | 0 => srt
  | depth + 1 => srtAfter srt.elem depth

partial def avSrt (id : Nat) : LM Srt := do
  match ← avOf id with
  | .node n _ => return (← read).nodes[n]!.srt
  | .base n path => return srtAfter (← read).nodes[n]!.srt path.size
  | .zero srt => return srt
  | .ite _ a _ => avSrt a

def defaultVal (srt : Srt) : LM Val := do
  match srt with
  | .bool => return .s (.bool false)
  | .int => return .s (.int 0)
  | .arr .. => return .a (← intern (.zero srt))

def iteVal (c : Tm) (a b : Val) : LM Val := do
  match ← Smt.norm c with
  | .bool true => return a
  | .bool false | .int _ => return b
  | c =>
      match a, b with
      | .s x, .s y => return .s (← Smt.iteT c x y)
      | .a x, .a y => if x == y then return a else return .a (← intern (.ite c x y))
      | _, _ => return a

def bindEnv (bvs : Array Nat) (values : Array Tm) : BEnv :=
  Id.run do
    let mut env : BEnv := {}
    for (b, v) in bvs.zip values do
      env := env.insert b v
    return env

/-- Runs `act`; `none`, with the flag cleared, if it found something unsupported. -/
def attempt {α : Type} (act : LM α) : LM (Option α) := do
  let before := (← getThe Smt.Enc).unsupported
  let result ← act
  if before.isNone && (← getThe Smt.Enc).unsupported.isSome then
    modifyThe Smt.Enc fun enc => { enc with unsupported := none }
    return none
  return some result

/-- Runs `act`, returning the literals that probe `p` was compared with undecidedly. -/
def watching {α : Type} (p : Tm) (act : LM α) : LM (α × Array Int) := do
  let .ref id := p | return (← act, #[])
  let saved ← getThe Smt.Enc
  modifyThe Smt.Enc fun enc => { enc with watch := some id, hits := #[] }
  let result ← act
  let hits := (← getThe Smt.Enc).hits
  modifyThe Smt.Enc fun enc => { enc with watch := saved.watch, hits := saved.hits }
  return (result, hits)

/-- The points around which to split a region whose probe hit `hits`. -/
def around (hits : Array Int) : Array Int :=
  hits.flatMap fun h => #[h - 1, h, h + 1]

/-- `d` when `r` is `x + d` for a `d` other than `x`. -/
def additiveOf (r x : Tm) : OpM (Option Tm) := do
  let (base, offset) ← Smt.offsetOf r
  if base == x then return some (.int offset)
  let .ref id ← Smt.norm r | return none
  let .ref xid := x | return none
  match (← Smt.info id).shape with
  | .sum p q =>
      if p == xid then
        return some (.ref q)
      else if q == xid then
        return some (.ref p)
      else
        return none
  | _ => return none

/-- `a * b`, when one is a literal or an `ite` between literals. -/
def mulT (a b : Tm) : OpM (Option Tm) := do
  match ← Smt.norm a, ← Smt.norm b with
  | .int x, b => return some (← Smt.mulK b x)
  | a, .int y => return some (← Smt.mulK a y)
  | a, .ref id =>
      match (← Smt.info id).shape with
      | .ite c (.int x) (.int y) =>
          return some (← Smt.iteT (.ref c) (← Smt.mulK a x) (← Smt.mulK a y))
      | _ => return none
  | _, _ => return none

/-- A step of a fold's iteration. -/
inductive Cand where
  | pt (k : Int)
  /-- Explicit indices, not yet visited. -/
  | span (lo hi : Int)
  /-- Part of a gap, not yet probed. -/
  | region (lo hi : Int) (depth : Nat)
  /-- A region where the condition is `c` throughout and the value is `v`, or the index plus
  `off`. -/
  | uni (lo hi : Int) (c : Tm) (v : Option Val) (off : Option Int)
deriving Inhabited

/-- Sorts `xs` and merges overlapping or adjacent intervals. -/
def normIvs (xs : Array (Int × Int)) : Array (Int × Int) :=
  Id.run do
    let mut out : Array (Int × Int) := #[]
    for (a, b) in xs.qsort (fun x y => x.1 < y.1) do
      if let some (p, q) := out.back? then
        if a <= q + 1 then
          out := out.pop.push (p, max q b)
          continue
      out := out.push (a, b)
    return out

/-- `xs` with `[p, q]`, merged with the last interval when adjacent. -/
def pushIv (xs : Array (Int × Int)) (p q : Int) : Array (Int × Int) :=
  match xs.back? with
  | some (a, b) =>
      if p == b + 1 then
        xs.pop.push (a, q)
      else if q + 1 == a then
        xs.pop.push (p, b)
      else
        xs.push (p, q)
  | none => xs.push (p, q)

/-- The interval of `xs` holding `k`. -/
def ivAt (xs : Array (Int × Int)) (k : Int) : Option (Int × Int) :=
  let i := firstEnding xs k
  if h : i < xs.size then if xs[i].1 <= k then some xs[i] else none else none

/-- `xs` without the indices of `ds`. -/
def subIvs (xs ds : Array (Int × Int)) : Array (Int × Int) :=
  Id.run do
    let mut out := #[]
    for (a, b) in xs do
      let mut a := a
      let mut j := firstEnding ds a
      while a <= b do
        if h : j < ds.size then
          let (p, q) := ds[j]
          if p <= b then
            if a < p then out := out.push (a, p - 1)
            a := max a (q + 1)
            j := j + 1
            continue
        out := out.push (a, b)
        a := b + 1
    return out

def shiftIvs (xs : Array (Int × Int)) (d : Int) : Array (Int × Int) :=
  let bump (x : Int) := if x >= INF || x <= -INF then x else x + d
  xs.map fun (a, b) => (bump a, bump b)

def unionD (a b : Delta) : Delta := do
  return normIvs ((← a) ++ (← b))

/-- `t` as `k + c`. -/
partial def affineIn (ir : Ir) (k : Nat) (t : Tm) : Option Int :=
  match t with
  | .ref id =>
      if id == k then
        some 0
      else
        let node := ir.nodes[id]!
        match node.op, node.args[1]? with
        | .add, some (Tm.int c) => (affineIn ir k node.args[0]!).map (· + c)
        | _, _ => none
  | _ => none

/-- How argument `i` of `node` is used, relative to index `k`. -/
def holeUse (ir : Ir) (k : Nat) (node : Node) (i : Nat) : HoleUse :=
  let affine (j : Nat) : Option Int := affineIn ir k node.args[j]!
  match node.op with
  | .select =>
      match i, affine 1 with
      | 0, some c => .read c
      | _, _ => .exact
  | .le | .eq =>
      match affine (1 - i) with
      | some c => .cmp c
      | none => .exact
  | _ => .exact

/-- The most nodes and holes a template may have. -/
def TMPL_NODES : Nat := 4096

def TMPL_HOLES : Nat := 512

/-- How deep `deltaArr` looks into nested arrays, and how many stores it follows. -/
def DELTA_DEPTH : Nat := 6

def CHAIN : Nat := 64

/-- How many earlier binders with the same template and environment are kept. -/
def RECENT : Nat := 16

def pushRecent {α : Type} (xs : Array α) (x : α) : Array α :=
  let xs := xs.push x
  if xs.size > RECENT then xs.extract (xs.size - RECENT) xs.size else xs

structure WalkSt where
  tcons : Std.HashMap (Op × Array TArg) Nat
  holes : Array (Tm × HoleUse) := #[]
  count : Nat := 0

def tnode (op : Op) (targs : Array TArg) : StateM WalkSt TArg := do
  let s ← get
  if let some tid := s.tcons[(op, targs)]? then return .node tid
  set { s with tcons := s.tcons.insert (op, targs) s.tcons.size }
  return .node s.tcons.size

/-- The template of `t` inside a binder with free variables `outer` and index `k`. -/
partial def tmplWalk (ir : Ir) (outer : Array Nat) (k : Nat) (use : HoleUse) (t : Tm)
    : StateM WalkSt TArg := do
  let .ref id := t | return .lit t
  let node := ir.nodes[id]!
  if node.bvs.all outer.contains then
    modify fun s => { s with holes := s.holes.push (t, use) }
    return .hole
  let s ← get
  if s.count >= TMPL_NODES then return .hole
  set { s with count := s.count + 1 }
  let mut targs := #[]
  for h : i in [0:node.args.size] do
    targs := targs.push (← tmplWalk ir outer k (holeUse ir k node i) node.args[i])
  tnode node.op targs

/-- The template of binder `id`. A fold's bounds and default are not part of it. -/
def tmplOf (id : Nat) : LM (Option Tmpl) := do
  if let some t := (← get).tmpls[id]? then return t
  let ir ← read
  let node := ir.nodes[id]!
  let walk := tmplWalk ir node.bvs (bvarId node.args[0]!) .exact
  let skip := TArg.lit (.bool false)
  let act : StateM WalkSt TArg := do
    let targs ←
      match node.op with
      | .fold _ =>
          pure
            #[
              ← walk node.args[0]!,
              skip,
              skip,
              ← walk node.args[3]!,
              ← walk node.args[4]!,
              skip
            ]
      | _ => node.args.mapM walk
    tnode node.op targs
  let tcons ← modifyGet fun s => (s.tcons, { s with tcons := {} })
  let (root, st) := act.run { tcons }
  let tmpl :=
    match root with
    | .node tid =>
        if st.count >= TMPL_NODES || st.holes.size > TMPL_HOLES then
          none
        else
          some { id := tid, holes := st.holes }
    | _ => none
  modify fun s => { s with tcons := st.tcons, tmpls := s.tmpls.insert id tmpl }
  return tmpl

mutual
  partial def lowerV (env : BEnv) (t : Tm) : LM Val := do
    match t with
    | .ref id => lowerNode env id
    | t => return .s t

  partial def lowerS (env : BEnv) (t : Tm) : LM Tm := do
    match ← lowerV env t with
    | .s t => return t
    | .a _ =>
        Smt.unsupported "an array where a scalar was expected"
        return .int 0

  partial def lowerA (env : BEnv) (t : Tm) : LM Nat := do
    match ← lowerV env t with
    | .a av => return av
    | .s _ =>
        Smt.unsupported "a scalar where an array was expected"
        intern (.zero (.arr .int))

  partial def lowerNode (env : BEnv) (id : Nat) : LM Val := do
    let node := (← read).nodes[id]!
    if node.op == .bvar then return .s (env.getD id (.int 0))
    if node.bvs.isEmpty then
      if let some v := (← get).memo[id]? then return v
      let v ← compute env id node
      modify fun s => { s with memo := s.memo.insert id v }
      return v
    else
      let key := (id, node.bvs.map fun b => env.getD b (.int 0))
      if let some v := (← get).bound[key]? then return v
      let v ← compute env id node
      modify fun s => { s with bound := s.bound.insert key v }
      return v

  partial def compute (env : BEnv) (id : Nat) (node : Node) : LM Val := do
    let args := node.args
    match node.op with
    | .var lo hi =>
        if node.srt == .bool then
          return .s (← Smt.declareBool)
        else
          return .s (← Smt.declare false lo hi)
    | .arrVar _ _ => return .a (← intern (.base id #[]))
    | .zero srt => defaultVal srt
    | .bvar => return .s (env.getD id (.int 0))
    | .not => return .s (← Smt.notT (← lowerS env args[0]!))
    | .and =>
        let mut parts := #[]
        for arg in args do
          let v ← Smt.norm (← lowerS env arg)
          if v == .bool false then return .s v
          parts := parts.push v
        return .s (← Smt.andL parts.toList)
    | .or =>
        let mut parts := #[]
        for arg in args do
          let v ← Smt.norm (← lowerS env arg)
          if v == .bool true then return .s v
          parts := parts.push v
        return .s (← Smt.orL parts.toList)
    | .ite =>
        match ← Smt.norm (← lowerS env args[0]!) with
        | .bool true => lowerV env args[1]!
        | .bool false | .int _ => lowerV env args[2]!
        | c => iteVal c (← lowerV env args[1]!) (← lowerV env args[2]!)
    | .eq => return .s (← Smt.eqT (← lowerS env args[0]!) (← lowerS env args[1]!))
    | .le => return .s (← Smt.le (← lowerS env args[0]!) (← lowerS env args[1]!))
    | .add => return .s (← Smt.addT (← lowerS env args[0]!) (← lowerS env args[1]!))
    | .sub => return .s (← Smt.subT (← lowerS env args[0]!) (← lowerS env args[1]!))
    | .mul2 => return .s (← Smt.doubleT (← lowerS env args[0]!))
    | .min => return .s (← Smt.minT (← lowerS env args[0]!) (← lowerS env args[1]!))
    | .max => return .s (← Smt.maxT (← lowerS env args[0]!) (← lowerS env args[1]!))
    | .count => return .s (← Smt.countT (← args.mapM (lowerS env)))
    | .select =>
        let av ← lowerA env args[0]!
        let i ← lowerS env args[1]!
        let (lo, hi) ← Smt.range i
        if hi - lo >= WIDE then
          let instr := (← getThe Smt.Enc).instruction
          modify fun s => { s with wide := s.wide.push (instr, id, hi - lo + 1) }
        selectAt av i
    | .store | .lam | .scan =>
        return .a (← intern (.node id (node.bvs.map fun b => env.getD b (.int 0))))
    | .fold kind =>
        let (lo, _) ← Smt.range (← lowerS env args[1]!)
        let (_, hi) ← Smt.range (← lowerS env args[2]!)
        if hi - lo >= WIDE then
          let instr := (← getThe Smt.Enc).instruction
          modify fun s => { s with wide := s.wide.push (instr, id, hi - lo + 1) }
        lowerFold env id node kind

  /-- The lowered index of a `store`, with its environment and node. -/
  partial def storeAt (av : Nat) : LM (Option (Tm × BEnv × Node)) := do
    let .node id ev ← avOf av | return none
    let node := (← read).nodes[id]!
    unless node.op == .store do
      return none
    let env := bindEnv node.bvs ev
    return some (← Smt.norm (← lowerS env node.args[1]!), env, node)

  /-- The values of the holes of `tmpl`; `none` if one is unsupported. -/
  partial def lowerHoles (env : BEnv) (tmpl : Tmpl) : LM (Option (Array Val)) :=
    attempt (tmpl.holes.mapM fun (h, _) => lowerV env h)

  /-- The indices where the bodies of two binders with template `tmpl` may differ. -/
  partial def deltaHoles (tmpl : Tmpl) (old new : Array Val) (depth : Nat)
      : LM Delta := do
    let mut d := #[]
    for h : i in [0:tmpl.holes.size] do
      let a := old[i]!
      let b := new[i]!
      if a == b then continue
      match tmpl.holes[i].2, a, b with
      | .cmp c, .s x, .s y =>
          let .int x ← Smt.norm x | return none
          let .int y ← Smt.norm y | return none
          d := d.push (min x y - c, max x y - c)
      | .exact, .a x, .a y =>
          -- Arrays used whole must not differ at all.
          let some e ← deltaArr x y depth | return none
          unless e.isEmpty do
            return none
      | .read c, .a x, .a y =>
          let some e ← deltaArr x y depth | return none
          d := d ++ shiftIvs e (-c)
      | _, _, _ => return none
    return some (normIvs d)

  /-- The indices where arrays `x` and `y` may differ. -/
  partial def deltaArr (x y : Nat) (depth : Nat) : LM Delta := do
    if x == y then return some #[]
    if let some (d, seen) := (← get).deltas[(x, y)]? then
      if d.isSome || seen >= depth then return d
    let d ← deltaChains x y depth
    modify fun s => { s with deltas := s.deltas.insert (x, y) (d, depth) }
    return d

  /-- Intervals of bound index `kb` where `c` is certainly `want`. -/
  partial def surely (env : BEnv) (kb : Nat) (want : Bool) (c : Tm)
      : LM (Array (Int × Int)) := do
    let ir ← read
    let every := #[(-INF, INF)]
    let free (t : Tm) : Bool :=
      match t with
      | .ref id => !ir.nodes[id]!.bvs.contains kb
      | _ => true
    if free c then
      match ← Smt.norm (← lowerS env c) with
      | .bool b => return if b == want then every else #[]
      | _ => return #[]
    let .ref id := c | return #[]
    let node := ir.nodes[id]!
    match node.op with
    | .not => surely env kb (!want) node.args[0]!
    | .and | .or =>
        let parts ← node.args.mapM (surely env kb want)
        -- An `and` is certainly true where every part is, and certainly false where any is.
        if (node.op == .and) == want then
          return parts.foldl (fun acc p => subIvs acc (subIvs every p)) every
        else
          return normIvs (parts.foldl (· ++ ·) #[])
    | .le | .eq =>
        let l := node.args[0]!
        let r := node.args[1]!
        -- `k + c` against `h`, with `k` on the left when `kLeft`.
        let (c, h, kLeft) ←
          match affineIn ir kb l, affineIn ir kb r with
          | some c, _ => if free r then pure (c, r, true) else return #[]
          | none, some c => if free l then pure (c, l, false) else return #[]
          | none, none => return #[]
        let (hl, hh) ← Smt.range (← Smt.norm (← lowerS env h))
        let lo := hl - c
        let hi := hh - c
        if node.op == .eq then
          return  if want then
                    (if lo == hi then #[(lo, lo)] else #[])
                  else
                    #[(-INF, lo - 1), (hi + 1, INF)]
        if kLeft then
          return if want then #[(-INF, lo)] else #[(hi + 1, INF)]
        else
          return if want then #[(hi, INF)] else #[(-INF, lo - 1)]
    | _ => return #[]

  /-- The array `av` overwrites in some indices (`none`: too many to say), and that array:
  a `store`, or a `lam k (ite c (select a k) e)` (either way round) with `a` free of `k`. -/
  partial def stepOf (av : Nat) : LM (Option (Option (Array (Int × Int)) × Nat)) := do
    let .node id ev ← avOf av | return none
    let ir ← read
    let node := ir.nodes[id]!
    let env := bindEnv node.bvs ev
    match node.op with
    | .store =>
        let j ← Smt.norm (← lowerS env node.args[1]!)
        let below ← lowerA env node.args[0]!
        match j with
        | .int k => return some (some #[(k, k)], below)
        | j =>
            let (lo, hi) ← Smt.range j
            return some (if hi - lo > CHAIN then none else some #[(lo, hi)], below)
    | .lam =>
        let k := node.args[0]!
        let kb := bvarId k
        let .ref bid := node.args[1]! | return none
        let body := ir.nodes[bid]!
        unless body.op == .ite do
          return none
        let under (t : Tm) : Option Tm :=
          match t with
          | .ref sid =>
              let sel := ir.nodes[sid]!
              let a := sel.args[0]!
              let free :=
                match a with
                | .ref aid => !ir.nodes[aid]!.bvs.contains kb
                | _ => true
              if sel.op == .select && sel.args[1]! == k && free then some a else none
          | _ => none
        let (a, want) ←
          match under body.args[1]!, under body.args[2]! with
          | some a, _ => pure (a, true)
          | none, some a => pure (a, false)
          | none, none => return none
        let same ← surely env kb want body.args[0]!
        let below ← lowerA env a
        return some (some (subIvs #[(-INF, INF)] same), below)
    | _ => return none

  /-- `stepOf`, memoized: an array's step never changes. -/
  partial def step (av : Nat) : LM (Option (Option (Array (Int × Int)) × Nat)) := do
    if let some r := (← get).steps[av]? then return r
    let r ← stepOf av
    modify fun s => { s with steps := s.steps.insert av r }
    return r

  /-- Follows the overwrites of `x` and `y` in lockstep, for up to `CHAIN` steps each, until
  one reaches an array the other has passed; else compares the arrays they end at. -/
  partial def deltaChains (x y : Nat) (depth : Nat) : LM Delta := do
    let mut seenX : Std.HashMap Nat Nat := ({} : Std.HashMap Nat Nat).insert x 0
    let mut seenY : Std.HashMap Nat Nat := ({} : Std.HashMap Nat Nat).insert y 0
    let mut rx : Array (Option (Array (Int × Int))) := #[]
    let mut ry : Array (Option (Array (Int × Int))) := #[]
    let mut curX := x
    let mut curY := y
    let mut doneX := false
    let mut doneY := false
    let mut meet : Option (Nat × Nat) := none
    for _ in [0:CHAIN] do
      if doneX && doneY then break
      if !doneX then
        match ← step curX with
        | some (r, below) =>
            rx := rx.push r
            curX := below
            if let some j := seenY[below]? then
              meet := some (rx.size, j)
              break
            seenX := seenX.insert below rx.size
        | none => doneX := true
      if !doneY then
        match ← step curY with
        | some (r, below) =>
            ry := ry.push r
            curY := below
            if let some i := seenX[below]? then
              meet := some (i, ry.size)
              break
            seenY := seenY.insert below ry.size
        | none => doneY := true
    let (regions, rest) ←
      match meet with
      | some (i, j) => pure (rx.extract 0 i ++ ry.extract 0 j, some #[])
      | none =>
          if doneX && doneY then
            pure (rx ++ ry, ← deltaBase curX curY depth)
          else
            pure (#[], none)
    let mut d := rest
    for r in regions do
      let some _ := d | return none
      let some r := r | return none
      d := unionD d (some r)
    return d

  /-- Compares arrays that are not stores. -/
  partial def deltaBase (x y : Nat) (depth : Nat) : LM Delta := do
    if x == y then return some #[]
    if depth == 0 then return none
    match ← avOf x, ← avOf y with
    | .ite c a b, .ite c' a' b' =>
        if c != c' then return none
        return unionD (← deltaArr a a' (depth - 1)) (← deltaArr b b' (depth - 1))
    | .node ix ex, .node iy ey =>
        let ir ← read
        let nx := ir.nodes[ix]!
        let ny := ir.nodes[iy]!
        unless (nx.op == .lam || nx.op == .scan) && nx.op == ny.op do
          return none
        let some tx ← tmplOf ix | return none
        let some ty ← tmplOf iy | return none
        if tx.id != ty.id then return none
        let some hx ← lowerHoles (bindEnv nx.bvs ex) tx | return none
        let some hy ← lowerHoles (bindEnv ny.bvs ey) ty | return none
        let some d ← deltaHoles tx hx hy (depth - 1) | return none
        if nx.op == .lam then return some d
        -- A scan's cells differ from the first step that does.
        match d[0]? with
        | some (lo, _) => return some #[(lo, INF)]
        | none => return some #[]
    | _, _ => return none

  /-- A read at `i`: a case split over the explicit indices and gap parts in the interval of `i`. -/
  partial def selectAt (av : Nat) (i : Tm) : LM Val := do
    match ← Smt.norm i with
    | .int k => cell av k
    | i =>
        -- Read over write when the store index is `i` plus a known offset.
        let (bi, oi) ← Smt.offsetOf i
        let mut av := av
        repeat
          let some (j, env, node) ← storeAt av | break
          let (bj, oj) ← Smt.offsetOf j
          if bi != bj then break
          if oi == oj then return ← lowerV env node.args[2]!
          av ← lowerA env node.args[0]!
        let (lo, hi) ← Smt.range i
        let ps := pieces (← get).explicit lo hi
        if explicitCount ps > SPLIT_LIMIT then
          Smt.unsupported s!"a read over [{lo}, {hi}]"
          return ← defaultVal (← avSrt av).elem
        -- The last part is the default; earlier ones are tested in turn.
        let mut acc : Option Val := none
        for piece in ps.reverse do
          match piece with
          | .pts a b =>
              for offset in [0:(b - a + 1).toNat] do
                let k := b - offset
                let v ← cell av k
                acc ←
                  match acc with
                  | none => pure (some v)
                  | some rest => some <$> iteVal (← Smt.eqK i k) v rest
          | .gap g a b =>
              let v ← cellIn av (← Smt.clampT i a b) g
              acc ←
                match acc with
                | none => pure (some v)
                | some rest => do
                    let inside ← Smt.andL [← Smt.le (.int a) i, ← Smt.le i (.int b)]
                    some <$> iteVal inside v rest
        match acc with
        | some v => return v
        | none => defaultVal (← avSrt av).elem

  /-- Cell `i` of `av`, for `i` in gap `g`. -/
  partial def cellIn (av : Nat) (i : Tm) (g : Nat) : LM Val := do
    let i ← Smt.norm i
    if let .int k := i then return ← cell av k
    let (il, ih) ← Smt.range i
    -- Skip stores whose index cannot be `i`.
    let mut av := av
    repeat
      let some (j, env, node) ← storeAt av | break
      let (jl, jh) ← Smt.range j
      unless jh < il || ih < jl do
        break
      av ← lowerA env node.args[0]!
    match ← avOf av with
    | .zero srt => defaultVal srt.elem
    | .base id path => gapCell id path g
    | .ite c a b => iteVal c (← cellIn a i g) (← cellIn b i g)
    | .node id ev =>
        let node := (← read).nodes[id]!
        let args := node.args
        let env := bindEnv node.bvs ev
        match node.op with
        | .store =>
            let j ← Smt.norm (← lowerS env args[1]!)
            let v ← lowerV env args[2]!
            if j == i then return v
            iteVal (← Smt.eqT i j) v (← cellIn (← lowerA env args[0]!) i g)
        | .lam => lowerV (env.insert (bvarId args[0]!) i) args[1]!
        | .scan => scanIn av env node i
        | _ => defaultVal node.srt.elem

  /-- The value shared by the cells of gap `g` of base `id` below `path`. -/
  partial def gapCell (id : Nat) (path : Array Int) (g : Nat) : LM Val := do
    if let some v := (← get).gapCells[(id, path, g)]? then return v
    let node := (← read).nodes[id]!
    let (lo, hi) :=
      match node.op with
      | .arrVar lo hi => (lo, hi)
      | _ => (-INF, INF)
    let srt := srtAfter node.srt (path.size + 1)
    let v ←
      if (← get).fill == .zero then
        let v ←
          if srt == .int && (0 < lo || hi < 0) then
            pure (.s (.int lo))
          else
            defaultVal srt
        if let .s t := v then
          modify fun s => { s with baseCells := s.baseCells.push (id, path, gapKey g, t) }
        pure v
      else
        match srt with
        | .arr .. => pure (.a (← intern (.base id (path.push (gapKey g)))))
        | _ =>
            let t ← if srt == .bool then Smt.declareBool else Smt.declare false lo hi
            modify
              fun s => { s with baseCells := s.baseCells.push (id, path, gapKey g, t) }
            pure (.s t)
    modify fun s => { s with gapCells := s.gapCells.insert (id, path, g) v }
    return v

  partial def cell (av : Nat) (k : Int) : LM Val := do
    if let some v := (← get).cells[(av, k)]? then return v
    let v ← cellRaw av k
    modify fun s => { s with cells := s.cells.insert (av, k) v }
    return v

  /-- Skips stores whose index cannot be `k`. -/
  partial def skipStores (av : Nat) (k : Int) : LM Nat := do
    let nodes := (← read).nodes
    let mut cur := av
    repeat
      if cur != av && (← get).cells.contains (cur, k) then break
      let .node id ev ← avOf cur | break
      let node := nodes[id]!
      unless node.op == .store do
        break
      let env := bindEnv node.bvs ev
      let (lo, hi) ← Smt.range (← lowerS env node.args[1]!)
      unless k < lo || hi < k do
        break
      cur ← lowerA env node.args[0]!
    return cur

  partial def cellRaw (av : Nat) (k : Int) : LM Val := do
    let skipped ← skipStores av k
    if skipped != av then return ← cell skipped k
    match ← avOf av with
    | .ite c a b => iteVal c (← cell a k) (← cell b k)
    | .zero srt => defaultVal srt.elem
    | .base id path => baseCell av id path k
    | .node id ev =>
        let node := (← read).nodes[id]!
        let args := node.args
        let env := bindEnv node.bvs ev
        match node.op with
        | .store =>
            let j ← Smt.norm (← lowerS env args[1]!)
            let v ← lowerV env args[2]!
            if j == .int k then return v
            -- Earlier stores at the same index are shadowed whenever `j != k`.
            let mut rest ← lowerA env args[0]!
            repeat
              let some (j', env', node') ← storeAt rest | break
              if j' != j then break
              rest ← lowerA env' node'.args[0]!
            iteVal (← Smt.eqK j k) v (← cell rest k)
        | .lam => lowerV (env.insert (bvarId args[0]!) (.int k)) args[1]!
        | .scan =>
            if k <= 0 then return ← lowerV env args[2]!
            advanceScan av env node k
            if let some v ← seeded av k then return v
            if let some v := (← get).cells[(av, k)]? then return v
            let regions := ((← get).scans.getD av {}).regions
            match regions.find? fun (a, b, _) => a <= k && k <= b with
            | some (a, _, sum) => regionValue env node a sum (.int k)
            | none =>
                Smt.unsupported "a scan cell"
                defaultVal node.srt.elem
        | _ => defaultVal node.srt.elem

  partial def scanStep (env : BEnv) (node : Node) (k prev : Tm) : LM Val :=
    lowerV ((env.insert (bvarId node.args[0]!) k).insert (bvarId node.args[1]!) prev)
      node.args[3]!

  /-- Cell `k` of scan `av`, which is computed or summarized. -/
  partial def scanValue (av : Nat) (env : BEnv) (node : Node) (k : Int) : LM Tm := do
    let .s t ← if k <= 0 then lowerV env node.args[2]! else cell av k
    |
      Smt.unsupported "a scan over arrays"
      return .int 0
    return t

  /-- Cell `k` of a region of a scan starting at `lo`. -/
  partial def regionValue (env : BEnv) (node : Node) (lo : Int) (sum : ScanSum) (k : Tm)
      : LM Val := do
    match sum with
    | .absorb start => scanStep env node k start
    | .additive start d =>
        let some m ← mulT (← Smt.addK k (1 - lo)) d
        |
          Smt.unsupported "a scan increment at a symbolic index"
          defaultVal node.srt.elem
        return .s (← Smt.addT start m)

  partial def setTop (av : Nat) (k : Int) : LM Unit :=
    modify
      fun s =>
        let st := s.scans.getD av {}
        { s with scans := s.scans.insert av { st with top := max st.top k } }

  partial def scanPoints (av : Nat) (env : BEnv) (node : Node) (a b : Int) : LM Unit := do
    for offset in [0:(b - a + 1).toNat] do
      let k := a + offset
      let v ← scanStep env node (.int k) (← scanValue av env node (k - 1))
      modify fun s => { s with cells := s.cells.insert (av, k) v }
      setTop av k

  /-- Summarizes scan `av` over `[a, b]` inside a gap, splitting it where probes say. -/
  partial def summarizeScan (av : Nat) (env : BEnv) (node : Node) (a b : Int)
      (depth : Nat)
      : LM Unit := do
    if b - a + 1 <= SMALL then return ← scanPoints av env node a b
    let start ← scanValue av env node (a - 1)
    let fresh : LM Tm :=
      if node.srt.elem == .bool then Smt.declareBool else Smt.declare false
    let found ←
      attempt do
        let x ← fresh
        let kv1 ← Smt.declare false a b
        let kv2 ← Smt.declare false a b
        let (r1, hits) ← watching kv1 (scanStep env node kv1 x)
        let .s r1 := r1 | return (none, hits)
        let .s r2 ← scanStep env node kv2 x | return (none, hits)
        let r1 ← Smt.norm r1
        let r2 ← Smt.norm r2
        -- Each step overwrites the earlier ones: `s[k] = step(k, start)`.
        let .s r21 ← scanStep env node kv2 r1 | return (none, hits)
        if (← Smt.norm r21) == r2 then return (some (ScanSum.absorb start), hits)
        if r1 == r2 then
          if let some d ← additiveOf r1 x then
            let x' ← fresh
            let .s r1' ← scanStep env node kv1 x' | return (none, hits)
            if (← additiveOf r1' x') == some d then
              return (some (ScanSum.additive start d), hits)
        return (none, hits)
    match found with
    | some (some sum, _) =>
        modify
          fun s =>
            let st := s.scans.getD av {}
            {
              s with
                scans :=
                  s.scans.insert av { st with regions := st.regions.push (a, b, sum) }
                probed := s.probed + 1
            }
        setTop av b
    | some (none, hits) =>
        let parts := cutAround a b (around hits)
        if depth < SPLIT_DEPTH && parts.size > 1 then
          for (point, p, q) in parts do
            if point then
              scanPoints av env node p q
            else
              summarizeScan av env node p q (depth + 1)
        else
          enumerateScan av env node a b
    | none => enumerateScan av env node a b

  partial def enumerateScan (av : Nat) (env : BEnv) (node : Node) (a b : Int)
      : LM Unit := do
    if b - a > SPLIT_LIMIT then
      Smt.unsupported s!"a scan over [{a}, {b}]"
      return
    let instr := (← getThe Smt.Enc).instruction
    modify fun s => { s with enumerated := s.enumerated.push (instr, b - a + 1) }
    scanPoints av env node a b

  partial def advanceScan (av : Nat) (env : BEnv) (node : Node) (k : Int) : LM Unit := do
    unless (← get).scans.contains av do
      seedScan av env node
    let top := ((← get).scans.getD av {}).top
    if k <= top then return
    for piece in pieces (← get).explicit (top + 1) k do
      match piece with
      | .pts a b => scanPoints av env node a b
      | .gap _ a b => summarizeScan av env node a b 0

  /-- Starts scan `av` from the cells of an earlier scan with the same template, below the
  first step where their holes may differ. -/
  partial def seedScan (av : Nat) (env : BEnv) (node : Node) : LM Unit := do
    let mut st : ScanState := {}
    if (← get).reuse then
      if let .node id _ ← avOf av then
        if let some tmpl ← tmplOf id then
          if let some holes ← lowerHoles env tmpl then
            let key := (tmpl.id, node.bvs.map fun b => env.getD b (.int 0))
            for (old, oldHoles) in ((← get).scanMemos.getD key #[]).reverse do
              let some d ← deltaHoles tmpl oldHoles holes DELTA_DEPTH | continue
              let ost := (← get).scans.getD old {}
              let top := min ost.top ((d[0]?.map (·.1)).getD INF - 1)
              if top < 1 then continue
              let regions :=
                ost.regions.filterMap
                  fun (a, b, sum) => if a <= top then some (a, min b top, sum) else none
              st := { top, regions, seed := some (old, top + 1) }
              modify fun s => { s with seededScans := s.seededScans + 1 }
              break
            modify
              fun s =>
                {
                  s with
                    scanMemos :=
                      s.scanMemos.insert key
                        (pushRecent (s.scanMemos.getD key #[]) (av, holes))
                }
    modify fun s => { s with scans := s.scans.insert av st }

  /-- Cell `k` of scan `av` from the scan it was seeded from, if below the seed. -/
  partial def seeded (av : Nat) (k : Int) : LM (Option Val) := do
    let mut cur := av
    repeat
      let some (old, m) := ((← get).scans.getD cur {}).seed | break
      if m <= k then break
      cur := old
      if (← get).cells.contains (cur, k) then break
    if cur == av then return none
    return some (← cell cur k)

  /-- Cell `i` of scan `av`, for `i` in a gap. -/
  partial def scanIn (av : Nat) (env : BEnv) (node : Node) (i : Tm) : LM Val := do
    let (il, ih) ← Smt.range i
    advanceScan av env node ih
    if let some (old, m) := ((← get).scans.getD av {}).seed then
      if ih < m then
        if let .node oid oev ← avOf old then
          let onode := (← read).nodes[oid]!
          return ← scanIn old (bindEnv onode.bvs oev) onode i
    let regions := ((← get).scans.getD av {}).regions
    -- Computed cells and parts of summarized regions covering `[il, ih]`.
    let mut segs : Array (Int × Int × Option (Int × ScanSum)) := #[]
    let mut k := il
    while k <= ih do
      match regions.find? fun (a, b, _) => a <= k && k <= b with
      | some (a, b, sum) =>
          segs := segs.push (k, min b ih, some (a, sum))
          k := min b ih + 1
      | none =>
          segs := segs.push (k, k, none)
          k := k + 1
      if segs.size.toInt64.toInt > SPLIT_LIMIT then
        Smt.unsupported s!"a scan read over [{il}, {ih}]"
        return ← defaultVal node.srt.elem
    let mut acc : Option Val := none
    for (a, b, sum) in segs.reverse do
      let v ←
        match sum with
        | none => cell av a
        | some (lo, sum) => do regionValue env node lo sum (← Smt.clampT i a b)
      acc ←
        match acc with
        | none => pure (some v)
        | some rest => do
            let inside ← Smt.andL [← Smt.le (.int a) i, ← Smt.le i (.int b)]
            some <$> iteVal inside v rest
    match acc with
    | some v => return v
    | none => defaultVal node.srt.elem

  partial def baseCell (av id : Nat) (path : Array Int) (k : Int) : LM Val := do
    if let some g := gapOf (← get).explicit k then
      let v ← gapCell id path g
      modify fun s => { s with cells := s.cells.insert (av, k) v }
      return v
    let node := (← read).nodes[id]!
    let (lo, hi) :=
      match node.op with
      | .arrVar lo hi => (lo, hi)
      | _ => (-INF, INF)
    let srt := srtAfter node.srt (path.size + 1)
    match srt with
    | .arr .. => return .a (← intern (.base id (path.push k)))
    | _ =>
        let t ← if srt == .bool then Smt.declareBool else Smt.declare false lo hi
        modify
          fun s =>
            {
              s with
                baseCells := s.baseCells.push (id, path, k, t)
                cells := s.cells.insert (av, k) (.s t)
            }
        if path.isEmpty then
          modify fun s => { s with materialized := s.materialized.insert (id, k) }
          trigger id k
        return .s t

  /-- Instantiates the axioms over base `id` that cell `k` completes. -/
  partial def trigger (id : Nat) (k : Int) : LM Unit := do
    let ir ← read
    for axIdx in (← get).axiomsByBase.getD id #[] do
      let ax := ir.axioms[axIdx]!
      for o in ax.offsets do
        let kk := k - o
        if (← get).axiomDone.contains (axIdx, kk) then continue
        let eager := ax.offsets == #[0]
        let s ← get
        let ready :=
          eager
          || ax.bases.all
              fun b =>
                ax.offsets.all fun o' => s.materialized.contains (b, kk + o')
        unless ready do
          continue
        modify fun s => { s with axiomDone := s.axiomDone.insert (axIdx, kk) }
        if eager then
          for b in ax.bases do
            discard <| cell (← intern (.base b #[])) kk
        let v ← lowerS (({} : BEnv).insert ax.bv (.int kk)) ax.body
        if ax.hard then
          Smt.require v ax.description (background := true)
        else
          Smt.assumeInv v

  /--
  Probes a fold over `[a, b]` inside a gap with two fresh indices. When the condition, and the
  value if needed, agree, returns the shared condition and either the shared value or the
  offset of the value from the index. Also returns the literals the first probe was compared
  with.
  -/
  partial def probeFold (env : BEnv) (node : Node) (needValue : Bool) (a b : Int)
      : LM (Option (Tm × Option Val × Option Int) × Array Int) := do
    let args := node.args
    let kb := bvarId args[0]!
    let cond (k : Tm) : LM Tm := do
      Smt.norm (← lowerS (env.insert kb k) args[3]!)
    let value (k : Tm) : LM Val := lowerV (env.insert kb k) args[4]!
    let result ←
      attempt do
        let kv1 ← Smt.declare false a b
        let ((c1, v1), hits) ←
          watching kv1 do
            let c ← cond kv1
            let v ←
              if needValue && c != .bool false then some <$> value kv1 else pure none
            pure (c, v)
        let kv2 ← Smt.declare false a b
        let c2 ← cond kv2
        if c1 != c2 then return (none, hits)
        let some v1 := v1 | return (some (c1, none, none), hits)
        let v2 ← value kv2
        if v1 == v2 then return (some (c1, some v1, none), hits)
        let .s t1 := v1 | return (none, hits)
        let .s t2 := v2 | return (none, hits)
        let (b1, o1) ← Smt.offsetOf t1
        let (b2, o2) ← Smt.offsetOf t2
        if b1 == kv1 && b2 == kv2 && o1 == o2 then return (some (c1, none, some o1), hits)
        return (none, hits)
    return result.getD (none, #[])

  partial def lowerFold (env : BEnv) (id : Nat) (node : Node) (kind : FoldKind)
      : LM Val := do
    let args := node.args
    let kb := bvarId args[0]!
    -- The largest index satisfying a condition is the last one.
    let maxIndex := kind == .max && args[4]! == args[0]!
    let kind := if maxIndex then .last else kind
    let lo ← Smt.norm (← lowerS env args[1]!)
    let hi ← Smt.norm (← lowerS env args[2]!)
    let (first, _) ← Smt.range lo
    let (_, top) ← Smt.range hi
    let ps := pieces (← get).explicit first top
    if explicitCount ps > SPLIT_LIMIT then
      Smt.unsupported s!"a fold over [{first}, {top}]"
      return ← defaultVal node.srt
    let guard (k : Int) : LM Tm := do
      Smt.norm (← Smt.andL [← Smt.le lo (.int k), ← Smt.le (.int k) hi])
    let cond (k : Int) : LM Tm := do
      Smt.norm (← lowerS (env.insert kb (.int k)) args[3]!)
    let value (k : Int) : LM Val := lowerV (env.insert kb (.int k)) args[4]!
    -- A condition contributing nothing.
    let neutral (c : Tm) : Bool := c == .bool (kind == .all)
    let needValue := kind != .any && kind != .all
    let down := kind == .last
    -- An earlier fold with the same template, and the indices where the bodies may differ.
    let mut plan : Option ((Nat × Array Tm) × Array Val) := none
    let mut old : Option (FoldMemo × Array (Int × Int)) := none
    if (← get).reuse then
      if let some tmpl ← tmplOf id then
        if let some holes ← lowerHoles env tmpl then
          let key := (tmpl.id, node.bvs.map fun b => env.getD b (.int 0))
          plan := some (key, holes)
          for m in ((← get).foldMemos.getD key #[]).reverse do
            if let some d ← deltaHoles tmpl m.holes holes DELTA_DEPTH then
              old := some (m, d)
              break
    let mut items : Std.TreeMap Int Tm := (old.map (·.1.items)).getD {}
    let mut visited : Array (Int × Int) := #[]
    -- Work in iteration order: the top of the stack is visited next.
    let mut stack : Array Cand := #[]
    for piece in if down then ps else ps.reverse do
      stack :=
        stack.push
          (match piece with
            | .pts a b => .span a b
            | .gap _ a b => .region a b 0)
    let mut acc : Tm ←
      if kind == .max || kind == .sum then lowerS env args[5]! else pure (.int 0)
    let mut parts : Array Tm := #[]
    let mut picks : Array (Tm × Val) := #[]
    let mut tail : Option Val := none
    let mut early : Option Val := none
    let instr := (← getThe Smt.Enc).instruction
    while h : 0 < stack.size do
      let cand := stack[stack.size - 1]
      stack := stack.pop
      -- The guarded condition, and the value when it holds, at a point or over a uniform region.
      let item : Option (Tm × Option (LM Val)) ←
        match cand with
        | .span a b =>
            let k := if down then b else a
            -- The earlier condition at `k`, or a run of neutral indices from `k` to `e`.
            let reused : Option (Option Tm × Int) :=
              match old with
              | some (m, d) =>
                  match ivAt m.cover k, ivAt d k with
                  | some (cl, ch), none =>
                      match items.get? k with
                      | some c => some (some c, k)
                      | none =>
                          let i := firstEnding d k
                          if down then
                            let e := max a cl
                            let e := if i > 0 then max e (d[i - 1]!.2 + 1) else e
                            let e :=
                              match items.getEntryLT? k with
                              | some (p, _) => max e (p + 1)
                              | none => e
                            some (none, e)
                          else
                            let e := min b ch
                            let e := if h : i < d.size then min e (d[i].1 - 1) else e
                            let e :=
                              match items.getEntryGT? k with
                              | some (p, _) => min e (p - 1)
                              | none => e
                            some (none, e)
                  | _, _ => none
              | none => none
            let (c, p, q) ←
              match reused with
              | some (c, e) =>
                  let (p, q) := if down then (e, k) else (k, e)
                  modify
                    fun s => { s with reusedPoints := s.reusedPoints + (q - p + 1).toNat }
                  pure (c, p, q)
              | none => pure (none, k, k)
            if down then
              if a < p then stack := stack.push (.span a (p - 1))
            else if q < b then
              stack := stack.push (.span (q + 1) b)
            if plan.isSome && reused.isSome then visited := pushIv visited p q
            if reused.isSome && c.isNone then
              pure none
            else
              let g ← guard k
              if g == .bool false then
                pure none
              else
                let c ←
                  match c with
                  | some c => pure c
                  | none => do
                      let c ← cond k
                      modify fun s => { s with points := s.points + 1 }
                      if plan.isSome then
                        items := if neutral c then items.erase k else items.insert k c
                        visited := pushIv visited k k
                      pure c
                if kind == .all then
                  pure (some (← Smt.norm (← Smt.impliesT g c), none))
                else
                  pure (some (← Smt.norm (← Smt.andL [g, c]), some (value k)))
        | .pt k =>
            stack := stack.push (.span k k)
            pure none
        | .region a b depth =>
            if b - a + 1 <= SMALL then
              stack := stack.push (.span a b)
              pure none
            else
              let (found, hits) ← probeFold env node needValue a b
              match found with
              | some (c, v, off) =>
                  modify fun s => { s with probed := s.probed + 1 }
                  stack := stack.push (.uni a b c v off)
              | none =>
                  let parts' := cutAround a b (around hits)
                  if depth < SPLIT_DEPTH && parts'.size > 1 then
                    for (point, p, q) in if down then parts' else parts'.reverse do
                      stack :=
                        stack.push (if point then .pt p else .region p q (depth + 1))
                  else
                    modify
                      fun s =>
                        { s with enumerated := s.enumerated.push (instr, b - a + 1) }
                    stack := stack.push (.span a b)
              pure none
        | .uni a b c v off =>
            let s ← Smt.maxT (.int a) lo
            let e ← Smt.minT (.int b) hi
            let ne ← Smt.le s e
            if kind == .all then
              pure (some (← Smt.norm (← Smt.impliesT ne c), none))
            else
              let pos := if kind == .first then s else e
              let val : LM Val :=
                match v, off with
                | some v, _ => pure v
                | none, some o => do return .s (← Smt.addK pos o)
                | none, none => defaultVal node.srt
              if kind == .sum then
                let .s vt ← val | pure none
                match ← mulT (← Smt.addK (← Smt.subT e s) 1) vt with
                | some total =>
                    pure (some (← Smt.norm (← Smt.andL [ne, c]), some (pure (.s total))))
                | none =>
                    -- A symbolic count times a symbolic value: enumerate instead.
                    modify
                      fun s =>
                        { s with enumerated := s.enumerated.push (instr, b - a + 1) }
                    stack := stack.push (.span a b)
                    pure none
              else
                pure (some (← Smt.norm (← Smt.andL [ne, c]), some val))
      let some (gc, val) := item | continue
      match kind with
      | .any =>
          if gc == .bool true then
            early := some (.s gc)
            break
          parts := parts.push gc
      | .all =>
          if gc == .bool false then
            early := some (.s gc)
            break
          parts := parts.push gc
      | .max | .sum =>
          if gc == .bool false then continue
          let some val := val | continue
          match ← val with
          | .s v =>
              if kind == .max then
                acc ← Smt.iteT gc (← Smt.maxT acc v) acc
              else
                acc ← Smt.addT acc (← Smt.iteT gc v (.int 0))
          | .a _ =>
              early := some (← defaultVal node.srt)
              break
      | .last | .first =>
          -- Collect from the winning end until a literal hit.
          if gc == .bool false then continue
          let some val := val | continue
          if gc == .bool true then
            tail := some (← val)
            break
          picks := picks.push (gc, ← val)
    if let some (key, holes) := plan then
      if (← getThe Smt.Enc).unsupported.isNone then
        let kept :=
          match old with
          | some (m, d) => subIvs m.cover d
          | none => #[]
        let memo : FoldMemo := { holes, cover := normIvs (kept ++ visited), items }
        modify
          fun s =>
            {
              s with
                foldMemos :=
                  s.foldMemos.insert key (pushRecent (s.foldMemos.getD key #[]) memo)
            }
    if let some v := early then return v
    match kind with
    | .any => return .s (← Smt.orL parts.toList)
    | .all => return .s (← Smt.andL parts.toList)
    | .max | .sum => return .s acc
    | .last | .first =>
        let mut result ←
          match tail with
          | some v => pure v
          | none => lowerV env args[5]!
        for (gc, v) in picks.reverse do
          result ← iteVal gc v result
        if maxIndex then
          let .s last := result | return result
          return .s (← Smt.maxT (← lowerS env args[5]!) last)
        return result
end

def lowerInit : LM Unit := do
  let ir ← read
  let mut byBase : Std.HashMap Nat (Array Nat) := {}
  for h : i in [0:ir.axioms.size] do
    for b in ir.axioms[i].bases do
      byBase := byBase.insert b ((byBase.getD b #[]).push i)
  modify fun s => { s with axiomsByBase := byBase }

def lowerCmd (cmd : Cmd) : LM Unit := do
  match cmd with
  | .instr i _ =>
      modifyThe Smt.Enc
        fun enc => { enc with instruction := i, out := enc.out.push s!"; instr {i}" }
      let size := (← getThe Smt.Enc).infos.size
      modify fun s => { s with sizes := s.sizes.push (i, size) }
  | .require t description background =>
      Smt.require (← lowerS {} t) description background
  | .assume cap t =>
      let v ← lowerS {} t
      if cap then Smt.assumeCap v else Smt.assumeInv v
  modify fun s => { s with bound := {} }

/-- Runs a lowering step on `ir` from the given states. -/
def runLM (ir : Ir) (act : LM Unit) (ls : LState) (enc : Smt.Enc) : LState × Smt.Enc :=
  let ((_, ls), enc) := ((act.run ir).run ls).run enc
  (ls, enc)

/-- Lowers `ir` into `enc`. -/
def lower (ir : Ir) (enc : Smt.Enc) : LState × Smt.Enc :=
  Id.run do
    let (ls, enc) := runLM ir lowerInit {} enc
    let mut ls := ls
    let mut enc := enc
    for cmd in ir.cmds do
      if enc.falsified.isSome then break
      (ls, enc) := runLM ir (lowerCmd cmd) ls enc
    return (ls, enc)

end CCFRaft.MidTrace.Gen
