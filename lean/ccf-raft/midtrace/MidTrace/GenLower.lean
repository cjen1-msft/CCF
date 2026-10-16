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
        lowerFold env node kind

  /-- The lowered index of a `store`, with its environment and node. -/
  partial def storeAt (av : Nat) : LM (Option (Tm × BEnv × Node)) := do
    let .node id ev ← avOf av | return none
    let node := (← read).nodes[id]!
    unless node.op == .store do
      return none
    let env := bindEnv node.bvs ev
    return some (← Smt.norm (← lowerS env node.args[1]!), env, node)

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
    let top := ((← get).scans.getD av {}).top
    if k <= top then return
    for piece in pieces (← get).explicit (top + 1) k do
      match piece with
      | .pts a b => scanPoints av env node a b
      | .gap _ a b => summarizeScan av env node a b 0

  /-- Cell `i` of scan `av`, for `i` in a gap. -/
  partial def scanIn (av : Nat) (env : BEnv) (node : Node) (i : Tm) : LM Val := do
    let (il, ih) ← Smt.range i
    advanceScan av env node ih
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

  partial def lowerFold (env : BEnv) (node : Node) (kind : FoldKind) : LM Val := do
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
    let cond (k : Int) : LM Tm := lowerS (env.insert kb (.int k)) args[3]!
    let value (k : Int) : LM Val := lowerV (env.insert kb (.int k)) args[4]!
    let needValue := kind != .any && kind != .all
    let down := kind == .last
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
    let instr := (← getThe Smt.Enc).instruction
    while h : 0 < stack.size do
      let cand := stack[stack.size - 1]
      stack := stack.pop
      -- The guarded condition, and the value when it holds, at a point or over a uniform region.
      let item : Option (Tm × Option (LM Val)) ←
        match cand with
        | .span a b =>
            if a < b then
              stack := stack.push (if down then .span a (b - 1) else .span (a + 1) b)
            let k := if down then b else a
            let g ← guard k
            if g == .bool false then
              pure none
            else if kind == .all then
              pure (some (← Smt.norm (← Smt.impliesT g (← cond k)), none))
            else
              pure (some (← Smt.norm (← Smt.andL [g, ← cond k]), some (value k)))
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
          if gc == .bool true then return .s gc
          parts := parts.push gc
      | .all =>
          if gc == .bool false then return .s gc
          parts := parts.push gc
      | .max =>
          if gc == .bool false then continue
          let some val := val | continue
          let .s v ← val | return ← defaultVal node.srt
          acc ← Smt.iteT gc (← Smt.maxT acc v) acc
      | .sum =>
          if gc == .bool false then continue
          let some val := val | continue
          let .s v ← val | return ← defaultVal node.srt
          acc ← Smt.addT acc (← Smt.iteT gc v (.int 0))
      | .last | .first =>
          -- Collect from the winning end until a literal hit.
          if gc == .bool false then continue
          let some val := val | continue
          if gc == .bool true then
            tail := some (← val)
            break
          picks := picks.push (gc, ← val)
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
