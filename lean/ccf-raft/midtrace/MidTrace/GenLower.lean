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

structure LState where
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

  /-- A read at `i`: a case split over the interval of `i`. -/
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
        if hi - lo > SPLIT_LIMIT then
          Smt.unsupported s!"a read over [{lo}, {hi}]"
          return ← defaultVal (← avSrt av).elem
        let mut acc ← cell av hi
        for offset in [1:(hi - lo + 1).toNat] do
          let k := hi - offset
          acc ← iteVal (← Smt.eqK i k) (← cell av k) acc
        return acc

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
            -- Unroll upwards from the last known cell rather than recursing.
            let mut j := k - 1
            while j > 0 && !(← get).cells.contains (av, j) do
              j := j - 1
            for offset in [0:(k - j).toNat] do
              discard <| cell av (j + offset)
            let .s prev ← cell av (k - 1)
            |
              Smt.unsupported "a scan over arrays"
              defaultVal node.srt.elem
            lowerV ((env.insert (bvarId args[0]!) (.int k)).insert (bvarId args[1]!) prev)
              args[3]!
        | _ => defaultVal node.srt.elem

  partial def baseCell (av id : Nat) (path : Array Int) (k : Int) : LM Val := do
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
    if top - first > SPLIT_LIMIT then
      Smt.unsupported s!"a fold over [{first}, {top}]"
      return ← defaultVal node.srt
    let count := if top < first then 0 else (top - first + 1).toNat
    let guarded (k : Int) : LM Tm := do
      let g ← Smt.andL [← Smt.le lo (.int k), ← Smt.le (.int k) hi]
      if (← Smt.norm g) == .bool false then return .bool false
      let c ← lowerS (env.insert kb (.int k)) args[3]!
      Smt.norm (← Smt.andL [g, c])
    let value (k : Int) : LM Val := lowerV (env.insert kb (.int k)) args[4]!
    match kind with
    | .max =>
        let mut acc ← lowerS env args[5]!
        for offset in [0:count] do
          let k := first + offset
          let gc ← guarded k
          if gc == .bool false then continue
          let .s v ← value k | return ← defaultVal node.srt
          acc ← Smt.iteT gc (← Smt.maxT acc v) acc
        return .s acc
    | .sum =>
        let mut acc ← lowerS env args[5]!
        for offset in [0:count] do
          let k := first + offset
          let gc ← guarded k
          if gc == .bool false then continue
          let .s v ← value k | return ← defaultVal node.srt
          acc ← Smt.addT acc (← Smt.iteT gc v (.int 0))
        return .s acc
    | .last | .first =>
        -- Collect from the winning end until a literal hit.
        let mut picks : Array (Tm × Int) := #[]
        let mut tail ← lowerV env args[5]!
        for offset in [0:count] do
          let k := if kind == .last then top - offset else first + offset
          let gc ← guarded k
          if gc == .bool false then continue
          if gc == .bool true then
            tail ← value k
            break
          picks := picks.push (gc, k)
        let mut acc := tail
        for (gc, k) in picks.reverse do
          acc ← iteVal gc (← value k) acc
        if maxIndex then
          let .s last := acc | return acc
          return .s (← Smt.maxT (← lowerS env args[5]!) last)
        return acc
    | .any =>
        let mut parts := #[]
        for offset in [0:count] do
          let gc ← guarded (first + offset)
          if gc == .bool true then return .s gc
          parts := parts.push gc
        return .s (← Smt.orL parts.toList)
    | .all =>
        let mut parts := #[]
        for offset in [0:count] do
          let k := first + offset
          let g ← Smt.andL [← Smt.le lo (.int k), ← Smt.le (.int k) hi]
          if (← Smt.norm g) == .bool false then continue
          let c ← lowerS (env.insert kb (.int k)) args[3]!
          let part ← Smt.norm (← Smt.impliesT g c)
          if part == .bool false then return .s part
          parts := parts.push part
        return .s (← Smt.andL parts.toList)
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
