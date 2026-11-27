module

public meta import Lean
public import Relevance.Walk

/-!
# Shared lemma cases

With `(shared := true)` the walker (`Walk.lean`) walks every theorem in scope once, as a unit
with its parameters as local variables, and records each call of a theorem as a call site
instead of inlining it. This file turns those records into one predicate per case of each
lemma, defined compositionally over the call graph, so that the definitions are linear in the
number of call sites rather than in the number of call paths.

## Definitions

Fix a level (step or state) and its pattern's binders `X`. A parameter of a unit is fixed when
at every call site from a unit reached at that level its argument is a term of `X` alone (after
the caller's fixed parameters are replaced by theirs, and a root's kept binders by `X`), the same
term at every site; it is replaced by that term everywhere.

The local closure of a set of conditions in a unit is the closure of `Walk.lean` (`teleOf`) with
the unit's fixed parameters (or a root's kept binders) not closed, and its other parameters
neither closed nor dropped: a parameter that the closure reaches is mentioned, and the
parameters its type mentions are mentioned with it; a hypothesis or a proof parameter is taken
when its type mentions a closed variable or a mentioned parameter.

`reach_k X y` ("unit `v` is reached with arguments `y` for its mentioned parameters `S`", with
flags: under a clause obligation, below a data binder outside a split) is the disjunction over
the call sites of `v` from a unit `u` reached at the level, and for a lemma `u` over the
predicates `reach_j` of `u` for the parameters `S_u` that the site's closure mentions, of

    ∃ z : S_u, reach_j X z ∧ ∃ closed, facts ∧ conditions at the site ∧ y = arguments

(for a root `u`: without `reach_j`, its kept binders read as `X`). The equalities are
heterogeneous when the parameter's type mentions another non-fixed parameter.

The shared class of a case (level, lemma, split, branch) is the disjunction, over the
occurrences of the branch in the lemma's unit and over the `reach` predicates of the unit for
the parameters that the branch's closure mentions, of `∃ y, reach X y ∧ ∃ closed, facts ∧
conditions`. A case of a root is its predicate of `Walk.lean`.

## Framing, clause attribution and newness

A clause obligation is opened where the state pattern's structure is built, as in `Walk.lean`,
but only on paths on which no obligation is open yet: a site or branch under a lemma's own
obligation contributes one disjunct per path kind, with the obligation's premises, the clause
premises at the pre-state negated (newness), and only with the `reach` predicates whose flag says
no obligation is open above; without it, only with those whose flag says one is. The pre-state
inside a lemma is the parameter that its first call site passes the caller's pre-state to; when
there is none, the premises at the pre-state are read at the pattern's pre-state.

A branch or call site under an obligation whose pre-state premises are all hypotheses in scope
(the frame test of `Walk.lean`) contributes nothing: a frame at a call site frames everything
below it. A branch on a path with no obligation and with a data binder outside a split is
unattributed and contributes nothing at step level, as in `Walk.lean`.

## Differences from per-path classes

- A proof passed as an argument is walked at the call site, with the caller's conditions; per
  path it is walked where the callee uses it, under the callee's conditions.
- The frame test for an obligation opened above a lemma is made at the call sites, not at the
  branch: a witness hypothesis local to the lemma is not seen.
- A hypothesis of a caller that mentions a variable closed only because an argument shares it
  with another closed variable (and not through the parameters the lemma's case mentions) is
  not taken.
- A recursive call is cut (counted).
-/

public meta section

open Lean Meta

namespace Relevance

/-- A path kind into a unit: the `reach` constant (over `X` and the mentioned parameters), and
its flags. -/
structure Combo where
  reach : Expr
  clause : Bool
  bound : Bool
  /-- Under a clause obligation opened above the unit: the clause premises at the pre-state, over
  the unit's parameters, when every variable they mention is passed down as an argument. -/
  prem : Option (Array Expr) := none
  /-- The clauses whose obligations feed into this path kind (metadata only; not part of the
  `mkReach` partition key, so clauses sharing a continuation share one `reach` definition). -/
  cnames : Array Name := #[]
  deriving Inhabited

/-- One disjunct of a `reach` definition or of a class: its flags, the clause premises at the
pre-state carried to the callee's parameters (see `Combo.prem`), and the predicate. -/
structure Disj where
  clause : Bool
  bound : Bool
  prem : Option (Array Expr) := none
  cnames : Array Name := #[]
  e : Expr
  deriving Inhabited

/-- One shared class: its case and its predicate over `X`. -/
structure SharedClass where
  level : Level
  decl : Name
  split : String
  tag : String
  pred : Expr
  occurrences : Array Nat
  /-- The clauses whose obligations the class's disjuncts are under. -/
  clauses : Array Name := #[]
  deriving Inhabited

structure ShSt where
  memo : Std.HashMap (Nat × List Nat) (Array Combo) := {}
  inProgress : Std.HashSet (Nat × List Nat) := {}
  defs : Array Name := #[]
  cycles : Nat := 0
  missingArgs : Nat := 0
  rootCallee : Nat := 0
  framedSites : Nat := 0
  /-- Per walked branch reached at this level (index into the branch records): its role. -/
  roles : Array (Nat × String) := #[]
  /-- Per branch (index) and clause: some kept path kind into it is under that clause. -/
  clauseOf : Std.HashSet (Nat × Name) := {}
  /-- The keys of `up` for which some path kind was dropped as framing. -/
  framedInto : Std.HashSet (Nat × List Nat) := {}
  /-- Path kinds under an obligation whose premises could not be carried to a callee. -/
  carryLost : Nat := 0
  /-- Units (index) reached under the obligation of a clause. -/
  unitClauses : Std.HashSet (Nat × Name) := {}

abbrev ShM := StateT ShSt MetaM

/-- `lctx` with the declarations `ds` appended. -/
def extendLCtx (lctx : LocalContext) (ds : Array LocalDecl) : LocalContext :=
  ds.foldl (fun l d => if l.contains d.fvarId then l else
    match d with
    | .cdecl _ id n ty bi k => l.mkLocalDecl id n ty bi k
    | .ldecl _ id n ty v nd k => l.mkLetDecl id n ty v nd k) lctx

/-- Run `k` in `lctx` extended with the current declarations of `xs`. -/
def withExtended (lctx : LocalContext) (xs : Array Expr) (k : MetaM α) : MetaM α := do
  let cur ← getLCtx
  let ds := xs.filterMap fun x => cur.find? x.fvarId!
  withLCtx (extendLCtx lctx ds) (← getLocalInstances) k

/-- The closure of `teleOf` in `lctx`: `keep` not closed, `params` mentioned rather than closed.
Returns the telescope and the mentioned parameters (in `params` order). -/
def teleIn (keep : Std.HashSet FVarId) (params : Array FVarId) (walking : Array FVarId)
    (conds seeds extra : Array Expr) : MetaM (Tele × Array FVarId) := do
  let lctx ← getLCtx
  let isParam (f : FVarId) := params.contains f
  let mut closed : Std.HashSet FVarId := {}
  let mut mention : Std.HashSet FVarId := {}
  let mut facts : Array Expr := #[]
  let mut factSet : Std.HashSet FVarId := {}
  let mut work : Array FVarId := #[]
  let mut condFacts : Array Expr := #[]
  for c in conds do
    let ty ← zetaAll (← inferType c)
    match c with
    | .fvar id =>
      if let some d := lctx.find? id then
        if !d.isLet (allowNondep := true) && !isParam id then
          work := work.push id
          continue
    | _ => pure ()
    condFacts := condFacts.push ty
    work := work ++ (collectFVars {} ty).fvarIds
  for e in seeds ++ extra do
    work := work ++ (collectFVars {} (← zetaAll e)).fvarIds
  let mut changed := true
  while changed do
    changed := false
    while !work.isEmpty do
      let f := work.back!
      work := work.pop
      if keep.contains f || closed.contains f || mention.contains f then continue
      let some d := lctx.find? f | continue
      if d.isLet (allowNondep := true) then continue
      if isParam f then mention := mention.insert f else closed := closed.insert f
      work := work ++ (collectFVars {} (← zetaAll d.type)).fvarIds
    for d in lctx do
      let f := d.fvarId
      if d.isImplementationDetail || closed.contains f || mention.contains f || factSet.contains f then
        continue
      if keep.contains f || walking.contains f then continue
      unless ← isProp d.type do continue
      let ty ← zetaAll d.type
      let fs := (collectFVars {} ty).fvarIds
      if fs.any fun g => closed.contains g || mention.contains g then
        if d.isLet (allowNondep := true) || isParam f then
          factSet := factSet.insert f
          facts := facts.push ty
        else
          work := work.push f
        work := work ++ fs
        changed := true
    unless work.isEmpty do changed := true
  let order := lctx.foldl (init := #[]) fun acc d =>
    if closed.contains d.fvarId then acc.push d.fvarId else acc
  let ms := params.filter mention.contains
  return ({ closed := order, hypTys := facts ++ condFacts }, ms)

/-- `∃ ms, r ∧ body`, innermost last. -/
def existsOver (ms : Array Expr) (body : Expr) : MetaM Expr := do
  let mut e := body
  for x in ms.reverse do
    let ty ← zetaAll (← inferType x)
    let lam ← mkLambdaFVars #[x] e
    let lam := lam.updateLambdaE! ty lam.bindingBody!
    e := mkApp2 (mkConst ``Exists [← getLevel ty]) ty lam
  return e

/-- `y = a`, or `HEq y a` when `hetero`. -/
def mkEqY (y yTy a : Expr) (hetero : Bool) : MetaM Expr := do
  let aTy ← inferType a
  let lvl ← getLevel aTy
  if hetero then return mkApp4 (mkConst ``HEq [lvl]) yTy y aTy a
  return mkApp3 (mkConst ``Eq [lvl]) aTy y a

structure SharedIn where
  cfg : Config
  level : Level
  /-- The pattern's binders (in the current local context). -/
  xs : Array Expr
  units : Array UnitRec
  sites : Array SiteRec
  /-- Per unit: whether it is reached at this level. -/
  reached : Array Bool
  /-- Per unit and parameter: its value over `xs` when fixed. -/
  fixed : Array (Array (Option Expr))
  /-- Per unit: the indices of the sites that call it. -/
  callers : Array (Array Nat)
  /-- Per unit: the number of its parameters that every reached call site supplies; the others
  are binders of the unit's body, as in a walk that inlines it. -/
  arity : Array Nat
  /-- Per unit: whether a parameter that not every call site supplies is data. -/
  tailBound : Array Bool
  index : Std.HashMap WalkUnit Nat
  ns : Name

def unitIdx (inp : SharedIn) (u : WalkUnit) : Option Nat := inp.index.get? u

/-- The keep set and the non-fixed parameters of unit `ui`, and the substitution of fixed
parameters (and a root's kept binders) by terms of `xs`. -/
def unitFrame (inp : SharedIn) (ui : Nat) :
    Std.HashSet FVarId × Array FVarId × Array Expr × Array Expr := Id.run do
  let ur := inp.units[ui]!
  if ur.isRoot then
    return (ur.keep.foldl (fun s x => s.insert x.fvarId!) {}, #[], ur.keep, inp.xs)
  let mut keep : Std.HashSet FVarId := {}
  let mut free := #[]
  let mut from_ := #[]
  let mut to := #[]
  for (p, i) in ur.params.zipIdx do
    if i ≥ inp.arity[ui]! then continue
    match inp.fixed[ui]![i]! with
    | some v => keep := keep.insert p.fvarId!; from_ := from_.push p; to := to.push v
    | none => free := free.push p.fvarId!
  return (keep, free, from_, to)

/-- The clause premises at the pre-state of an obligation, read at the pattern's pre-state when
the walk deferred them. -/
def premSOf (inp : SharedIn) (cl : Clause) : MetaM (Array Expr) := do
  unless cl.deferred do return cl.premS
  let (some pre, _) ← stepEnds inp.cfg inp.xs inp.xs | return #[]
  let paramsS := (← stateAt inp.cfg.statePat pre).getAppArgs
  let cv ← getConstInfoCtor cl.ctor
  let ty := cv.type.instantiateLevelParams cv.levelParams cl.ctorLevels
  let mut tS ← instantiateForall ty paramsS
  for k in [0:cl.idx] do
    tS := tS.bindingBody!.instantiate1 cl.ctorArgs[cv.numParams + k]!
  premisesAt tS.bindingDomain! cl.xs cl.prems

/-- The closed body of a closure in the current local context, over `xs`, the mentioned
parameters and (for a lemma) `r` applied to them. -/
def closedPart (inp : SharedIn) (ui : Nat) (walking : Array FVarId) (conds seeds extra : Array Expr)
    (eqs : Array Expr → MetaM (Array Expr)) :
    MetaM (Array Expr × (Option Expr → MetaM Expr)) := do
  let (keep, free, from_, to) := unitFrame inp ui
  let (tele, ms) ← teleIn keep free walking conds seeds extra
  let ms := ms.map mkFVar
  let es ← eqs ms
  let body ← closeBody (tele.closed.map mkFVar) (tele.hypTys ++ (← extra.mapM zetaAll) ++ es)
  let finish (r : Option Expr) : MetaM Expr := do
    let e ← match r with
      | some r => existsOver ms (mkAnd (mkAppN r (inp.xs ++ ms)) body)
      | none => pure body
    return e.replaceFVars from_ to
  return (ms, finish)

/-- `e` with every occurrence of one of the terms `args` replaced by the parameter `ps` at the
same position (outermost first), when the result mentions no other local variable than `ps`. -/
def carryTo (args ps : Array Expr) (e : Expr) : Option Expr :=
  let r := e.replace fun t => (args.findIdx? (· == t)).bind (ps[·]?)
  if (collectFVars {} r).fvarIds.all fun f => ps.any (·.fvarId! == f) then some r else none

/-- Group disjuncts by flags and carried premises (not clause name) into `reach` definitions
over `xs ++ ys`, merging clause-name metadata and deduplicating identical disjuncts. -/
def mkReach (inp : SharedIn) (ys : Array Expr) (ds : Array Disj) :
    ShM (Array Combo) := do
  let mut out := #[]
  let mut keys : Array (Bool × Bool × Option (Array Expr)) := #[]
  for d in ds do
    let k := (d.clause, d.bound, d.prem)
    unless keys.contains k do keys := keys.push k
  for (cl, bd, pm) in keys do
    let mut es : Array Expr := #[]
    let mut cns : Array Name := #[]
    for d in ds do
      if d.clause == cl && d.bound == bd && d.prem == pm then
        unless es.contains d.e do es := es.push d.e
        for cn in d.cnames do
          unless cn.isAnonymous || cns.contains cn do cns := cns.push cn
    if es.isEmpty then continue
    let v ← mkLambdaFVars (inp.xs ++ ys) (mkOrN es)
    let v ← instantiateMVars v
    let k := (← get).defs.size
    let name := inp.ns ++ Name.mkSimple s!"reach_{k}"
    let ty ← inferType v
    let lps := (collectLevelParams {} v).params.toList
    addDecl <| .defnDecl { name, levelParams := lps, type := ty, value := v,
                           hints := .abbrev, safety := .safe }
    modify fun s => { s with defs := s.defs.push name }
    out := out.push { reach := mkConst name (lps.map mkLevelParam), clause := cl, bound := bd,
                      prem := pm, cnames := cns }
  return out

/-- Run `k` with local variables `ys` standing for the parameters `ps` (declared in `lctx`) of a
unit, with fixed parameters replaced. -/
partial def withYs (lctx : LocalContext) (ps : Array Expr) (from_ to : Array Expr)
    (k : Array Expr → ShM α) (acc : Array Expr := #[]) : ShM α := do
  if acc.size == ps.size then return ← k acc
  let p := ps[acc.size]!
  let some d := lctx.find? p.fvarId! | throwError "relevance: parameter not in scope"
  let ty ← withLCtx lctx (← getLocalInstances) (zetaAll d.type)
  let ty := (ty.replaceFVars (ps.extract 0 acc.size) acc).replaceFVars from_ to
  withLocalDeclD d.userName ty fun y => withYs lctx ps from_ to k (acc.push y)

mutual

/-- The path kinds into unit `vi` for its mentioned parameters `S` (indices into its params). -/
partial def up (inp : SharedIn) (vi : Nat) (S : List Nat) : ShM (Array Combo) := do
  let key := (vi, S)
  if let some r := (← get).memo.get? key then return r
  if (← get).inProgress.contains key then
    modify fun s => { s with cycles := s.cycles + 1 }
    return #[]
  modify fun s => { s with inProgress := s.inProgress.insert key }
  let v := inp.units[vi]!
  let (_, vFree, vFrom, vTo) := unitFrame inp vi
  let ps := S.toArray.map (v.params[·]!)
  let heteros := ps.map fun p => match v.lctx.find? p.fvarId! with
    | some d => (collectFVars {} d.type).fvarIds.any vFree.contains
    | none => true
  let r ← withYs v.lctx ps vFrom vTo fun ys => do
    let mut ds : Array Disj := #[]
    for si in inp.callers[vi]! do
      let σ := inp.sites[si]!
      let some ui := unitIdx inp σ.at_.unit | continue
      unless inp.reached[ui]! do continue
      if S.any (· ≥ σ.args.size) then
        modify fun s => { s with missingArgs := s.missingArgs + 1 }
        continue
      let args := S.toArray.map (σ.args[·]!)
      let callee := (σ.args, v.params.extract 0 σ.args.size)
      let (sd, nf) ← siteDisjuncts inp ui σ.at_ args heteros ys (some callee)
      ds := ds ++ sd
      if nf > 0 then modify fun s => { s with framedInto := s.framedInto.insert key }
    let tb := inp.tailBound[vi]!
    mkReach inp ys (ds.map fun d => { d with bound := d.bound || tb })
  modify fun s => { s with memo := s.memo.insert key r, inProgress := s.inProgress.erase key }
  for c in r do
    for cn in c.cnames do
      unless cn.isAnonymous do
        modify fun s => { s with unitClauses := s.unitClauses.insert (vi, cn) }
  return r

/-- The disjuncts of a branch or call site at `at_` in unit `ui`: per path kind into `ui`, the
flags and `∃ z, reach X z ∧ closure`, and the number of path kinds dropped as framing. With
`args`, the closure also takes the arguments `args` for the callee's parameters `ps`, as
equalities with `ys`. With `callee` (all the site's arguments and the callee's parameters they
are for), the clause premises at the pre-state of each disjunct are carried to the callee. -/
partial def siteDisjuncts (inp : SharedIn) (ui : Nat) (at_ : SharedAt) (args : Array Expr)
    (heteros : Array Bool) (ys : Array Expr) (callee : Option (Array Expr × Array Expr) := none) :
    ShM (Array Disj × Nat) := do
  let u := inp.units[ui]!
  let xs := inp.xs
  let step := inp.level == .step
  let cl := if step then at_.clause else none
  let eqs (_ : Array Expr) : MetaM (Array Expr) := do
    let mut out := #[]
    for ((y, a), hetero) in (ys.zip args).zip heteros do
      out := out.push (← mkEqY y (← inferType y) (← zetaAll a) hetero)
    return out
  -- the premises `prem` (in this unit) carried to the callee's parameters
  let carry (prem : Option (Array Expr)) : ShM (Option (Array Expr)) := do
    let some (as, ps) := callee | return none
    let some prem := prem | return none
    let r ← withExtended at_.lctx (xs ++ ys) do
      let as ← as.mapM zetaAll
      let prem ← prem.mapM zetaAll
      return prem.mapM (carryTo as ps)
    if r.isNone then modify fun s => { s with carryLost := s.carryLost + 1 }
    return r
  let framed (prem : Array Expr) : MetaM Bool :=
    withExtended at_.lctx (xs ++ ys) do return (← frameWitness? prem).isSome
  let mut out := #[]
  let mut nFramed := 0
  if u.isRoot then
    let r? ← withExtended at_.lctx (xs ++ ys) do
      let mut conds := at_.conds
      let mut extra := at_.condProps
      if let some c := cl then
        if (← frameWitness? c.premS).isSome then return none
        conds := conds ++ c.prems
        extra := extra.push (mkNot (mkAndN c.premS))
      let (_, finish) ← closedPart inp ui at_.walking conds args extra eqs
      return some (← finish none)
    match r? with
    | some e =>
      let prem ← carry (cl.map (·.premS))
      let cns := match cl with | some c => #[c.name] | none => #[]
      out := out.push { clause := cl.isSome, bound := at_.bound, prem, e, cnames := cns }
    | none =>
      nFramed := nFramed + 1
      modify fun s => { s with framedSites := s.framedSites + 1 }
    return (out, nFramed)
  for useCl in (if cl.isSome then [false, true] else [false]) do
    let r? ← withExtended at_.lctx (xs ++ ys) do
      let mut conds := at_.conds
      let mut extra := at_.condProps
      if useCl then
        let c := cl.get!
        let premS ← premSOf inp c
        if (← frameWitness? premS).isSome then return none
        conds := conds ++ c.prems
        extra := extra.push (mkNot (mkAndN premS))
      some <$> closedPart inp ui at_.walking conds args extra eqs
    let some (ms, finish) := r? |
      nFramed := nFramed + 1
      modify fun s => { s with framedSites := s.framedSites + 1 }
      continue
    let S := ms.map fun m => (u.params.findIdx? (· == m)).get!
    let combos ← up inp ui S.toList
    -- path kinds dropped as framing at an enclosing site
    if (← get).framedInto.contains (ui, S.toList) then nFramed := nFramed + 1
    for c in combos do
      if cl.isSome && (useCl == c.clause) then continue
      -- an obligation opened above this unit: framing when its pre-state premises are here
      if let some prem := c.prem then
        if ← framed prem then
          nFramed := nFramed + 1
          modify fun s => { s with framedSites := s.framedSites + 1 }
          continue
      let e ← withExtended at_.lctx (xs ++ ys) (finish (some c.reach))
      let prem ← carry (if useCl then none else c.prem)
      let cns := if useCl then #[cl.get!.name] else c.cnames
      out := out.push { clause := c.clause || useCl, bound := c.bound || at_.bound, prem, e,
                        cnames := cns }
  return (out, nFramed)
end

/-- The parameters of each unit that are fixed at a level, by iteration from the roots. -/
def fixedParams (inp : SharedIn) : MetaM (Array (Array (Option Expr))) := do
  let mut fixed := inp.units.map fun u => Array.replicate u.params.size (none : Option Expr)
  let mut changed := true
  let mut rounds := 0
  while changed && rounds < inp.units.size + 1 do
    changed := false
    rounds := rounds + 1
    for (v, vi) in inp.units.zipIdx do
      if v.isRoot || !inp.reached[vi]! then continue
      let callers := (inp.callers[vi]!).filter fun si =>
        (unitIdx inp inp.sites[si]!.at_.unit).any (inp.reached[·]!)
      if callers.isEmpty then continue
      for i in [0:inp.arity[vi]!] do
        if fixed[vi]![i]!.isSome then continue
        let mut val : Option Expr := none
        let mut ok := true
        for si in callers do
          let σ := inp.sites[si]!
          let some ui := unitIdx inp σ.at_.unit | ok := false; break
          let some a := σ.args[i]? | ok := false; break
          let u := inp.units[ui]!
          let (from_, to) : Array Expr × Array Expr := if u.isRoot then (u.keep, inp.xs) else
            Id.run do
              let mut f := #[]
              let mut t := #[]
              for (p, j) in u.params.zipIdx do
                if let some x := fixed[ui]![j]! then f := f.push p; t := t.push x
              return (f, t)
          let a ← withExtended σ.at_.lctx inp.xs (zetaAll a)
          unless (collectFVars {} a).fvarIds.all fun f => from_.any (·.fvarId! == f) do
            ok := false; break
          let a := a.replaceFVars from_ to
          match val with
          | none => val := some a
          | some b => unless a == b do ok := false; break
        if ok then
          if let some x := val then
            fixed := fixed.modify vi (·.set! i (some x))
            changed := true
  return fixed

structure SharedOut where
  classes : Array SharedClass := #[]
  defs : Nat := 0
  cycles : Nat := 0
  missingArgs : Nat := 0
  rootCallee : Nat := 0
  framedSites : Nat := 0
  roles : Array (Nat × String) := #[]
  carryLost : Nat := 0
  /-- (unit declaration, clause): the unit is reached under the clause's obligation. -/
  unitClauses : Array (Name × Name) := #[]
  reached : Nat := 0
  fixed : Nat := 0
  deriving Inhabited

/-- The shared classes at `level` (pattern `pat`): one per case (lemma, split, branch) of the
branches `use` selects, with its `reach` definitions in namespace `ns`. -/
def sharedClasses (cfg : Config) (ns : Name) (level : Level) (pat : Expr)
    (branches : Array BranchRec) (sites : Array SiteRec) (units : Array UnitRec)
    (use : Nat → Bool) (defsFrom : Nat) : MetaM SharedOut :=
  lambdaTelescope pat fun xs _ => do
  let index : Std.HashMap WalkUnit Nat :=
    units.zipIdx.foldl (fun m (u, i) => if m.contains u.unit then m else m.insert u.unit i) {}
  let mut callers := units.map fun _ => (#[] : Array Nat)
  let mut rootCallee := 0
  for (σ, si) in sites.zipIdx do
    let some vi := index.get? σ.callee | continue
    if units[vi]!.isRoot then rootCallee := rootCallee + 1; continue
    callers := callers.modify vi (·.push si)
  -- units reached from the roots of this level
  let mut reached := units.map fun u => u.isRoot && u.level == level
  let mut todo := (List.range units.size).filter (reached[·]!) |>.toArray
  while !todo.isEmpty do
    let ui := todo.back!
    todo := todo.pop
    for σ in sites do
      unless σ.at_.unit == units[ui]!.unit do continue
      let some vi := index.get? σ.callee | continue
      if reached[vi]! || units[vi]!.isRoot then continue
      reached := reached.set! vi true
      todo := todo.push vi
  let arity := units.zipIdx.map fun (u, vi) =>
    (callers[vi]!).foldl (init := u.params.size) fun n si =>
      if (index.get? sites[si]!.at_.unit).any (reached[·]!) then min n sites[si]!.args.size else n
  let mut tailBound := #[]
  for (u, vi) in units.zipIdx do
    let mut tb := false
    for p in u.params.extract arity[vi]! u.params.size do
      if let some d := u.lctx.find? p.fvarId! then
        unless ← withLCtx u.lctx (← getLocalInstances) (isProp d.type) do tb := true
    tailBound := tailBound.push tb
  let inp0 : SharedIn := { cfg, level, xs, units, sites, reached, callers, arity, tailBound,
                           index, ns,
                           fixed := units.map fun u => Array.replicate u.params.size none }
  let fixed ← fixedParams inp0
  let inp := { inp0 with fixed }
  let go : ShM (Array SharedClass) := do
    let mut keys : Array (Name × String × String) := #[]
    let mut acc : Std.HashMap (Name × String × String) (Array Expr × Array Nat) := {}
    for (b, bi) in branches.zipIdx do
      unless use bi do continue
      let some at_ := b.shared | continue
      let some ui := index.get? at_.unit | continue
      unless reached[ui]! do continue
      let u := units[ui]!
      let mut ds := #[]
      if u.isRoot then
        unless u.level == level do continue
        let roleOk := if level == .step then b.role == "step-own" || b.role == "effect"
          else b.role == "state"
        modify fun s => { s with roles := s.roles.push (bi, b.role) }
        let some p := b.pred | continue
        if roleOk then ds := #[p.beta xs]
      else
        let (dis, nFramed) ← siteDisjuncts inp ui at_ #[] #[] #[]
        let mut kinds : Array String := #[]
        for d in dis do
          unless d.bound && !d.clause do
            for cn in d.cnames do
              unless cn.isAnonymous do
                modify fun s => { s with clauseOf := s.clauseOf.insert (bi, cn) }
          let k := if level != .step then "state" else if d.clause then "effect"
            else if d.bound then "unattributed" else "step-own"
          unless kinds.contains k do kinds := kinds.push k
          if k == "unattributed" then continue
          ds := ds.push d.e
        if nFramed > 0 then kinds := kinds.push "frame"
        -- the branch's role: the strongest kind of its path kinds
        let role := ["effect", "step-own", "state", "unattributed", "frame"].find? kinds.contains
          |>.getD "no-path"
        modify fun s => { s with roles := s.roles.push (bi, role) }
      if ds.isEmpty then continue
      let key := (b.decl, b.split, b.tag)
      unless keys.contains key do keys := keys.push key
      let (es, os) := acc.getD key (#[], #[])
      acc := acc.insert key (es ++ ds, os.push bi)
    let mut out := #[]
    for key in keys do
      let (es, os) := acc.getD key (#[], #[])
      let pred ← instantiateMVars (← mkLambdaFVars xs (mkOrN es))
      let co := (← get).clauseOf
      let clauses := os.foldl (init := #[]) fun acc bi =>
        let b := branches[bi]!
        let own := if b.clause == "-" then #[] else #[b.clause.toName]
        let below := co.toArray.filterMap fun (i, n) => if i == bi then some n else none
        (own ++ below).foldl (fun a n => if a.contains n then a else a.push n) acc
      out := out.push { level, decl := key.1, split := key.2.1, tag := key.2.2, pred,
                        occurrences := os, clauses := clauses.qsort (·.toString < ·.toString) }
    return out
  let (classes, st) ← go.run { defs := Array.replicate defsFrom .anonymous }
  return { classes, defs := st.defs.size - defsFrom, cycles := st.cycles,
           missingArgs := st.missingArgs, rootCallee, framedSites := st.framedSites, roles := st.roles, carryLost := st.carryLost,
           unitClauses := st.unitClauses.toArray.map fun (vi, n) => (units[vi]!.unit.decl, n),
           reached := (reached.filter id).size,
           fixed := fixed.foldl (fun n a => n + (a.filter Option.isSome).size) 0 }

end Relevance

end
