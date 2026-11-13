module

public meta import Lean
public import Relevance.Walk
public import Relevance.Shared

/-!
# Generating the step signature and state context from the recorded splits

Nothing here mentions a particular model. A model author writes, in a module that imports the
proof with `import all`:

    relevance_generate Ns
      (scope := Pkg.Proof) (package := [Pkg]) (roots := [Pkg.Proof.main₁, Pkg.Proof.main₂])
      (step := fun {n : Nat} (s : State n) (a : Action n) (t : State n) => step s a = some t)
      (state := fun {n : Nat} (s : State n) => Invariant s)

The two patterns are the only model-specific input. The binders of `step` are the step's
variables: by default its first explicit binder is the pre-state and its last the post-state.
The last explicit binder of `state` is the state; its other binders are parameters. Optional
arguments:

- `(pre := fun xs => e)` and `(post := fun xs => e)`, over the same binders as `step`: the
  pre-state and post-state as terms of the step's variables (for a step on histories, for
  example, `before :: rest` and `after :: before :: rest`);
- `(derive := [D₁, …])`: theorems whose last explicit hypothesis is something the state pattern
  follows from (an execution, a reachability proof); the conclusion of each must mention the
  state pattern's head.

Levels. The theorems in scope used by the roots (transitively) are classified by their header.
A theorem is step-level when one of its hypotheses matches the `step` pattern; state-level when one
matches the `state` pattern, none matches `step`, and exactly one binder has the state's type, or
when none matches either pattern and one of its hypotheses matches the last explicit hypothesis
of a theorem `D` of `derive` with exactly one of the matched variables able to play the state
(`D` and the theorems it uses excepted); other otherwise. The walked roots are the step-level and
state-level theorems not used by another step-level or state-level theorem, and the given roots
of level other (which do not inline the former). The theorems of `derive` are never inlined.

A clause (a field of the state pattern's structure) that is a definition rather than a `∀` is
unfolded at its head to read its instance binders and premises; conditions nested deeper (a
`match` with implications inside) are not premises, and stay case splits of the proof.

A split counts when at least two of its branches are live (not closed by contradiction) and no
live branch's script closes every other live branch (the replay test of `split_rel`).

Generated:

- `Ns.StepBranch`: one constructor per distinct predicate of a live `step-own` or `effect` branch
  of a counting split under a step-level root (see `Walk.lean` for the roles), with one predicate
  definition `Ns.step_<name>` per constructor and the set `Ns.sig`;
- `Ns.StateBranch`: one constructor per live branch of a counting split under a state-level root,
  with `Ns.state_<name>` and the set `Ns.ctx`;
- `Ns.creates`: the step makes some instance of some clause of the state pattern's structure new
  (its premises hold after the step and not before);
- `Ns.table`: a TSV of every recorded split branch, every unrecorded split and every clause;
- `Ns.branch_<i>`, `Ns.frame_<i>`, `Ns.cond_<i>` and `Ns.conv_<i>`: the branch, frame,
  split-condition and converse lemmas of `Walk.lean`;
- `Ns.telescope_<i>`, for every branch occurrence of a step or state class: the class predicate
  (`Ns.step_<name>` or `Ns.state_<name>`) is, by `Iff.refl`, the closure of the branch lemma's
  telescope (with the negated pre-state premises of an `effect` branch);
- `Ns.rederive_<root>`, for every walked root: the root's statement, proved by its rebuilt proof
  term, in which every branch is a call of its branch lemma.

The elaborator logs two summary lines: the tie-back (lemmas generated, of all, and what the
re-derived proofs still take from the marked-up proof: branch markers and theorems containing
markers), and the relevance line ending in the number of unrecorded splits.

`unfold_ns Ns` (a tactic) delta-expands every constant whose name starts with `Ns` in the goal.
-/

public meta section

open Lean Elab Command Meta

namespace Relevance

/-- The root fvars matched by the explicit-or-not binders of `pat`, if `hyp` matches its body. -/
def matchPat (pat hyp : Expr) : MetaM (Option (Array Expr)) := do
  let saved ← saveState
  let (ms, _, body) ← lambdaMetaTelescope pat
  let ok ← try withReducible (isDefEq body hyp) catch _ => pure false
  if ok then
    let vs ← ms.mapM instantiateMVars
    if vs.all (·.isFVar) && (vs.map (·.fvarId!)).toList.eraseDups.length == vs.size then
      return some vs
  saved.restore
  return none

/-- The state pattern's binders, as root fvars, when the fvar `sv` plays its state (its last
explicit binder): the other binders are found by unification and instance synthesis. -/
def stateBinders (statePat sv : Expr) : MetaM (Option (Array Expr)) := do
  let saved ← saveState
  let (ms, bis, _) ← lambdaMetaTelescope statePat
  let some k := (List.range ms.size).reverse.find? (bis[·]! == .default) | return none
  let ok ← try
      if ← withReducible (isDefEq (← inferType ms[k]!) (← inferType sv)) then
        isDefEq ms[k]! sv
      else pure false
    catch _ => pure false
  let mut out := none
  if ok then
    for (m, bi) in ms.zip bis do
      if bi.isInstImplicit && !(← m.mvarId!.isAssigned) then
        if let .some inst ← trySynthInstance (← inferType m) then
          discard <| isDefEq m inst
    let vs ← ms.mapM instantiateMVars
    if vs.all (·.isFVar) && (vs.map (·.fvarId!)).toList.eraseDups.length == vs.size then
      out := some vs
  saved.restore
  return out

/-- The binders of the state pattern when a hypothesis among `xs` is the last explicit
proposition hypothesis of a theorem of `cfg.derive` and exactly one of the root variables it is
matched with can play the state. -/
def derivedState (cfg : Config) (xs : Array Expr) : MetaM (Option (Array Expr)) := do
  for d in cfg.derive do
    let ci ← getConstInfo d
    for x in xs do
      let saved ← saveState
      let (ms, bis, _) ← forallMetaTelescope ci.type
      let mut hyp := none
      for i in (List.range ms.size).reverse do
        if bis[i]! == .default && (← isProp (← inferType ms[i]!)) then hyp := some i; break
      let some i := hyp | do saved.restore; continue
      let ok ← try withReducible (isDefEq (← inferType ms[i]!) (← inferType x)) catch _ => pure false
      let mut found := #[]
      if ok then
        let vs ← (ms.extract 0 i).mapM instantiateMVars
        for v in vs.toList.eraseDups do
          unless v.isFVar && xs.contains v do continue
          if let some keep ← stateBinders cfg.statePat v then found := found.push keep
      saved.restore
      if let #[keep] := found then return some keep
  return none

/-- The theorem's level and, for step and state levels, the root binders matched by the pattern.
With `derived`, a theorem with a hypothesis that a theorem of `cfg.derive` turns into the state
pattern is state-level too. -/
def classify (cfg : Config) (xs : Array Expr) (derived := true) : MetaM (Level × Array Expr) := do
  for x in xs do
    if let some vs ← matchPat cfg.stepPat (← inferType x) then return (.step, vs)
  for x in xs do
    if let some vs ← matchPat cfg.statePat (← inferType x) then
      let some sv := vs.back? | continue
      let sty ← inferType sv
      let mut count := 0
      for y in xs do
        if ← withReducible (isDefEq (← inferType y) sty) then count := count + 1
      if count == 1 then return (.state, vs)
  if derived then
    if let some vs ← derivedState cfg xs then return (.state, vs)
  return (.other, #[])

def theoremsUsed (cfg : Config) (c : Name) : CoreM (Array Name) := do
  let some ci := (← getEnv).find? c | return #[]
  let some v := ci.value? (allowOpaque := true) | return #[]
  let env ← getEnv
  return v.getUsedConstants.filter fun d =>
    cfg.scope.isPrefixOf ((privateToUserName? d).getD d) &&
      (env.find? d matches some (.thmInfo _))

structure Result where
  branches : Array BranchRec := #[]
  splits : Array SplitRec := #[]
  unrecorded : Array Unrecorded := #[]
  noValue : Array Name := #[]
  levels : Array (Name × Level × Bool) := #[]
  unusedHaves : Array (Name × String) := #[]
  ties : Array TieRec := #[]
  /-- Per walked step-level or state-level root: the re-derived theorem, or the error. -/
  rederived : Array (Name × Except String Name) := #[]
  /-- Shared walk: call sites and units (see `Config.shared`). -/
  sites : Array SiteRec := #[]
  units : Array UnitRec := #[]
  deriving Inhabited

/-- Walk every root; returns all records. -/
def analyse (cfg : Config) (roots : Array Name) : MetaM Result := do
  -- closure of the given roots over theorems in scope
  let mut seen : Array Name := #[]
  let mut todo := roots
  let mut uses : Std.HashMap Name (Array Name) := {}
  while !todo.isEmpty do
    let c := todo.back!
    todo := todo.pop
    if seen.contains c then continue
    seen := seen.push c
    let us ← theoremsUsed cfg c
    uses := uses.insert c us
    todo := todo ++ us
  -- the theorems that derive the state pattern, and those they use, are not state-level by it
  let mut derivation : Std.HashSet Name := {}
  todo := cfg.derive
  while !todo.isEmpty do
    let c := todo.back!
    todo := todo.pop
    if derivation.contains c then continue
    derivation := derivation.insert c
    todo := todo ++ (← theoremsUsed cfg c)
  let mut levels : Std.HashMap Name Level := {}
  for c in seen do
    let ci ← getConstInfo c
    let lvl ← forallTelescope ci.type fun xs _ =>
      return (← classify cfg xs (!derivation.contains c)).1
    levels := levels.insert c lvl
  let isTop (c : Name) : Bool := match levels.get? c with
    | some .other | none => false
    | _ => !seen.any fun d =>
        d != c && (levels.get? d matches some .step | some .state) && (uses.getD d #[]).contains c
  let tops := seen.filter isTop
  let others := roots.filter fun c => levels.get? c matches some .other
  let mut res : Result := {}
  for c in seen do
    res := { res with levels := res.levels.push (c, levels.getD c .other, tops.contains c) }
  let mut st : St := {}
  let mut rederived := #[]
  for root in tops ++ others do
    let ci ← getConstInfo root
    let some v := ci.value? (allowOpaque := true) | throwError "relevance: no proof for {root}"
    let pat := match levels.getD root .other with
      | .step => cfg.stepPat
      | _ => cfg.statePat
    let (st', rd) ← lambdaTelescope pat fun ps _ => forallTelescope ci.type fun xs _ => do
      let (lvl, keep) ← classify cfg xs (!derivation.contains root)
      let pre ← if lvl == .step then pure (← stepEnds cfg ps keep).1 else pure none
      let ctx : Ctx := { cfg, root, level := lvl, keep, pattern := ps, pre, rootBinders := xs,
                         stop := (if lvl == .other then tops else #[]) ++ cfg.derive,
                         unit := if cfg.shared then some { decl := root } else none }
      let st := { st with path := #[], calls := {}, inProgress := #[], stack := #[],
                          condStack := #[], region := false }
      let (e, st) ← ((walk (v.beta xs)).run ctx).run st
      let lctx ← getLCtx
      let ur : UnitRec := { unit := { decl := root }, walked := true, params := xs, lctx,
                            isRoot := true, level := lvl, keep, pattern := ps }
      let st := if cfg.shared then { st with units := st.units.push ur } else st
      -- the root proved again by the rebuilt term, in which branches are calls of their lemmas
      if lvl == .other || cfg.ns.isAnonymous || cfg.shared then return (st, none)
      let name := cfg.ns ++ Name.mkSimple s!"rederive_{root.components.getLast!}"
      let r ← try
          let value ← mkLambdaFVars xs e
          pure (← addTheorem name ci.type value)
        catch ex => pure (.error (← ex.toMessageData.toString))
      return (st, some (root, r.map fun () => name))
    st := st'
    if let some x := rd then rederived := rederived.push x
  -- shared walk: every lemma unit reached from a call site, once
  if cfg.shared then
    let ctx : Ctx := { cfg, root := .anonymous, level := .other, stop := cfg.derive }
    let mut i := 0
    while i < st.pending.size do
      let u := st.pending[i]!
      i := i + 1
      if st.units.any (·.unit == u) then continue
      let pre := (st.sites.find? (·.callee == u)).bind (·.preArg)
      let st0 := { st with path := #[], calls := {}, inProgress := #[], stack := #[],
                           condStack := #[], region := false }
      let (ur, st') ← ((walkUnit ctx u pre).run ctx).run st0
      st := { st' with units := st'.units.push ur }
  return { res with branches := st.branches, splits := st.splits,
                    unrecorded := st.unrecorded, noValue := st.noValue,
                    unusedHaves := st.unusedHaves, ties := st.ties, rederived,
                    sites := st.sites, units := st.units }

/-- Per split occurrence: whether it counts and why. -/
def counts (r : Result) (s : SplitRec) : Bool × String :=
  let bs := s.branches.map (r.branches[·]!)
  let live := bs.filter (!·.dead)
  let refut := if s.refutation then "inside a refutation; " else ""
  if live.size < 2 then (false, s!"{refut}{live.size} live branch(es)")
  else if s.coveredBy != "" then
    (false, s!"{refut}redundant: the script of {s.coveredBy} closes every live branch")
  else (true, s!"{refut}{live.size} live branches, no script closes the others")

def sanitize (s : String) : String :=
  String.ofList (s.toList.map fun c => if c.isAlphanum then c else '_')

def table (r : Result) (classOf : Array String := #[])
    (clauses : Array String := #[]) (extra : Array String := #[]) : MetaM String := do
  let mut rows := #["kind\troot\tlevel\tcall_path\tdecl\tsplit\tbranch\tlive\tcounts\twhy\tconditions\tpredicate\tclause\trole\tclass\ttie_back"]
  for (b, idx) in r.branches.zipIdx do
    let s := r.splits[b.splitId]!
    let (c, why) := counts r s
    let tie := (r.ties.filter (·.branch == idx)).toList.map fun t => match t.name with
      | some n => s!"{n.components.getLast!}{if t.fallback != "" then s!" (by the original term; rebuilt term {t.fallback})" else ""}{if t.context.isEmpty then "" else s!" ({if t.kind == "cond" then "split conditions" else "other hypotheses"}: {"; ".intercalate t.context.toList})"}"
      | none => s!"{t.kind} lemma not proved: {t.error}"
    rows := rows.push <| "\t".intercalate [
      "branch", b.root.toString, b.level.str, "/".intercalate b.path.toList, b.decl.toString,
      b.split, b.tag, if b.dead then "dead" else "live", toString c, why,
      " ∧ ".intercalate b.conds.toList, b.predStr, b.clause, b.role, (classOf[idx]?).getD "-",
      if tie.isEmpty then "-" else "; ".intercalate tie]
  for u in r.unrecorded do
    rows := rows.push <| "\t".intercalate [
      "unrecorded", u.root.toString, "-", "/".intercalate u.path.toList, u.decl.toString,
      u.head.toString, u.major, "-", "-",
      if u.internal then "internal to automation" else "protocol", u.cond, "-"]
  for (c, l, top) in r.levels do
    rows := rows.push s!"theorem\t{c}\t{l.str}\t-\t{c}\t-\t-\t-\t-\t{if top then "walked as root" else "inlined"}\t-\t-"
  for c in r.noValue do
    rows := rows.push s!"no_value\t{c}\t-\t-\t{c}\t-\t-\t-\t-\tproof not available\t-\t-"
  for (c, n) in r.unusedHaves do
    rows := rows.push s!"unused_have\t{c}\t-\t-\t{c}\t-\t{n}\t-\t-\thave never used: its branches are not walked\t-\t-"
  for c in clauses do
    rows := rows.push s!"clause\t{c}"
  rows := rows ++ extra
  return "\n".intercalate rows.toList ++ "\n"

def uniqueNames (bases : Array String) : Array String := Id.run do
  let mut names : Array String := #[]
  for base in bases do
    let mut nm := base
    let mut k := 2
    while names.contains nm do
      nm := s!"{base}_{k}"
      k := k + 1
    names := names.push nm
  return names

/-- Declare `ns.ty` with one constructor per item (name, doc, predicate), a predicate definition
per constructor and `ns.set`. -/
def generate (ns ty setName : Name) (prefix_ : String) (items : Array (String × String × Expr)) :
    CommandElabM Unit := do
  let tyName := ns ++ ty
  let ctorLines := items.map fun (n, d, _) => s!"  /-- {d} -/\n  | {n}"
  let src := s!"inductive {tyName} : Type where\n{"\n".intercalate ctorLines.toList}\n  deriving DecidableEq, Repr"
  let env ← getEnv
  match Parser.runParserCategory env `command src with
  | .error e => throwError "relevance_generate: {e}\n{src}"
  | .ok stx => elabCommand stx
  -- predicates
  let mut preds : Array Name := #[]
  for (n, _, p) in items do
    let declName := ns ++ Name.mkSimple s!"{prefix_}_{n}"
    let ty ← liftTermElabM do inferType p
    let lps := (collectLevelParams {} p).params.toList
    liftCoreM <| addDecl <| .defnDecl {
      name := declName, levelParams := lps, type := ty, value := p,
      hints := .abbrev, safety := .safe }
    preds := preds.push declName
  -- the set: fun xs b => casesOn b (pred₁ xs) …
  let some (_, _, p0) := items[0]? | return
  let v ← liftTermElabM do
    lambdaTelescope p0 fun xs _ => do
      withLocalDeclD `b (mkConst tyName) fun bv => do
        let motive ← mkLambdaFVars #[bv] (mkSort Level.zero)
        let minors ← preds.mapM fun pn => do
          let ci ← getConstInfo pn
          return mkAppN (mkConst pn (ci.levelParams.map mkLevelParam)) xs
        let body := mkAppN (mkConst (tyName ++ `casesOn) [Level.one]) (#[motive, bv] ++ minors)
        let v ← mkLambdaFVars (xs.push bv) body
        check v
        return v
  let tyv ← liftTermElabM do inferType v
  let lps := (collectLevelParams {} v).params.toList
  liftCoreM <| addDecl <| .defnDecl {
    name := ns ++ setName, levelParams := lps, type := tyv, value := v,
    hints := .abbrev, safety := .safe }

/-- Whether the proof of `d` records split `split` (a `splitMark` with that name). -/
def recordsSplit (env : Environment) (d : Name) (split : String) : Bool :=
  match env.find? d >>= (·.value? (allowOpaque := true)) with
  | none => false
  | some v => (v.find? fun e => e.isAppOf ``splitMark && e.getAppNumArgs ≥ 2 &&
      e.getArg! 1 == mkStrLit split).isSome

/-- The theorem whose proof records the split of a per-path occurrence: its innermost declaration
if that records it, else the nearest theorem on its call path that does. -/
def splitOwner (env : Environment) (b : BranchRec) : Name := Id.run do
  if recordsSplit env b.decl b.split then return b.decl
  for label in (b.path.toList.reverse ++ [b.root.toString]) do
    let n := (label.splitOn "#").head!.toName
    if recordsSplit env n b.split then return n
  return b.decl

/-- Elaborate `stx` (a proof term, typically `by tac`) at type `ty`; the proof, or why not. -/
def proveWith (stx : Syntax) (ty : Expr) : TermElabM (Except String Expr) := do
  let saved ← saveState
  let errors ← errorCount
  let attempt : TermElabM (Except String Expr) := do
    let e ← Term.withoutErrToSorry <| Term.elabTermEnsuringType stx ty
    Term.synthesizeSyntheticMVarsNoPostponing
    let e ← instantiateMVars e
    if e.hasMVar || e.hasSyntheticSorry || e.hasSorry || (← errorCount) != errors then
      return .error "not closed"
    return .ok e
  let fail (ex : Exception) : TermElabM (Except String Expr) := do
    return .error ((← ex.toMessageData.toString).take 200).toString
  let r ← tryCatchRuntimeEx attempt fail
  if r matches .error _ then saved.restore
  return r

def branchDoc (b : BranchRec) : String :=
  let cl := if b.clause == "-" then "" else s!"clause {b.clause}, "
  s!"{b.root} / {"/".intercalate b.path.toList} : {cl}split {b.split}, branch {b.tag}"

/-- `creates`: over the step pattern's binders, the disjunction over the clauses of the
state pattern's structure of `∃ x, P(post, x) ∧ ¬ P(pre, x)`. Also returns, per clause, its name
and its numbers of data binders and premises (a clause without premises has no new instances). -/
def mkCreates (cfg : Config) : MetaM (Option Expr × Array (String × Nat × Nat)) := do
  let some ctor := cfg.stateCtor | return (none, #[])
  lambdaTelescope cfg.stepPat fun ps _ => do
    let (some pre, some post) ← stepEnds cfg ps ps | return (none, #[])
    let tyT ← stateAt cfg.statePat post
    let tyS ← stateAt cfg.statePat pre
    let cv ← getConstInfoCtor ctor
    let ty := cv.type.instantiateLevelParams cv.levelParams tyT.getAppFn.constLevels!
    let mut tT ← instantiateForall ty tyT.getAppArgs
    let mut tS ← instantiateForall ty tyS.getAppArgs
    let names := (getStructureInfo? (← getEnv) cv.induct).map (·.fieldNames) |>.getD #[]
    let mut disj := #[]
    let mut shapes := #[]
    for k in [0:cv.numFields] do
      let fT := tT.bindingDomain!
      let fS := tS.bindingDomain!
      let name := (names[k]?.map (·.toString)).getD s!"field{k}"
      let (nd, npr) ← clauseShape fT
      shapes := shapes.push (name, nd, npr)
      if npr > 0 then
        let d ← forallBoundedTelescope fT (some (nd + npr)) fun ys _ => do
          let xs := ys.extract 0 nd
          let prems := ys.extract nd ys.size
          let premT ← prems.mapM inferType
          let premS ← premisesAt fS xs prems
          let mut body := mkAnd (mkAndN premT) (mkNot (mkAndN premS))
          for x in xs.reverse do
            let xty ← inferType x
            body := mkApp2 (mkConst ``Exists [← getLevel xty]) xty (← mkLambdaFVars #[x] body)
          return body
        disj := disj.push d
      if tT.bindingBody!.hasLooseBVars || tS.bindingBody!.hasLooseBVars then
        throwError "relevance: clause {name} is used by a later clause's statement"
      tT := tT.bindingBody!
      tS := tS.bindingBody!
    let v ← mkLambdaFVars ps (mkOrN disj)
    check v
    return (some v, shapes)

/-- `∀ pattern, cls pattern ↔ ∃ closed, hyps ∧ extra`, where the right side is rebuilt from the
binders of the branch lemma of `tie` (its closed variables and hypotheses), proved by `Iff.rfl`:
the class statement is the closure of that lemma's telescope. -/
def telescopeLemma (name cls : Name) (tie : TieRec) : MetaM (Except String Unit) := do
  let some lemma := tie.name | return .error "no branch lemma"
  let ci ← getConstInfo cls
  let some pv := ci.value? | return .error "class has no definition"
  let lci ← getConstInfo lemma
  let lhsC := mkConst cls (ci.levelParams.map mkLevelParam)
  let n := tie.nRoots + tie.nRest + tie.nHyps
  lambdaTelescope pv fun ps _ => do
    let rhs? ← forallBoundedTelescope lci.type (some n) fun bs _ => do
      if bs.size != n then return none
      let closed := tie.closedPos.map (bs[·]!)
      let hyps ← (bs.extract (tie.nRoots + tie.nRest) n).mapM inferType
      let extra ← tie.extra.mapM (instantiateLambda · (bs.extract 0 (tie.nRoots + tie.nRest)))
      let body ← closeBody closed (hyps ++ extra)
      let lam ← mkLambdaFVars (tie.keptPos.map (bs[·]!)) body
      let rhs := lam.beta ps
      if rhs.hasAnyFVar (fun f => bs.any (·.fvarId! == f)) then return none
      return some rhs
    let some rhs := rhs? | return .error "the closure mentions a root binder that is not kept"
    let lhs := mkAppN lhsC ps
    let type ← mkForallFVars ps (mkIff lhs rhs)
    let value ← mkLambdaFVars ps (mkApp (mkConst ``Iff.refl) lhs)
    addTheorem name type value

/-- The theorems reached from `roots` through generated lemmas (names under `ns`). -/
def reachedLemmas (ns : Name) (roots : Array Name) : CoreM (Std.HashSet Name) := do
  let mut seen : Std.HashSet Name := {}
  let mut todo := roots
  while !todo.isEmpty do
    let c := todo.back!
    todo := todo.pop
    if seen.contains c then continue
    seen := seen.insert c
    let some ci := (← getEnv).find? c | continue
    let some v := ci.value? (allowOpaque := true) | continue
    todo := todo ++ v.getUsedConstants.filter (ns.isPrefixOf ·)
  return seen

/-- Number of distinct recorded-branch markers in `e`. -/
def countMarks (e : Expr) : Nat := Id.run do
  let mut n := 0
  let mut seen : Std.HashSet Expr := {}
  let mut todo := #[e]
  while !todo.isEmpty do
    let x := todo.back!
    todo := todo.pop
    if seen.contains x then continue
    seen := seen.insert x
    if x.isAppOf ``branchMark then n := n + 1
    match x with
    | .app f a => todo := todo.push f |>.push a
    | .lam _ t b _ | .forallE _ t b _ => todo := todo.push t |>.push b
    | .letE _ t v b _ => todo := todo.push t |>.push v |>.push b
    | .mdata _ b | .proj _ _ b => todo := todo.push b
    | _ => pure ()
  return n

syntax relArg := " (" ident " := " term ")"
syntax (name := relevanceGenerate) "relevance_generate " ident (ppLine relArg)* : command

@[command_elab relevanceGenerate] def elabRelevanceGenerate : CommandElab := fun stx => do
  let ns := stx[1].getId
  let mut args : Std.HashMap String Syntax := {}
  for a in stx[2].getArgs do
    args := args.insert a[1].getId.toString a[3]
  let get (k : String) : CommandElabM Syntax := do
    let some v := args.get? k | throwError "relevance_generate: missing ({k} := ...)"
    return v
  let idents (s : Syntax) : Array Name :=
    (s.getArgs.foldl (init := #[]) fun acc a => acc ++ a.getSepArgs.filterMap fun x =>
      if x.isIdent then some x.getId else none)
  let scope := (← get "scope").getId
  let package := idents (← get "package")
  let roots ← (idents (← get "roots")).mapM fun n => liftCoreM <| realizeGlobalConstNoOverload (mkIdent n)
  let elabPat (s : Syntax) : CommandElabM Expr := liftTermElabM do
    let e ← Term.elabTerm s none
    Term.synthesizeSyntheticMVarsNoPostponing
    let e ← instantiateMVars e
    if e.hasMVar then throwError "relevance_generate: pattern has metavariables"
    return e
  let stepPat ← elabPat (← get "step")
  let statePat ← elabPat (← get "state")
  let stateCtor ← liftTermElabM <| lambdaTelescope statePat fun _ body => do
    let some c := body.getAppFn.constName? | return none
    let env ← getEnv
    return if isStructure env c then some (getStructureCtor env c).name else none
  -- the pre-state and post-state as terms over the step pattern's binders
  let endOf (k : String) : CommandElabM (Option Expr) := do
    let some s := args.get? k | return none
    let f ← elabPat s
    liftTermElabM <| lambdaTelescope stepPat fun ps _ => do
      unless (← lambdaTelescope f fun qs _ => pure qs.size) == ps.size do
        throwError "relevance_generate: ({k} := ...) must bind the step pattern's binders"
      let e := f.beta ps
      check e
      discard <| stateAt statePat e
    return some f
  let preOf ← endOf "pre"
  let postOf ← endOf "post"
  -- theorems that turn a hypothesis into the state pattern
  let derive ← match args.get? "derive" with
    | none => pure #[]
    | some s => (idents s).mapM fun n => liftCoreM <| realizeGlobalConstNoOverload (mkIdent n)
  for d in derive do
    let head := ← liftTermElabM <| lambdaTelescope statePat fun _ body => pure body.getAppFn
    let ok ← liftTermElabM <| forallTelescopeReducing (← getConstInfo d).type fun _ c =>
      return (c.find? (·.getAppFn == head)).isSome
    unless ok do
      throwError "relevance_generate: the conclusion of {d} does not mention the state pattern"
  let shared := match args.get? "shared" with
    | some s => s.isIdent && s.getId == `true
    | none => false
  let cfg : Config := { scope, package, stepPat, statePat, stateCtor, ns, preOf, postOf, derive,
                        shared }
  let r ← liftTermElabM <| analyse cfg roots
  if shared then
    let counted (b : BranchRec) := !b.dead && (counts r r.splits[b.splitId]!).1
    let walked := r.units.filter (·.walked)
    let rootUnits := r.units.filter (·.isRoot)
    let use (bi : Nat) := counted r.branches[bi]!
    let st ← liftTermElabM <| sharedClasses cfg ns .step stepPat r.branches r.sites r.units use 0
    let sa ← liftTermElabM <| sharedClasses cfg ns .state statePat r.branches r.sites r.units use st.defs
    let items (cs : Array SharedClass) : Array (String × String × Expr) :=
      let names := uniqueNames (cs.map fun c => sanitize s!"{c.decl.components.getLast!}_{c.split}_{c.tag}")
      (names.zip cs).map fun (n, c) =>
        (n, s!"{c.decl} : split {c.split}, branch {c.tag} ({c.occurrences.size} occurrence(s))", c.pred)
    let stepItems := items st.classes
    let stateItems := items sa.classes
    unless stepItems.isEmpty do generate ns `StepBranch `sig "step" stepItems
    unless stateItems.isEmpty do generate ns `StateBranch `ctx "state" stateItems
    -- the roles of the branches, per level they are reached at
    let mut roleOf : Array (Array String) := Array.replicate r.branches.size #[]
    for (bi, role) in st.roles ++ sa.roles do
      unless roleOf[bi]!.contains role do roleOf := roleOf.modify bi (·.push role)
    let rs := r.branches.zipIdx.map fun (b, bi) =>
      if roleOf[bi]!.isEmpty then b else { b with role := "/".intercalate roleOf[bi]!.toList }
    let mut classOf : Array (Array String) := Array.replicate r.branches.size #[]
    for (cs, its, pre) in [(st.classes, stepItems, "step_"), (sa.classes, stateItems, "state_")] do
      for (c, (n, _)) in cs.zip its do
        for bi in c.occurrences do classOf := classOf.modify bi (·.push (pre ++ n))
    -- per root given: the theorems in scope its proof uses, transitively
    let mut closures : Array (Name × Std.HashSet Name) := #[]
    for root in roots do
      let mut seen : Std.HashSet Name := {}
      let mut todo := #[root]
      while !todo.isEmpty do
        let c := todo.back!
        todo := todo.pop
        if seen.contains c then continue
        seen := seen.insert c
        todo := todo ++ (← liftCoreM <| theoremsUsed cfg c)
      closures := closures.push (root, seen)
    let rootsOf (d : Name) : String :=
      let hits := closures.filter (·.2.contains d)
      if hits.isEmpty then "-" else ",".intercalate (hits.toList.map (·.1.toString))
    -- clause-level: the clauses (fields of the state pattern's structure) each root reads outside
    -- step-level theorems, closed under the clauses read by the units under each clause's
    -- obligation
    let env ← getEnv
    let fields : Array Name := match cfg.stateCtor.bind fun c => (env.find? c) with
      | some (.ctorInfo ci) => (getStructureFields env ci.induct).map (ci.induct ++ ·)
      | _ => #[]
    let structName := fields[0]?.map (·.getPrefix)
    let readsOf (d : Name) : CoreM (Array Name) := do
      let some ci := (← getEnv).find? d | return #[]
      let some v := ci.value? (allowOpaque := true) | return #[]
      let used := v.getUsedConstants
      if structName.any fun sn => used.contains (sn ++ `casesOn) || used.contains (sn ++ `rec) then
        return fields
      return fields.filter used.contains
    let stepLevel : Std.HashSet Name :=
      r.levels.foldl (fun h (c, l, _) => if l == .step then h.insert c else h) {}
    let stepTops : Std.HashSet Name :=
      r.levels.foldl (fun h (c, l, top) => if l == .step && top then h.insert c else h) {}
    -- the clauses read by the theorems in scope that `starts` use, transitively, outside
    -- the theorems in `skip`
    let readClosure (skip : Std.HashSet Name) (starts : Array Name) : CoreM (Array Name) := do
      let mut seen : Std.HashSet Name := {}
      let mut todo := starts
      let mut use : Array Name := #[]
      while !todo.isEmpty do
        let c := todo.back!
        todo := todo.pop
        if seen.contains c || skip.contains c then continue
        seen := seen.insert c
        for f in ← readsOf c do unless use.contains f do use := use.push f
        todo := todo ++ (← theoremsUsed cfg c)
      return use
    let mut under : Std.HashMap Name (Array Name) := {}
    for (u, c) in st.unitClauses do
      under := under.insert c ((under.getD c #[]).push u)
    -- obligations opened in a unit: lemmas count as under them; at a root, the arguments of
    -- the call sites under them are read
    let mut rootReads : Std.HashMap Name (Array Name) := {}
    for σ in r.sites do
      let some cl := σ.at_.clause | continue
      let isRoot := r.units.any fun u => u.isRoot && u.unit == σ.at_.unit
      if isRoot then
        let used ← liftTermElabM <| withLCtx σ.at_.lctx {} do
          let mut used : Array Name := #[]
          for a in σ.args do
            for c in (← zetaAll (← instantiateMVars a)).getUsedConstants do
              unless used.contains c do used := used.push c
          return used
        let fs := fields.filter used.contains
        rootReads := rootReads.insert cl.name ((rootReads.getD cl.name #[]) ++ fs)
        -- theorems called at the site
        let ts := used.filter fun c => cfg.scope.isPrefixOf ((privateToUserName? c).getD c)
        under := under.insert cl.name ((under.getD cl.name #[]) ++ ts)
      else
        under := under.insert cl.name ((under.getD cl.name #[]).push σ.at_.unit.decl)
    let mut reads : Std.HashMap Name (Array Name) := {}
    for (c, us) in under.toList do
      reads := reads.insert c ((← liftCoreM <| readClosure stepTops us) ++ rootReads.getD c #[])
    let mut clauseClosures : Array (Name × Array Name) := #[]
    for root in roots do
      let use ← liftCoreM <| readClosure stepLevel #[root]
      let mut cl := use
      let mut i := 0
      while i < cl.size do
        for f in reads.getD (cl[i]!.componentsRev.head!) #[] do
          unless cl.contains f do cl := cl.push f
        i := i + 1
      clauseClosures := clauseClosures.push (root, cl.map (·.componentsRev.head!))
    let clauseTag (c : SharedClass) : String :=
      if c.clauses.isEmpty then "-" else
      let hits := clauseClosures.filter fun (_, cl) => c.clauses.any cl.contains
      if hits.isEmpty then "none" else ",".intercalate (hits.toList.map (·.1.toString))
    let mut classRows := #[]
    let mut tags : Array (String × Nat) := #[]
    for (cs, its, lvl) in [(st.classes, stepItems, "step"), (sa.classes, stateItems, "state")] do
      for (c, (n, _)) in cs.zip its do
        let roles := c.occurrences.foldl (fun acc bi =>
          (roleOf[bi]!).foldl (fun a x => if a.contains x then a else a.push x) acc) #[]
        let tag := rootsOf c.decl
        tags := match tags.findIdx? (·.1 == s!"{lvl} {tag}") with
          | some k => tags.modify k fun (t, m) => (t, m + 1)
          | none => tags.push (s!"{lvl} {tag}", 1)
        classRows := classRows.push <| "\t".intercalate [
          "class", s!"{lvl}_{n}", lvl, c.decl.toString, c.split, c.tag,
          toString c.occurrences.size, "/".intercalate roles.toList, tag,
          if c.clauses.isEmpty then "-" else ",".intercalate (c.clauses.toList.map toString),
          clauseTag c]
        let ct := s!"{lvl} by clause {clauseTag c}"
        tags := match tags.findIdx? (·.1 == ct) with
          | some k => tags.modify k fun (t, m) => (t, m + 1)
          | none => tags.push (ct, 1)
    let (_, shapes) ← liftTermElabM <| mkCreates cfg
    let clauseRows := shapes.map fun (n, nd, np) =>
      s!"{n}\t{nd} data binder(s)\t{np} premise(s){if np == 0 then "\tno premises: no new instances" else ""}"
    let text ← liftTermElabM <| table { r with branches := rs }
      (classOf.map fun cs => if cs.isEmpty then "-" else ",".intercalate cs.toList) clauseRows
      classRows
    liftCoreM <| addAndCompile <| .defnDecl {
      name := ns ++ `table, levelParams := [], type := mkConst ``String, value := mkStrLit text,
      hints := .abbrev, safety := .safe }
    let roleCount (lvl : String) (rs : Array (Nat × String)) : String := Id.run do
      let mut parts : Array String := #[]
      for k in ["effect", "step-own", "state", "unattributed", "frame", "no-path"] do
        let n := (rs.filter (·.2 == k)).size
        if n != 0 then parts := parts.push s!"{n} {k}"
      return s!"{lvl}: {", ".intercalate parts.toList}"
    let deadAt := r.branches.filter fun b => b.dead && b.shared.isSome
    -- distinct step predicates (as the per-path classes are counted)
    let mut distinct : Array Expr := #[]
    for c in st.classes do
      let mut found := false
      for q in distinct do
        if ← liftTermElabM (do try withReducible (isDefEq c.pred q) catch _ => pure false) then
          found := true; break
      unless found do distinct := distinct.push c.pred
    logInfo m!"relevance (shared): {r.units.size} units ({walked.size} walked, \
      {r.units.size - walked.size} without a proof to walk), {r.sites.size} call sites; \
      {r.splits.size} split occurrences, {r.branches.size} branch occurrences \
      ({(r.branches.filter counted).size} counted); {r.unrecorded.size} unrecorded splits \
      ({(r.unrecorded.filter (!·.internal)).size} protocol); {rootUnits.size} roots; \
      {st.classes.size} step classes ({distinct.size} distinct), {sa.classes.size} state classes; \
      {st.defs + sa.defs} reach definitions; {st.reached}/{sa.reached} units reached (step/state), \
      {st.fixed}/{sa.fixed} fixed parameters, {st.framedSites + sa.framedSites} framed sites \
      ({st.carryLost} path kinds whose clause premises could not be carried to a callee), \
      {st.cycles + sa.cycles} recursive calls cut, {st.missingArgs + sa.missingArgs} sites with \
      missing arguments, {st.rootCallee} calls of roots; counted branch occurrences by role \
      ({roleCount "step" st.roles}; {roleCount "state" sa.roles}); {deadAt.size} dead branch \
      occurrences; classes by the roots whose proofs use their lemma: \
      {", ".intercalate (tags.toList.map fun (t, m) => s!"{m} {t}")}; clauses read by each \
      root, closed under the clauses read under each clause's obligation: \
      {"; ".intercalate (clauseClosures.toList.map fun (n, cl) =>
        s!"{n}: {cl.size} [{", ".intercalate (cl.toList.map toString)}]")}; clauses: \
      {", ".intercalate (shapes.toList.map fun (n, nd, np) => s!"{n} ({nd} binders, {np} premises)")}"
    -- per-path comparison: each shared class against the per-path occurrences of its case
    let some tac := args.get? "compare" | return
    let pp ← liftTermElabM <| analyse { cfg with shared := false } roots
    let env ← getEnv
    let pcounted (b : BranchRec) := !b.dead && (counts pp pp.splits[b.splitId]!).1
    let mut proved : Nat := 0
    let mut failed : Array String := #[]
    let mut onlyPP : Array String := #[]
    let mut k : Nat := 0
    for (lvl, pat, cs) in [(Level.step, stepPat, st.classes), (Level.state, statePat, sa.classes)] do
      let roleOk (b : BranchRec) := if lvl == .step then b.role == "step-own" || b.role == "effect"
        else b.role == "state"
      let occs := pp.branches.filter fun b =>
        b.level == lvl && pcounted b && roleOk b && b.pred.isSome
      let keyOf (b : BranchRec) := (splitOwner env b, b.split, b.tag)
      for b in occs do
        unless cs.any (fun c => (c.decl, c.split, c.tag) == keyOf b) do
          onlyPP := onlyPP.push (branchDoc b)
      for c in cs do
        let mine := occs.filter fun b => keyOf b == (c.decl, c.split, c.tag)
        let tac := tac
        let ty ← liftTermElabM <| lambdaTelescope pat fun xs _ => do
          let rhs := mkOrN (mine.map fun b => b.pred.get!.beta xs)
          mkForallFVars xs (mkIff (c.pred.beta xs) rhs)
        let name := ns ++ Name.mkSimple s!"equiv_{k}"
        k := k + 1
        match ← liftTermElabM <| proveWith tac ty with
        | .ok prf =>
          liftCoreM <| addDecl <| .thmDecl {
            name, levelParams := (collectLevelParams {} ty).params.toList, type := ty, value := prf }
          proved := proved + 1
        | .error e =>
          -- which inclusion holds
          let dir (fwd : Bool) : TermElabM Bool := lambdaTelescope pat fun xs _ => do
            let l := c.pred.beta xs
            let r := mkOrN (mine.map fun b => b.pred.get!.beta xs)
            let ty ← mkForallFVars xs (if fwd then mkForall `h .default l r else mkForall `h .default r l)
            return (← proveWith tac ty) matches .ok _
          let sp ← liftTermElabM <| dir true
          let ps ← liftTermElabM <| dir false
          let e := s!"{if sp then "only shared -> per-path proved" else if ps then "only per-path -> shared proved" else "neither inclusion proved"}; {(e.splitOn "\n").head!}"
          let e := if sp && ps then "both inclusions proved separately" else e
          liftCoreM <| addDecl <| .defnDecl {
            name := name ++ `stmt, levelParams := (collectLevelParams {} ty).params.toList,
            type := mkSort .zero, value := ty, hints := .abbrev, safety := .safe }
          failed := failed.push s!"{name}.stmt: {c.decl} {c.split} {c.tag} ({mine.size} per-path): {e}"
    let ppClasses := (pp.branches.filter fun b => b.level == .step && pcounted b &&
      (b.role == "step-own" || b.role == "effect") && b.pred.isSome).size
    logInfo m!"relevance (compare): {proved}/{k} shared classes proved equivalent to the \
      disjunction of their per-path occurrences ({ppClasses} per-path step occurrences); \
      {onlyPP.size} per-path occurrences with no shared class\
      {String.join (failed.toList.map (s!"\n  not proved: " ++ ·))}\
      {String.join (onlyPP.toList.map (s!"\n  per-path only: " ++ ·))}"
    return
  let counted (b : BranchRec) := !b.dead && (counts r r.splits[b.splitId]!).1
  let live (lvl : Level) := r.branches.filter fun b => b.level == lvl && counted b
  let stateItems (bs : Array BranchRec) : Array (String × String × Expr) :=
    let names := uniqueNames (bs.map fun b => sanitize s!"{b.decl.components.getLast!}_{b.split}_{b.tag}")
    (names.zip bs).map fun (n, b) => (n, branchDoc b, b.pred.getD (mkConst ``True))
  for b in (live .step) ++ (live .state) do
    if b.pred.isNone && (b.role == "step-own" || b.role == "effect" || b.role == "state") then
      throwError "relevance_generate: branch {branchDoc b} has no predicate"
  let prot := r.unrecorded.filter (!·.internal)
  -- one step class per distinct predicate
  let mut reps : Array (Expr × Array Nat) := #[]
  let mut classIdx : Array (Option Nat) := Array.replicate r.branches.size none
  for (b, idx) in r.branches.zipIdx do
    unless b.level == .step && counted b && (b.role == "step-own" || b.role == "effect") do continue
    let some p := b.pred | continue
    let mut found := none
    for (q, k) in reps.zipIdx do
      if p == q.1 then found := some k; break
      let eq : Bool ← liftTermElabM (do try withReducible (isDefEq p q.1) catch _ => pure false)
      if eq then
        found := some k; break
    match found with
    | some k =>
      classIdx := classIdx.set! idx (some k)
      reps := reps.modify k fun (q, os) => (q, os.push idx)
    | none =>
      classIdx := classIdx.set! idx (some reps.size)
      reps := reps.push (p, #[idx])
  let bases := reps.map fun (_, os) =>
    let b := r.branches[os[0]!]!
    let cl := if b.clause == "-" then "" else s!"{b.clause}_"
    sanitize s!"{cl}{b.decl.components.getLast!}_{b.split}_{b.tag}"
  let names := uniqueNames bases
  let items := (names.zip reps).map fun (n, (p, os)) =>
    let occ := os.map fun i => branchDoc r.branches[i]!
    (n, s!"{os.size} occurrence(s): " ++ "; ".intercalate occ.toList, p)
  generate ns `StepBranch `sig "step" items
  generate ns `StateBranch `ctx "state" (stateItems (live .state))
  let (creates, shapes) ← liftTermElabM <| mkCreates cfg
  if let some v := creates then
    let tyv ← liftTermElabM do inferType v
    liftCoreM <| addDecl <| .defnDecl {
      name := ns ++ `creates, levelParams := (collectLevelParams {} v).params.toList, type := tyv,
      value := v, hints := .abbrev, safety := .safe }
  let classOf := classIdx.map fun o => (o.map (names[·]!)).getD "-"
  let clauseRows := shapes.map fun (n, nd, np) =>
    s!"{n}\t{nd} data binder(s)\t{np} premise(s){if np == 0 then "\tno premises: no new instances" else ""}"
  let text ← liftTermElabM <| table r classOf clauseRows
  liftCoreM <| addAndCompile <| .defnDecl {
    name := ns ++ `table, levelParams := [], type := mkConst ``String, value := mkStrLit text,
    hints := .abbrev, safety := .safe }
  -- tie-back: the class statement of each occurrence is the closure of its branch lemma
  let stateNames := uniqueNames ((live .state).map fun b =>
    sanitize s!"{b.decl.components.getLast!}_{b.split}_{b.tag}")
  let mut clsOf : Array (Nat × Name) := #[]
  for idx in [0:r.branches.size] do
    if let some k := classIdx[idx]! then
      clsOf := clsOf.push (idx, ns ++ Name.mkSimple s!"step_{names[k]!}")
  let stateIdx := (r.branches.zipIdx.filter fun (b, _) => b.level == .state && counted b).map (·.2)
  for (idx, n) in stateIdx.zip stateNames do
    clsOf := clsOf.push (idx, ns ++ Name.mkSimple s!"state_{n}")
  let mut l1ok : Nat := 0
  let mut l1err : Array String := #[]
  for (idx, cls) in clsOf do
    let b := r.branches[idx]!
    let some k := b.tie | l1err := l1err.push s!"{branchDoc b}: no branch lemma"; continue
    match ← liftTermElabM <| telescopeLemma (ns ++ Name.mkSimple s!"telescope_{idx}") cls r.ties[k]! with
    | .ok () => l1ok := l1ok + 1
    | .error e => l1err := l1err.push s!"{branchDoc b}: {e}"
  for e in l1err do logWarning m!"relevance: statement = telescope not proved: {e}"
  let walked := r.branches.filter (·.level != .other)
  let l2 := r.ties.filter (·.kind == "branch")
  let l2ok := l2.filter (·.name.isSome)
  let l4 := r.ties.filter (·.kind == "frame")
  let l4ok := l4.filter (·.name.isSome)
  let lc := r.ties.filter (·.kind == "cond")
  let lv := r.ties.filter (·.kind == "conv")
  let withContext := lv.filter (!·.context.isEmpty)
  let noOwn := lc.filter fun t => t.name.isSome && t.context.isEmpty
  let ctxCount (what : String) : Nat :=
    lv.foldl (fun n t => n + (t.context.filter (·.startsWith s!"[{what}]")).size) 0
  let stmtDiff := r.ties.filter (·.kind == "statement")
  for t in r.ties do
    if t.name.isNone then
      logWarning m!"relevance: {t.kind} lemma of {branchDoc r.branches[t.branch]!} not proved: {t.error}"
  let roots := r.rederived.filterMap fun (_, x) => match x with | .ok n => some n | _ => none
  for (root, x) in r.rederived do
    if let .error e := x then logWarning m!"relevance: {root} not re-derived: {e}"
  let reached ← liftCoreM <| reachedLemmas ns roots
  let placed := l2ok.filter fun t => reached.contains t.name.get!
  -- what the re-derived proofs still take from the marked-up proof: branch markers left in
  -- them, and the theorems with markers that they use
  let valueOf (n : Name) : CoreM (Option Expr) := do
    return (← getEnv).find? n >>= (·.value? (allowOpaque := true))
  let isBranchLemma (n : Name) : Bool :=
    n.getPrefix == ns && (n.getString!.startsWith "branch_")
  let mut residual : Nat := 0
  let mut nested : Nat := 0
  let mut marked : Std.HashMap Name Bool := {}
  let mut usesMarked : Array (Name × Array Name) := #[]
  for n in roots ++ reached.toArray.qsort (·.toString < ·.toString) do
    if !roots.contains n && !isBranchLemma n then continue
    let some v ← liftCoreM (valueOf n) | continue
    residual := residual + countMarks v
    let used := v.getUsedConstants
    if isBranchLemma n && used.any fun c => c != n && isBranchLemma c then nested := nested + 1
    let mut hits := #[]
    for c in used do
      if ns.isPrefixOf c || !scope.isPrefixOf c then continue
      let m ← match marked.get? c with
        | some m => pure m
        | none => do
          let m := ((← liftCoreM (valueOf c)).map countMarks).getD 0 > 0
          marked := marked.insert c m
          pure m
      if m then hits := hits.push c
    unless hits.isEmpty || roots.contains n do usesMarked := usesMarked.push (n, hits)
  let byRole (role : String) : String :=
    let all := l2.filter fun t => r.branches[t.branch]!.role == role
    s!"{(all.filter (·.name.isSome)).size}/{all.size} {role}"
  let roles := ["step-own", "effect", "frame", "unattributed", "state"].map byRole
  logInfo m!"tie-back: statement = telescope {l1ok}/{clsOf.size} class occurrences; branch \
    lemmas {l2ok.size}/{walked.size} branch occurrences ({", ".intercalate roles}; \
    {nested} of them calling nested branch lemmas, \
    {(l2ok.filter (·.fallback != "")).size} proved by the original sub-term because the rebuilt \
    one failed); re-derived roots \
    {roots.size}/{r.rederived.size} ({", ".intercalate (r.rederived.toList.map (·.1.toString))}), \
    using {placed.size} branch lemmas; left in these proofs: {residual} branch markers, \
    {usesMarked.size} branch lemmas using a marked theorem \
    [{", ".intercalate (usesMarked.toList.map fun (n, cs) =>
      s!"{n.getString!} ({", ".intercalate (cs.toList.map toString)})")}]; frame lemmas \
    {l4ok.size}/{l4.size}; split-condition lemmas {(lc.filter (·.name.isSome)).size}/{l2.size} \
    ({noOwn.size} of them for branches that the split leaves no hypothesis in), converse lemmas {(lv.filter (·.name.isSome)).size}/{l2.size} ({withContext.size} of them using \
    hypotheses in scope that are not split conditions: {ctxCount "clause premise"} clause \
    premises and {ctxCount "binder"} other binders of the proof), statements computed before the body that differ {stmtDiff.size}; covering \
    lemmas not generated"
  let stepLive := r.branches.filter fun b => b.level == .step && !b.dead
  let cnt (role : String) := (stepLive.filter (·.role == role)).size
  logInfo m!"relevance: {r.splits.size} split occurrences, {r.branches.size} branch \
    occurrences; live step-level branch occurrences: {cnt "step-own"} step-own, {cnt "effect"} \
    effect, {cnt "frame"} frame, {cnt "unattributed"} unattributed; {reps.size} step classes, \
    {(live .state).size} state classes; clauses without premises: \
    {(shapes.filter (·.2.2 == 0)).map (·.1)}; unused haves: {r.unusedHaves.size}; \
    {r.unrecorded.size} unrecorded splits ({prot.size} protocol)"

elab "unfold_ns " ns:ident : tactic => do
  let p := ns.getId.eraseMacroScopes
  Tactic.liftMetaTactic1 fun g => do
    let ty ← instantiateMVars (← g.getType)
    let ty ← deltaExpand ty (p.isPrefixOf ·)
    g.change (← Core.betaReduce ty)

end Relevance

end
