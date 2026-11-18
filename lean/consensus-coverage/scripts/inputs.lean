module

meta import Lean
meta import Relevance.Generate
import all Consensus.Proofs.SafetyInvariant

/-!
# Generator inputs for the consensus safety proof, report only

Checks the inputs for the stepwise proof, with the generator's
own functions and without walking any proof:

- the step pattern `Ctx f after` with pre-state `f` and post-state
  `f.advance after` (`(pre := ...)`, `(post := ...)`);
- the clauses of `Inv`, read through their definitions: data binders and premises per clause;
- the theorems classified from their `Inv` or `Ctx` hypotheses.

Run from the repository root (the workspace is out of tree):

    WS=$(python3 lean/relevance/scripts/workspace.py consensus-coverage)
    lake -d $WS/consensus-coverage env lean $PWD/lean/consensus-coverage/scripts/inputs.lean
-/

open Lean Meta Elab Command Relevance

set_option hygiene false in
open Consensus Consensus.Proofs Consensus.Proofs.Safety in
#eval show CommandElabM Unit from do
  let elab_ (s : TSyntax `term) : CommandElabM Expr := liftTermElabM do
    let e ← Term.elabTerm s none
    Term.synthesizeSyntheticMVarsNoPostponing
    instantiateMVars e
  let stepPat ← elab_ (← `(fun [Consensus.Proofs.Config.InitialConfiguration]
    (f : Frame) (after : Model.State) => Ctx f after))
  let statePat ← elab_ (← `(fun [Consensus.Proofs.Config.InitialConfiguration] (f : Frame) => Inv f))
  let preOf ← elab_ (← `(fun [Consensus.Proofs.Config.InitialConfiguration]
    (f : Frame) (_ : Model.State) => f))
  let postOf ← elab_ (← `(fun [Consensus.Proofs.Config.InitialConfiguration]
    (f : Frame) (after : Model.State) => f.advance after))
  let stateCtor ← liftTermElabM <| lambdaTelescope statePat fun _ body => do
    let some c := body.getAppFn.constName? | return none
    return some (getStructureCtor (← getEnv) c).name
  IO.println s!"state structure constructor: {stateCtor}"
  let cfg : Relevance.Config :=
    { scope := `Consensus.Proofs, package := #[`Consensus], stepPat, statePat, stateCtor, preOf,
      postOf }
  let t0 ← IO.monoMsNow
  let (creates, shapes) ← liftTermElabM <| mkCreates cfg
  IO.println s!"creates generated: {creates.isSome}"
  if let some v := creates then
    let txt ← liftTermElabM <| lambdaTelescope v fun _ b => do
      let .app (.app (.const ``Or _) d) _ := b | return toString (← ppExpr b)
      return toString (← ppExpr d)
    IO.println s!"first clause of creates: {txt}"
  for (n, nd, np) in shapes do
    IO.println s!"clause {n}: {nd} data binder(s), {np} premise(s)"
  -- levels of the theorems used by the two safety theorems
  let roots := #[``CommittedLogs.committed_logs_prefix, ``Election.election_safety]
  let mut seen : Array Name := #[]
  let mut todo := roots
  while !todo.isEmpty do
    let c := todo.back!
    todo := todo.pop
    if seen.contains c then continue
    seen := seen.push c
    todo := todo ++ (← liftCoreM <| theoremsUsed cfg c)
  let mut steps := #[]
  let mut states := #[]
  let mut others := 0
  for c in seen do
    let ci ← getConstInfo c
    let (lvl, keep) ← liftTermElabM <| forallTelescope ci.type fun xs _ => do
      let (l, k) ← classify cfg xs true
      return (l, ← k.mapM fun x => return toString (← x.fvarId!.getUserName))
    match lvl with
    | .step => steps := steps.push c
    | .state => states := states.push (c, keep)
    | .other => others := others + 1
  IO.println s!"theorems {seen.size}: step {steps.size}, state {states.size}, other {others}"
  for (c, keep) in states do
    IO.println s!"state-level: {(privateToUserName? c).getD c} (state binders {keep})"
  IO.println s!"time {(← IO.monoMsNow) - t0} ms"
