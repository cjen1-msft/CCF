module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.CensusQueueStep
import all ConsensusCoverage.CensusQueueElection
import all ConsensusCoverage.CensusQueueBool
public meta import ConsensusCoverage.CensusQueueBool
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersPolarObserve
import all ConsensusCoverage.DeepInputCases
import all ConsensusCoverage.DeepGrantCases
import all ConsensusCoverage.DeepActorCases
import all ConsensusCoverage.DeepCampaignCases
import all ConsensusCoverage.DeepLeaderCases
import all ConsensusCoverage.DeepElectionCases
import all ConsensusCoverage.DeepEffectCases
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ReadersPolar
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ActionProfile
import all Consensus.Proofs.SafetyInvariant
public meta import Lean
public meta import ConsensusCoverage.PinnedClasses

namespace ConsensusCoverage.CensusQueueHints

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open ActionProfile ReadersAtoms ReadersPolar

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 16384

-- Candidate generation is never evidence; the generated term includes
-- *literal* voter, candidate, term and request fields and rechecks the guard.
def findGrant (s : Step) (k : DeepGrantCases.GrantCase) : List Nat := Id.run do
  let p := CensusQueueStep.pools s
  for r in p.requests.get do
    for v in p.ids.get do
      for n in p.ids.get do
        if DeepGrantCases.check s k v n r.term r then
          return [v, n, r.term, r.term, r.lastCommittableTerm, r.lastCommittableIndex]
  return []

def findVoter (s : Step) (k : DeepCampaignCases.CampaignCase) : List Nat :=
  ((CensusQueueStep.pools s).ids.get.find? fun v => DeepCampaignCases.check s k v).toList

meta section
open Lean Meta Elab Tactic

private unsafe def evalArgsImpl (x : Expr) : MetaM (List Nat) :=
  evalExpr (List Nat) (mkApp (mkConst ``List [.zero]) (mkConst ``Nat)) x (checkMeta := false)

@[implemented_by evalArgsImpl] private def evalArgs (_ : Expr) : MetaM (List Nat) := return []

private def enumRule (b : Expr) (tag col : Name) : MetaM (Option Name) := do
  for case_ in (← getConstInfoInduct tag).ctors do
    let e := mkApp (mkConst col) (mkConst case_)
    if (← withTransparency .all <| whnf e).isConstOf b.constName! then return some case_
  return none

private def seed (st : Term) (source : String) : TacticM Unit := do
  let exactName := Name.mkStr `ConsensusCoverage.ReadersCompiler.R (source ++ "_iff")
  if (← getEnv).contains exactName then
    let r := mkIdent exactName
    return ← evalTactic (← `(tactic| exact (@$(r):ident ⟨Step.cfg $st⟩ _ _ (CensusQueueStep.context $st) _
      (CensusQueueStep.reflected $st)).mp (by queue_bool)))
  for ns in [`ReadersPolarObserve, `ReadersPolarBacking, `ReadersPolarSummary, `ReadersPolarFrontier] do
    let sound := Name.mkStr (`ConsensusCoverage ++ ns ++ `R) ("yes_" ++ source ++ "_sound")
    if (← getEnv).contains sound then
      let r := mkIdent sound
      return ← evalTactic (← `(tactic| exact @$(r):ident ⟨Step.cfg $st⟩ _ _ (CensusQueueStep.context $st) _
        (CensusQueueStep.reflected $st) (CensusQueueStep.pools $st) (by queue_bool)))
  throwError "no checked positive source for {source}"

elab "queue_hint " st:term : tactic => withMainContext do
  let target ← instantiateMVars (← (← getMainGoal).getType)
  unless target.isAppOfArity ``Eq 3 && (target.getArg! 1).isAppOfArity ``label 2 do
    throwError "expected a concrete step label"
  let q := (target.getArg! 1).appArg!
  unless q.isAppOfArity ``FullProfile.Question.step 1 do throwError "expected a step coordinate"
  let b := q.appArg!
  let some n := b.constName? | throwError "expected a concrete branch"
  let s ← elabTerm st (some (mkConst ``Step))
  for (tag, col, rule, search) in [
      (``DeepInputCases.InputCase, ``DeepInputCases.InputCase.column, ``DeepInputCases.correct, none),
      (``DeepActorCases.ActorCase, ``DeepActorCases.ActorCase.column, ``DeepActorCases.correct, none),
      (``DeepGrantCases.GrantCase, ``DeepGrantCases.GrantCase.column, ``DeepGrantCases.correct, some ``findGrant),
      (``DeepCampaignCases.CampaignCase, ``DeepCampaignCases.CampaignCase.column, ``DeepCampaignCases.correct, some ``findVoter)] do
    if let some tag ← enumRule b tag col then
      let r := mkIdent rule
      let k := mkIdent tag
      let some search := search | return ← evalTactic (← `(tactic| exact $r $st $k (by decide +kernel)))
      let values ← evalArgs (mkApp2 (mkConst search) s (mkConst tag))
      match values.map Syntax.mkNatLit with
      | [v] => return ← evalTactic (← `(tactic| exact $r $st $k $v (by decide +kernel)))
      | [v, c, t, rt, lt, li] =>
        return ← evalTactic (← `(tactic| exact $r $st $k $v $c $t ⟨$rt, $lt, $li⟩ (by decide +kernel)))
      | _ => throwError "no matching witness for {tag} in the recorded candidate pool"
  let formula := "step_" ++ n.getString!
  for r in [``DeepLeaderCases.leaderPositive, ``DeepLeaderCases.leaderZero,
      ``DeepLeaderCases.electedPositive, ``DeepLeaderCases.electedZero] do
    let ci ← getConstInfo r
    let result ← forallTelescope ci.type fun _ goal => pure goal.getAppFn.constName!
    if result.getString! == formula then
      let rule := mkIdent r
      return ← evalTactic (← `(tactic| (
        refine CensusQueueStep.ofFormula $st _ ?_
        apply @$(rule):ident ⟨Step.cfg $st⟩ _ _ (CensusQueueStep.context $st)
        all_goals decide +kernel)))
  for r in [``DeepElectionCases.electedLed, ``DeepElectionCases.electedNew, ``DeepEffectCases.flushCons] do
    let ci ← getConstInfo r
    let (source, result) ← forallTelescope ci.type fun args goal => do
      return ((← inferType args.back!).getAppFn.constName!, goal.getAppFn.constName!)
    if result.getString! == formula then
      let rule := mkIdent r
      evalTactic (← `(tactic| (
        refine CensusQueueStep.ofFormula $st _ ?_
        apply @$(rule):ident ⟨Step.cfg $st⟩ _ _ (CensusQueueStep.context $st))))
      return ← seed st source.getString!
  if n.getString!.endsWith "_message_proposeRequestVoteRequest" then
    let other := (n.getString!.dropEnd "proposeRequestVoteRequest".length).toString ++ "appendEntriesResponse"
    evalTactic (← `(tactic| refine CensusQueueStep.ofFormula $st _ ?_))
    return ← seed st ("step_" ++ other)
  evalTactic (← `(tactic| refine CensusQueueStep.ofFormula $st _ ?_))
  seed st formula
end
end ConsensusCoverage.CensusQueueHints
