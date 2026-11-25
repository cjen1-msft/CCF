module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ReadersCorpus
import all ConsensusCoverage.ReadersCorpus
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersPolarGenerated
import all ConsensusCoverage.ReadersPolar
import all ConsensusCoverage.SolvedWitnesses
meta import Lean

namespace ConsensusCoverage.ReadersWitnessesSplit

open ActionProfile ReadersAtoms
open Lean Elab Tactic

set_option maxHeartbeats 0
set_option maxRecDepth 8192

private def recorded : Option Step := ReadersCorpus.caseStepAt 21 5

private theorem sawStep : recorded.isSome = true := by decide +kernel

private def step : Step := recorded.get sawStep

private def view : Option XView :=
  ofXAction step.cfg step.before step.after step.past step.act

private theorem sawView : view.isSome = true := by decide +kernel

private def x : XView := view.get sawView

private def pools : ReadersPolar.Pools := ReadersPolar.prepare step.cfg x

local elab "bool_or_witness " ix:num : tactic => do
  for _ in [:ix.getNat] do
    evalTactic (← `(tactic| rw [Bool.or_eq_true]; right))
  evalTactic (← `(tactic| rw [Bool.or_eq_true]; left))

-- Checking one successful disjunct avoids evaluating the preceding failures.
private theorem positive :
    @ReadersPolarCompiler.R.yes_step_summary_message_requestVoteResponse ⟨step.cfg⟩ x pools = true := by
  unfold ReadersPolarCompiler.R.yes_step_summary_message_requestVoteResponse
  bool_or_witness 12
  rw [Bool.and_eq_true]
  exact ⟨by decide +kernel, by decide +kernel⟩

public theorem voteResponse : ∃ s : Step, label s (.step .summary_message_requestVoteResponse) = true := by
  letI : Consensus.Proofs.Config.InitialConfiguration := ⟨step.cfg⟩
  obtain ⟨v, made, ok⟩ := ofXAction_matches step
  have made' : ofXAction step.cfg step.before step.after step.past step.act = some x :=
    Option.eq_some_of_isSome sawView
  have same := Option.some.inj (made.symm.trans made')
  refine ⟨step, (label_true step _).mpr ((SolvedWitnesses.sig_iff step.context _).mpr ?_)⟩
  exact @ReadersPolarCompiler.R.yes_step_summary_message_requestVoteResponse_sound
    _ step.frame step.after step.context x (same ▸ ok) pools positive

end ConsensusCoverage.ReadersWitnessesSplit
