module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ReadersCorpus
import all ConsensusCoverage.ReadersCorpus
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersPolarFrontier
import all ConsensusCoverage.ReadersPolar
import all ConsensusCoverage.SolvedWitnesses
meta import Lean

namespace ConsensusCoverage.ReadersWitnessesChains

open ActionProfile ReadersAtoms Consensus.Proofs
open Lean Elab Term Meta

set_option maxHeartbeats 0
set_option maxRecDepth 8192
set_option Elab.async false

private def recorded : Option Step := ReadersCorpus.caseStepAt 32 9

private theorem sawStep : recorded.isSome = true := by decide +kernel

private def step : Step := recorded.get sawStep

private def view : Option XView :=
  ofXAction step.cfg step.before step.after step.past step.act

private theorem sawView : view.isSome = true := by decide +kernel

private def x : XView := view.get sawView

private def pools : ReadersPolar.Pools :=
  { ReadersPolar.prepare step.cfg x with sets := Thunk.mk fun _ => [{0, 1}] }

local elab "right_alternative%" t:term : term => do
  let e ← elabTerm t (some (mkConst ``Bool))
  synthesizeSyntheticMVarsNoPostponing
  let some e ← unfoldDefinition? (← instantiateMVars e) | throwError "expected a generated reader"
  unless e.isAppOfArity ``Bool.or 2 do throwError "expected two alternatives"
  return e.getArg! 1

private theorem yesOfRight [Config.InitialConfiguration] (v : XView) (ps : ReadersPolar.Pools)
    (ok : (right_alternative% ReadersPolarFrontier.R.yes_step_commitChains_step_led_inr v ps) = true) :
    ReadersPolarFrontier.R.yes_step_commitChains_step_led_inr v ps = true := by
  unfold ReadersPolarFrontier.R.yes_step_commitChains_step_led_inr
  rw [Bool.or_eq_true]
  exact Or.inr ok

-- Check the successful disjunct and quorum rather than searching for them in the kernel.
private theorem yesRight :
    (right_alternative% (@ReadersPolarFrontier.R.yes_step_commitChains_step_led_inr ⟨step.cfg⟩ x pools)) = true := by
  decide +kernel

public theorem occurs : ∃ s : Step, label s (.step .commitChains_step_led_inr) = true := by
  letI : Config.InitialConfiguration := ⟨step.cfg⟩
  obtain ⟨v, made, ok⟩ := ofXAction_matches step
  have made' : view = some x := Option.eq_some_of_isSome sawView
  have same := Option.some.inj (made.symm.trans made')
  refine ⟨step, (label_true step _).mpr ((SolvedWitnesses.sig_iff step.context _).mpr ?_)⟩
  exact @ReadersPolarFrontier.R.yes_step_commitChains_step_led_inr_sound
    _ step.frame step.after step.context x (same ▸ ok) pools (yesOfRight x pools yesRight)

end ConsensusCoverage.ReadersWitnessesChains
