module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ActionProfile
import all ConsensusCoverage.CensusQueueElection
import all ConsensusCoverage.CensusQueueStep
import all ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.SolvedWitnesses
meta import ConsensusCoverage.CensusQueueElection

namespace ConsensusCoverage.CaseWitnessesQueued
open Consensus Consensus.Model Consensus.Model.Node ActionProfile FrontierRows
set_option maxRecDepth 16384
set_option maxHeartbeats 150000
set_option Elab.async false

private def run0 : Run := ⟨{0, 1, 2}, [0, 1, 2], [.input 0 (.append [{content := .signature, flushes := [(1, 2), (2, 2)]}]), .deliver 0 1, .deliver 0 2, .deliver 1 0, .input 0 (.nominateSuccessor), .input 0 (.append [{content := .signature}]), .deliver 0 1, .deliver 1 2, .deliver 2 1]⟩
private def select0 := CensusQueueStep.selected run0 (by unfold Run.valid; decide) [] 8
private def step0 : Step := select0.get (by decide +kernel)
private theorem yes_commit_backed_eq_zero_or_pos_inl : label step0 (.step .commit_backed_eq_zero_or_pos_inl) = true := by queue_win step0
private def run1 : Run := ⟨{0, 1, 2}, [0, 1, 2], [.input 0 (.append [{content := .signature, flushes := [(1, 2), (2, 2)]}]), .deliver 0 1, .deliver 0 2, .deliver 1 0, .input 0 (.nominateSuccessor), .input 0 (.sendEntries 2 2), .deliver 0 2, .deliver 0 1, .deliver 1 2, .deliver 2 1, .input 1 (.append [{content := .signature, flushes := [(2, 3)]}]), .deliver 1 2, .deliver 1 2, .deliver 2 1, .deliver 2 1, .input 1 (.sendEntries 2 3), .deliver 1 2, .input 1 (.nominateSuccessor), .deliver 1 2, .deliver 2 1, .deliver 1 2]⟩
private def select1 := CensusQueueStep.selected run1 (by unfold Run.valid; decide) [(19, 6)] 20
private def step1 : Step := select1.get (by decide +kernel)
private theorem yes_commit_backed_eq_zero_or_pos_inr : label step1 (.step .commit_backed_eq_zero_or_pos_inr) = true := by queue_win step1

public def witnessed : List Classes.StepBranch :=
  [.commit_backed_eq_zero_or_pos_inl, .commit_backed_eq_zero_or_pos_inr]

public theorem occurs {b : Classes.StepBranch} (mem : b ∈ witnessed) :
    ∃ s : Step, label s (.step b) = true := by
  simp only [witnessed, List.mem_cons, List.not_mem_nil, or_false] at mem
  rcases mem with rfl | rfl
  · exact ⟨step0, yes_commit_backed_eq_zero_or_pos_inl⟩
  · exact ⟨step1, yes_commit_backed_eq_zero_or_pos_inr⟩

public theorem count : witnessed.Nodup ∧ witnessed.length = 2 := by decide +kernel

end ConsensusCoverage.CaseWitnessesQueued
