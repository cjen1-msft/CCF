-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayAdvanceCommit

set_option autoImplicit false

namespace CCFRaft.NativeArrayAdvanceCommit

open NativeArrayCheckQuorum NativeArrayCommitIndex

variable {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]

inductive AdvanceCommit (frame : NativeArrayVote.Frame N T) (source : N) :
    NativeArrayVote.Frame N T -> Prop where
  | advance (current best : Nat) (retirement signature retired : Option Nat)
      (completed : Finset N)
      (currentCorrect :
        CurrentIndex (get frame.nodes source).log (get frame.nodes source).commit current)
      (bestCorrect : CommitIndex (get frame.nodes source) source current best)
      (retirementCorrect :
        retirementIndexInLog source (get frame.nodes source).log.decode = retirement)
      (signatureCorrect :
        retirement.bind
          (retirementCommittableIndexInLog (get frame.nodes source).log.decode) = signature)
      (retiredCorrect :
        retiredCommittedIndexInLog source (get frame.nodes source).log.decode = retired)
      (completedCorrect :
        retirementCompletedNodes
            (commitRow (get frame.nodes source) best retirement signature retired).log.decode
            (commitRow (get frame.nodes source) best retirement signature retired).commit =
          completed)
      (allowed : enabled frame source best
        (commitRow (get frame.nodes source) best retirement signature retired)) :
      AdvanceCommit frame source
        (advanceCommit frame source
          (commitRow (get frame.nodes source) best retirement signature retired) completed)

theorem AdvanceCommit.model_correct
    (frame after : NativeArrayVote.Frame N T) (state : State N T)
    (rep : frame.Rep state) (source : N)
    (step : AdvanceCommit frame source after) :
    CCFRaft.Enabled state (.advanceCommitIndex source) /\
      after.Rep (CCFRaft.next state (.advanceCommitIndex source)) := by
  cases step with
  | advance current best retirement signature retired completed currentCorrect bestCorrect
      retirementCorrect signatureCorrect retiredCorrect completedCorrect allowed =>
    let row := get frame.nodes source
    let output := commitRow row best retirement signature retired
    have same : state.nodes source = row.toModel :=
      (get_rep frame.nodes state rep.nodes source).symm
    have bestModel : highestCommittableIndex state source = best :=
      (commit_index_correct row state source current best same currentCorrect).mp bestCorrect
    have rowCorrect :
        output.toModel =
          refreshRetirementState source { (state.nodes source) with commitIndex := best } := by
      rw [same]
      exact commit_row_correct row source best retirement signature retired
        retirementCorrect signatureCorrect retiredCorrect
    have modelEnabled : CCFRaft.Enabled state (.advanceCommitIndex source) :=
      (enabled_correct frame state rep source best output bestModel rowCorrect).mp allowed
    have nextRep : (advanceCommit frame source output completed).Rep
        (CCFRaft.next state (.advanceCommitIndex source)) := by
      apply advance_commit_output_rep frame state rep source output completed
      · rw [bestModel]
        exact rowCorrect
      · exact completedCorrect
      · exact allowed.2.2.2
    exact ⟨modelEnabled, nextRep⟩

theorem AdvanceCommit.exists_of_enabled
    (frame : NativeArrayVote.Frame N T) (state : State N T)
    (rep : frame.Rep state) (source : N)
    (allowed : CCFRaft.Enabled state (.advanceCommitIndex source)) :
    exists after, AdvanceCommit frame source after := by
  let row := get frame.nodes source
  let previous := currentConfigurationAt row.log.decode row.commit
  have currentCorrect : CurrentIndex row.log row.commit previous.index :=
    ((NativeArrayConfiguration.current_configuration_correct row.log row.commit
      previous.index previous.nodes).mpr rfl).1
  let best := highestCommittableIndex state source
  have same : state.nodes source = row.toModel :=
    (get_rep frame.nodes state rep.nodes source).symm
  have bestCorrect : CommitIndex row source previous.index best :=
    (commit_index_correct row state source previous.index best same currentCorrect).mpr rfl
  let retirement := retirementIndexInLog source row.log.decode
  let signature := retirement.bind (retirementCommittableIndexInLog row.log.decode)
  let retired := retiredCommittedIndexInLog source row.log.decode
  let output := commitRow row best retirement signature retired
  let completed := retirementCompletedNodes output.log.decode output.commit
  have rowCorrect :
      output.toModel =
        refreshRetirementState source { (state.nodes source) with commitIndex := best } := by
    rw [same]
    exact commit_row_correct row source best retirement signature retired rfl rfl rfl
  have nativeAllowed : enabled frame source best output :=
    (enabled_correct frame state rep source best output rfl rowCorrect).mpr allowed
  exact ⟨advanceCommit frame source output completed,
    .advance previous.index best retirement signature retired completed currentCorrect
      bestCorrect rfl rfl rfl rfl nativeAllowed⟩

end CCFRaft.NativeArrayAdvanceCommit

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayAdvanceCommit).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
