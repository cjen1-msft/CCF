-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayBecomeLeader

set_option autoImplicit false

namespace CCFRaft.NativeArrayBecomeLeader

open NativeArrayCheckQuorum NativeArrayVote

variable {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]

inductive BecomeLeader (frame : Frame N T) (source : N) : Frame N T -> Prop where
  | promote (latest current : Nat) (retirement signature retired : Option Nat)
      (completed : Finset N)
      (latestCorrect : SignatureIndex (get frame.nodes source).log latest)
      (currentCorrect :
        CurrentIndex (get frame.nodes source).log (get frame.nodes source).commit current)
      (retirementCorrect :
        retirementIndexInLog source
          (prepareRow (get frame.nodes source) latest).log.decode = retirement)
      (signatureCorrect :
        retirement.bind
          (retirementCommittableIndexInLog
            (prepareRow (get frame.nodes source) latest).log.decode) = signature)
      (retiredCorrect :
        retiredCommittedIndexInLog source
          (prepareRow (get frame.nodes source) latest).log.decode = retired)
      (completedCorrect :
        retirementCompletedNodes
            (refreshRow (get frame.nodes source) latest retirement signature retired).log.decode
            (refreshRow (get frame.nodes source) latest retirement signature retired).commit =
          completed)
      (allowed : enabled frame source current
        (refreshRow (get frame.nodes source) latest retirement signature retired)) :
      BecomeLeader frame source
        (becomeLeader frame source
          (refreshRow (get frame.nodes source) latest retirement signature retired) completed)

theorem BecomeLeader.model_correct
    (frame after : Frame N T) (state : State N T)
    (rep : frame.Rep state) (source : N)
    (step : BecomeLeader frame source after) :
    CCFRaft.Enabled state (.becomeLeader source) /\
      after.Rep (CCFRaft.next state (.becomeLeader source)) := by
  cases step with
  | promote latest current retirement signature retired completed latestCorrect
      currentCorrect retirementCorrect signatureCorrect retiredCorrect completedCorrect
      allowed =>
    let row := get frame.nodes source
    let output := refreshRow row latest retirement signature retired
    have same : state.nodes source = row.toModel :=
      (get_rep frame.nodes state rep.nodes source).symm
    have latestValue :
        maxCommittableIndex (state.nodes source).log = latest := by
      rw [same]
      simpa only [Local.toModel] using
        (signature_index_correct row.log latest).mp latestCorrect
    have rowCorrect :
        output.toModel =
          refreshRetirementState source (prepareRow row latest).toModel := by
      rw [prepare_row_correct]
      exact refresh_row_correct row source latest retirement signature retired
        retirementCorrect signatureCorrect retiredCorrect
    have modelEnabled : CCFRaft.Enabled state (.becomeLeader source) :=
      (enabled_correct frame state rep source current latest output currentCorrect
        latestCorrect rowCorrect).mp allowed
    have outputCorrect :
        output.toModel =
          refreshRetirementState source
            { (state.nodes source) with
              role := .leader
              log := (state.nodes source).log.take
                (maxCommittableIndex (state.nodes source).log)
              sentIndex := fun _ =>
                ((state.nodes source).log.take
                  (maxCommittableIndex (state.nodes source).log)).length
              matchIndex := fun _ => 0 } := by
      rw [prepare_row_correct] at rowCorrect
      rw [← same, ← latestValue] at rowCorrect
      exact rowCorrect
    exact
      ⟨modelEnabled,
        become_leader_output_rep frame state rep source output completed allowed.1
          outputCorrect completedCorrect⟩

theorem BecomeLeader.exists_of_enabled
    (frame : Frame N T) (state : State N T)
    (rep : frame.Rep state) (source : N)
    (allowed : CCFRaft.Enabled state (.becomeLeader source)) :
    exists after, BecomeLeader frame source after := by
  let row := get frame.nodes source
  let latest := maxCommittableIndex row.log.decode
  have latestCorrect : SignatureIndex row.log latest :=
    (signature_index_correct row.log latest).mpr rfl
  let previous := currentConfigurationAt row.log.decode row.commit
  have currentCorrect : CurrentIndex row.log row.commit previous.index :=
    ((NativeArrayConfiguration.current_configuration_correct row.log row.commit
      previous.index previous.nodes).mpr rfl).1
  let prepared := prepareRow row latest
  let retirement := retirementIndexInLog source prepared.log.decode
  let signature :=
    retirement.bind (retirementCommittableIndexInLog prepared.log.decode)
  let retired := retiredCommittedIndexInLog source prepared.log.decode
  let output := refreshRow row latest retirement signature retired
  let completed := retirementCompletedNodes output.log.decode output.commit
  have rowCorrect :
      output.toModel =
        refreshRetirementState source (prepareRow row latest).toModel := by
    rw [prepare_row_correct]
    exact refresh_row_correct row source latest retirement signature retired rfl rfl rfl
  have nativeAllowed : enabled frame source previous.index output :=
    (enabled_correct frame state rep source previous.index latest output currentCorrect
      latestCorrect rowCorrect).mpr allowed
  exact
    ⟨becomeLeader frame source output completed,
      .promote latest previous.index retirement signature retired completed latestCorrect
        currentCorrect rfl rfl rfl rfl nativeAllowed⟩

end CCFRaft.NativeArrayBecomeLeader

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayBecomeLeader).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
