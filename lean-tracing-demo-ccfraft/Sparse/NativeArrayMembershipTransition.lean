-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayChangeConfiguration

set_option autoImplicit false

namespace CCFRaft.NativeArrayChangeConfiguration

open NativeArrayCheckQuorum

variable {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]

inductive ChangeConfiguration (frame : NativeArrayVote.Frame N T) (source : N)
    (configuration : Finset N) : NativeArrayVote.Frame N T -> Prop where
  | change (previousIndex : Nat) (previous : Finset N)
      (retirement signature retired : Option Nat) (completed : Finset N)
      (current : CurrentIndex (get frame.nodes source).log
        (get frame.nodes source).log.length previousIndex)
      (atPrevious :
        NativeArrayConfiguration.At (get frame.nodes source).log previousIndex previous)
      (retirementCorrect : retirementIndexInLog source
        (appendRow (get frame.nodes source) configuration previous).log.decode = retirement)
      (signatureCorrect : retirement.bind (retirementCommittableIndexInLog
        (appendRow (get frame.nodes source) configuration previous).log.decode) = signature)
      (retiredCorrect : retiredCommittedIndexInLog source
        (appendRow (get frame.nodes source) configuration previous).log.decode = retired)
      (completedCorrect : retirementCompletedNodes
        ((get frame.nodes source).toModel.log ++
          [{ term := (get frame.nodes source).toModel.currentTerm,
             content := .reconfiguration configuration }])
        (get frame.nodes source).toModel.commitIndex = completed)
      (allowed : enabled frame source configuration previous retirement signature retired) :
      ChangeConfiguration frame source configuration
        (changeConfiguration frame source configuration previous retirement signature retired completed)

theorem ChangeConfiguration.model_correct
    (frame after : NativeArrayVote.Frame N T) (state : State N T)
    (rep : frame.Rep state) (source : N) (configuration : Finset N)
    (step : ChangeConfiguration frame source configuration after) :
    CCFRaft.Enabled state (.changeConfiguration source configuration) /\
      after.Rep (CCFRaft.next state (.changeConfiguration source configuration)) := by
  cases step with
  | change previousIndex previous retirement signature retired completed
      current atPrevious retirementCorrect signatureCorrect retiredCorrect completedCorrect allowed =>
    exact
      ⟨(enabled_correct frame state rep source configuration previous previousIndex
          retirement signature retired current atPrevious retirementCorrect signatureCorrect
          retiredCorrect).mp allowed,
        change_configuration_rep frame state rep source configuration previous previousIndex
          retirement signature retired completed current atPrevious retirementCorrect
          signatureCorrect retiredCorrect completedCorrect⟩

theorem ChangeConfiguration.exists_of_enabled
    (frame : NativeArrayVote.Frame N T) (state : State N T)
    (rep : frame.Rep state) (source : N) (configuration : Finset N)
    (allowed : CCFRaft.Enabled state (.changeConfiguration source configuration)) :
    exists after, ChangeConfiguration frame source configuration after := by
  let row := get frame.nodes source
  let previous := currentConfigurationAt row.log.decode row.log.length
  obtain ⟨current, atPrevious⟩ :=
    (NativeArrayConfiguration.current_configuration_correct row.log row.log.length
      previous.index previous.nodes).mpr rfl
  let appended := appendRow row configuration previous.nodes
  let retirement := retirementIndexInLog source appended.log.decode
  let signature := retirement.bind (retirementCommittableIndexInLog appended.log.decode)
  let retired := retiredCommittedIndexInLog source appended.log.decode
  let completed := retirementCompletedNodes
    (row.toModel.log ++
      [{ term := row.toModel.currentTerm, content := .reconfiguration configuration }])
    row.toModel.commitIndex
  have nativeAllowed : enabled frame source configuration previous.nodes retirement signature retired :=
    (enabled_correct frame state rep source configuration previous.nodes previous.index
      retirement signature retired current atPrevious rfl rfl rfl).mpr allowed
  exact ⟨_, .change previous.index previous.nodes retirement signature retired completed
    current atPrevious rfl rfl rfl rfl nativeAllowed⟩

end CCFRaft.NativeArrayChangeConfiguration

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayChangeConfiguration).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
