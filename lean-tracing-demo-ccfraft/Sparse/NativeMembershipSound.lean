-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeMembershipExecutionConstraints
import Sparse.NativeMembershipRowEncoding
import Sparse.NativeMembershipFrameEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem membership_prefix_model_correct {width : PNat} [Bootstrap (Fin width)]
    (source : Fin width) (configuration : Finset (Fin width))
    (before after : Encoding width)
    (initial : MembershipPrefixStates width) (suffix : MembershipSuffixStates width)
    (execution :
      MembershipChangeExecutionResult source configuration before after initial suffix)
    (assignment : Assignment)
    (holds : Holds suffix.writerBefore.assertions.toList assignment)
    (constraints : MembershipPrefixConstraints source configuration before
      (membershipExecutionTerms before source configuration) assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat) (state : State (Fin width) Nat)
    (columnsRep : FrameColumnsRep assignment before.toColumns frame)
    (modelRep : frame.Rep state)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION) :
    let terms := membershipExecutionTerms before source configuration
    let old := NativeArrayCheckQuorum.get frame.nodes source
    exists (previous : Finset (Fin width))
      (output : NativeArrayCheckQuorum.Local (Fin width) Nat) (completed : Finset (Fin width)),
      (latestConfiguration (state.nodes source)).nodes = previous /\
      terms.added.eval assignment Locals.empty = encodeBits (configuration \ previous) /\
      terms.completed.eval assignment Locals.empty = encodeBits completed /\
      terms.values.Rep assignment output /\
      output.toModel = refreshRetirementState source
        (NativeArrayChangeConfiguration.appendRow old configuration previous).toModel /\
      completed = retirementCompletedNodes
        (NativeArrayChangeConfiguration.appendRow old configuration previous).log.decode
        old.commit /\
      CCFRaft.Enabled state (.changeConfiguration source configuration) := by
  let terms := membershipExecutionTerms before source configuration
  let old := NativeArrayCheckQuorum.get frame.nodes source
  let previous := (currentConfigurationAt old.log.decode old.log.length).nodes
  have oldRep :=
    node_row_snapshot_rep assignment before.toColumns frame.nodes columnsRep.nodes source
  obtain ⟨_, _, _, currentMembers⟩ :=
    current_configuration_terms_sound assignment Locals.empty before.bootstrap
      terms.old.logLength terms.old.logEntries terms.old.logLength terms.current
      old.log old.log.length sameBootstrap oldRep.logLength oldRep.logLength
      oldRep.logEntries constraints.current
  have previousValue : terms.previous.eval assignment Locals.empty =
      encodeBits previous :=
    constraints.previous.trans currentMembers
  have addedValue : terms.added.eval assignment Locals.empty =
      encodeBits (configuration \ previous) :=
    constraints.added.trans
      (membership_added_term_correct assignment configuration previous terms.previous previousValue)
  obtain ⟨output, outputRep, outputModel, sameLog, _⟩ :=
    membership_row_terms_correct assignment before.toColumns frame.nodes columnsRep.nodes
      source configuration previous terms.length terms.entries terms.added before.bootstrap
      terms.first terms.retirement terms.signature terms.retired constraints.length
      constraints.entries addedValue sameBootstrap constraints.refresh
  have oldModel := NativeArrayCheckQuorum.get_rep frame.nodes state modelRep.nodes source
  have previousCorrect : (latestConfiguration (state.nodes source)).nodes = previous := by
    rw [<- oldModel, NativeArrayChangeConfiguration.latest_configuration_at_length]
  have enabled : CCFRaft.Enabled state (.changeConfiguration source configuration) :=
    (membership_guards_output_model_correct assignment before.toColumns frame state
      columnsRep modelRep source configuration previous terms.previous
      terms.values.membershipState output previousValue outputRep.membershipState
      previousCorrect outputModel).mp constraints.guards
  let completed := retirementCompletedNodes
    (NativeArrayChangeConfiguration.appendRow old configuration previous).log.decode
    old.commit
  have completedValue : terms.completed.eval assignment Locals.empty =
      encodeBits completed := by
    have bitsCorrect := retirement_completed_constraints_bits_correct before.bootstrap
      (.boolean true) terms.length terms.entries terms.old.commit terms.committedCurrent
      suffix.committedCurrentAsserted suffix.writerBefore (before.next + 10)
      execution.runs.suffixRuns.completedRun assignment holds output.log old.commit
      outputRep.logLength oldRep.commit sameBootstrap outputRep.logEntries rfl
      constraints.committedCurrent
    simpa only [sameLog] using bitsCorrect
  exact ⟨previous, output, completed, previousCorrect, addedValue, completedValue,
    outputRep, outputModel, rfl, enabled⟩

theorem membership_change_model_sound {width : PNat} [Bootstrap (Fin width)]
    (source : Fin width) (configuration : Finset (Fin width))
    (before after : Encoding width)
    (run : (membershipChange source configuration).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat) (state : State (Fin width) Nat)
    (columnsRep : FrameColumnsRep assignment before.toColumns frame)
    (modelRep : frame.Rep state)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION) :
    CCFRaft.Enabled state (.changeConfiguration source configuration) /\
      exists written : NativeArrayVote.Frame (Fin width) Nat,
        FrameColumnsRep assignment after.toColumns written /\
        written.Rep (CCFRaft.next state (.changeConfiguration source configuration)) := by
  obtain ⟨initial, suffix, execution, writerHolds, constraints⟩ :=
    membership_change_constraints source configuration before after run assignment holds
  let terms := membershipExecutionTerms before source configuration
  obtain ⟨previous, output, completed, previousCorrect, addedValue, completedValue,
    outputRep, outputModel, completedCorrect, enabled⟩ :=
    membership_prefix_model_correct source configuration before after initial suffix execution
      assignment writerHolds constraints frame state columnsRep modelRep sameBootstrap
  have writerRep : FrameColumnsRep assignment suffix.writerBefore.toColumns frame := by
    rw [execution.writerColumns]
    exact columnsRep
  have written := membership_writes_model_sound source terms.added terms.values output
    terms.completed completed configuration previous suffix.writerBefore after
    execution.runs.suffixRuns.writeRun assignment holds frame state writerRep modelRep
    outputRep addedValue completedValue previousCorrect outputModel completedCorrect
  exact ⟨enabled, _, written.1, written.2⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
