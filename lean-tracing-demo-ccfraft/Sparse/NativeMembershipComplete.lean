-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeMembershipSound
import Sparse.NativeMembershipLogAssignment
import Sparse.NativeMembershipRetirementAssignment
import Sparse.NativeMembershipTailAssignment

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem membership_finish_assignment {width : PNat} [Bootstrap (Fin width)]
    (source : Fin width) (configuration : Finset (Fin width))
    (before after : Encoding width)
    (initial : MembershipPrefixStates width) (suffix : MembershipSuffixStates width)
    (execution :
      MembershipChangeExecutionResult source configuration before after initial suffix)
    (assignment : Assignment)
    (holds : Holds suffix.writerBefore.assertions.toList assignment)
    (valid : ReferencesValid before)
    (frame : NativeArrayVote.Frame (Fin width) Nat) (state : State (Fin width) Nat)
    (columnsRep : FrameColumnsRep assignment before.toColumns frame)
    (modelRep : frame.Rep state)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION) :
    exists extended : Assignment,
      assignment.AgreesBelow suffix.writerBefore.next extended /\
      Holds after.assertions.toList extended /\
      exists written : NativeArrayVote.Frame (Fin width) Nat,
        FrameColumnsRep extended after.toColumns written /\
        written.Rep (CCFRaft.next state (.changeConfiguration source configuration)) := by
  let terms := membershipExecutionTerms before source configuration
  have constraints := membership_prefix_constraints source configuration before after
    initial suffix execution assignment holds
  obtain ⟨previous, output, completed, previousCorrect, addedValue, completedValue,
    outputRep, outputModel, completedCorrect, _⟩ :=
    membership_prefix_model_correct source configuration before after initial suffix execution
      assignment holds constraints frame state columnsRep modelRep sameBootstrap
  have writerRep : FrameColumnsRep assignment suffix.writerBefore.toColumns frame := by
    rw [execution.writerColumns]
    exact columnsRep
  have writerValid : ReferencesValid suffix.writerBefore := by
    cases valid
    constructor <;> simp_all only [execution.writerColumns, execution.writerNext] <;> omega
  obtain ⟨_, extended, agreement, afterHolds, writtenRep, writtenModel⟩ :=
    membership_writes_model_complete source terms.added terms.values output
      terms.completed completed configuration previous suffix.writerBefore after
      execution.runs.suffixRuns.writeRun assignment holds frame state writerRep modelRep
      outputRep writerValid addedValue completedValue previousCorrect outputModel completedCorrect
  exact ⟨extended, agreement, afterHolds, _, writtenRep, writtenModel⟩

theorem membership_change_model_complete {width : PNat} [Bootstrap (Fin width)]
    (source : Fin width) (configuration : Finset (Fin width))
    (before after : Encoding width)
    (run : (membershipChange source configuration).run before = .ok ((), after))
    (assignment : Assignment)
    (holds : Holds before.assertions.toList assignment)
    (valid : ReferencesValid before)
    (frame : NativeArrayVote.Frame (Fin width) Nat) (state : State (Fin width) Nat)
    (columnsRep : FrameColumnsRep assignment before.toColumns frame)
    (modelRep : frame.Rep state)
    (enabled : CCFRaft.Enabled state (.changeConfiguration source configuration))
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION) :
    exists extended : Assignment,
      assignment.AgreesBelow before.next extended /\
      Holds after.assertions.toList extended /\
      exists written : NativeArrayVote.Frame (Fin width) Nat,
        FrameColumnsRep extended after.toColumns written /\
        written.Rep
          (CCFRaft.next state (.changeConfiguration source configuration)) := by
  obtain ⟨initial, suffix, execution⟩ :=
    membership_change_success source configuration before after run
  let old := NativeArrayCheckQuorum.get frame.nodes source
  let previousSet := (currentConfigurationAt old.log.decode old.log.length).nodes
  let appended :=
    NativeArrayChangeConfiguration.appendRow old configuration previousSet
  have oldModel : old.toModel = state.nodes source := by
    simpa [old] using
      NativeArrayCheckQuorum.get_rep frame.nodes state modelRep.nodes source
  have previousCorrect :
      (latestConfiguration (state.nodes source)).nodes = previousSet := by
    rw [<- oldModel, NativeArrayChangeConfiguration.latest_configuration_at_length]
  obtain ⟨logAssignment, logAgreement, logHolds, logRep, previousValue,
      addedValue, logLength, logEntries⟩ :=
    membership_log_assignment source configuration before after initial suffix execution
      assignment holds valid frame columnsRep sameBootstrap
  obtain ⟨retirementAssignment, output, retirementAgreement, retirementHolds,
      retirementRep, retirementPrevious, retirementAdded, retirementLength,
      retirementEntries, _, _, _, _⟩ :=
    membership_retirement_assignment source configuration before after initial suffix
      execution logAssignment logHolds valid frame state logRep modelRep enabled
      sameBootstrap previousSet previousCorrect previousValue addedValue logLength
      logEntries
  obtain ⟨tailAssignment, tailAgreement, tailHolds, tailRep⟩ :=
    membership_tail_assignment source configuration before after initial suffix execution
      retirementAssignment retirementHolds valid frame retirementRep appended.log
      retirementLength retirementEntries sameBootstrap
  obtain ⟨extended, finishAgreement, afterHolds, written, writtenRep, writtenModel⟩ :=
    membership_finish_assignment source configuration before after initial suffix execution
      tailAssignment tailHolds valid frame state tailRep modelRep sameBootstrap
  have lengthDefinedNext : initial.lengthDefined.next = before.next + 5 :=
    (fresh_success initial.lengthDefined suffix.firstFresh (before.next + 5)
      execution.runs.suffixRuns.firstRun).1.symm
  have guardsAssertedNext : suffix.guardsAsserted.next = before.next + 9 :=
    (fresh_success suffix.guardsAsserted suffix.committedCurrentFresh
      (before.next + 9) execution.runs.suffixRuns.committedCurrentRun).1.symm
  have originalToRetirement :
      assignment.AgreesBelow before.next retirementAssignment :=
    logAgreement.trans
      (retirementAgreement.restrict (by rw [lengthDefinedNext]; omega))
  have originalToTail : assignment.AgreesBelow before.next tailAssignment :=
    originalToRetirement.trans
      (tailAgreement.restrict (by rw [guardsAssertedNext]; omega))
  have originalToExtended : assignment.AgreesBelow before.next extended :=
    originalToTail.trans
      (finishAgreement.restrict (by rw [execution.writerNext]; omega))
  exact ⟨extended, originalToExtended, afterHolds, written, writtenRep, writtenModel⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
