-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeMembershipSound

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

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
