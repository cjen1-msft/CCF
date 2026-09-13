-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendReceiveSound

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem append_receive_finish_assignment {width : PNat} [Bootstrap (Fin width)]
    (source destination : Fin width) (before after : Encoding width)
    (states : AppendReceivePrefixStates width)
    (execution : AppendReceiveExecutionResult source destination before after states)
    (assignment : Assignment)
    (holds : Holds states.middle.suffix.writerBefore.assertions.toList assignment)
    (valid : ReferencesValid before)
    (frame : NativeArrayVote.Frame (Fin width) Nat) (state : State (Fin width) Nat)
    (columnsRep : FrameColumnsRep assignment before.toColumns frame)
    (modelRep : frame.Rep state)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION) :
    exists extended : Assignment,
      assignment.AgreesBelow states.middle.suffix.writerBefore.next extended /\
      Holds after.assertions.toList extended /\
      exists written : NativeArrayVote.Frame (Fin width) Nat,
        FrameColumnsRep extended after.toColumns written /\
        written.Rep (CCFRaft.next state (.receive source destination)) := by
  let terms := appendReceiveExecutionTerms before source destination
  have constraints := append_receive_prefix_constraints source destination before after
    states execution assignment holds
  obtain ⟨_, output, response, completed, _, _, outputRep,
    responseValue, responseSource, responseDestination, sameCompleted, writtenModel⟩ :=
    append_receive_prefix_model_correct source destination before assignment constraints
      frame state columnsRep modelRep sameBootstrap
  have writerRep : FrameColumnsRep assignment
      states.middle.suffix.writerBefore.toColumns frame := by
    rw [execution.writerColumns]
    exact columnsRep
  have writerValid : ReferencesValid states.middle.suffix.writerBefore := by
    cases valid
    constructor <;> simp_all only [execution.writerColumns, execution.writerNext] <;> omega
  obtain ⟨extended, agreement, afterHolds, writtenRep⟩ :=
    append_receive_writes_complete source destination terms.branches.stepDown
      terms.values output terms.response response terms.completed completed
      states.middle.suffix.writerBefore after execution.runs.middleRuns.suffixRuns.writeRun
      assignment holds frame writerRep outputRep writerValid
      (terms.branches.stepDown.eval assignment Locals.empty) rfl responseValue
      responseSource responseDestination sameCompleted
  exact ⟨extended, agreement, afterHolds, _, writtenRep, writtenModel⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
