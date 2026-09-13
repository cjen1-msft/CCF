-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendReceiveSound
import Sparse.NativeAppendReceiveLogAssignment
import Sparse.NativeAppendReceiveCommitAssignment
import Sparse.NativeAppendReceiveRetirementAssignment
import Sparse.NativeAppendReceiveTailAssignment

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem append_receive_current_assignment {width : PNat} [Bootstrap (Fin width)]
    (source destination : Fin width) (before after : Encoding width)
    (states : AppendReceivePrefixStates width)
    (execution : AppendReceiveExecutionResult source destination before after states)
    (assignment : Assignment)
    (holds : Holds before.assertions.toList assignment)
    (valid : ReferencesValid before)
    (frame : NativeArrayVote.Frame (Fin width) Nat) (state : State (Fin width) Nat)
    (columnsRep : FrameColumnsRep assignment before.toColumns frame)
    (modelRep : frame.Rep state)
    (request : AppendEntriesRequest (Fin width) Nat)
    (selected : NativeArrayAppendNetwork.SelectedAppend
      frame source destination request)
    (enabled : CCFRaft.Enabled state (.receive source destination))
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION) :
    exists extended : Assignment,
      assignment.AgreesBelow before.next extended /\
      Holds states.middle.suffix.currentAsserted.assertions.toList extended /\
      FrameColumnsRep extended before.toColumns frame /\
      (appendReceiveExecutionTerms before source destination).packet.eval
          extended Locals.empty =
        packetValue (.appendEntriesRequest request) /\
      exists (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (commit : Nat),
        (appendReceiveExecutionTerms before source destination).logLength.eval
            extended Locals.empty = (log.length : Int) /\
        (forall position, position < log.length ->
          modelEntry
              ((appendReceiveExecutionTerms before source destination).logEntries.eval
                extended Locals.empty (position : Int)) =
            log.entries position) /\
        (appendReceiveExecutionTerms before source destination).commit.eval
            extended Locals.empty = (commit : Int) /\
        (currentConfigurationIndexTerm width
          (appendReceiveExecutionTerms before source destination).logLength
          (appendReceiveExecutionTerms before source destination).logEntries
          (appendReceiveExecutionTerms before source destination).commit
          (appendReceiveExecutionTerms before source destination).current).eval
            extended Locals.empty = true := by
  let terms := appendReceiveExecutionTerms before source destination
  have nonempty : 0 < (frame.queues destination source).length := by
    by_contra empty
    have zero : (frame.queues destination source).length = 0 := by omega
    have head := selected.head
    simp [NativeArrayQueue.Queue.peek, zero] at head
  have guards : Holds
      (appendReceiveGuards before.toColumns source destination) assignment :=
    (append_receive_guards_model_correct assignment before.toColumns frame state
      columnsRep modelRep source destination).mpr
      ⟨selected.destinationAllocated, nonempty, request, selected.head,
        selected.destinationHeader, enabled⟩
  have headValue :
      (frame.queues destination source).cells
          (frame.queues destination source).head =
        .appendEntriesRequest request := by
    simpa only [NativeArrayQueue.Queue.peek, if_pos nonempty, Option.some.injEq]
      using selected.head
  have samePacket :
      (queueHeadPacketTerm before.toColumns source destination).eval
          assignment Locals.empty =
        packetValue (.appendEntriesRequest request) := by
    rw [queue_head_packet_term_correct assignment before.toColumns frame columnsRep
      source destination nonempty, headValue]
  obtain ⟨logAssignment, logAgreement, logHolds, logRep, logPacket,
      logLength, logEntries⟩ :=
    append_receive_log_assignment source destination before after states execution
      assignment frame holds valid columnsRep guards request samePacket
  let payload := NativeArrayCheckQuorum.Log.ofList request.entries
  let row := NativeArrayCheckQuorum.get frame.nodes destination
  let log := NativeArrayAppendCandidate.candidateLog row request payload
    (terms.branches.acceptable.eval logAssignment Locals.empty)
    (terms.branches.alreadyDone.eval logAssignment Locals.empty)
  have sameLogLength :
      terms.logLength.eval logAssignment Locals.empty = (log.length : Int) := by
    simpa only [terms, payload, row, log] using logLength
  have sameLogEntries : forall position, position < log.length ->
      modelEntry (terms.logEntries.eval logAssignment Locals.empty (position : Int)) =
        log.entries position := by
    simpa only [terms, payload, row, log] using logEntries
  obtain ⟨commitAssignment, commitAgreement, commitHolds, commitRep, commitPacket,
      commitLength, commitEntries, commit, commitValue⟩ :=
    append_receive_commit_assignment source destination before after states execution
      logAssignment frame logHolds valid logRep request logPacket log sameLogLength
      sameLogEntries
  obtain ⟨currentAssignment, currentAgreement, currentHolds, currentRep,
      currentPacket, currentLength, currentEntries, currentCommit, currentConstraint⟩ :=
    append_receive_retirement_assignment source destination before after states execution
      commitAssignment frame commitHolds valid commitRep request commitPacket log
      commitLength commitEntries commit commitValue sameBootstrap
  have entriesNext : states.middle.entriesDefined.next = before.next + 5 :=
    (fresh_success states.middle.entriesDefined states.middle.commitSignatureFresh
      (before.next + 5) execution.runs.middleRuns.commitSignatureRun).1.symm
  have commitNext : states.middle.commitDefined.next = before.next + 7 :=
    (fresh_success states.middle.commitDefined states.middle.suffix.firstFresh
      (before.next + 7) execution.runs.middleRuns.suffixRuns.firstRun).1.symm
  have assignmentToCurrent : assignment.AgreesBelow before.next currentAssignment :=
    logAgreement.trans
      ((commitAgreement.restrict (by rw [entriesNext]; omega)).trans
        (currentAgreement.restrict (by rw [commitNext]; omega)))
  exact ⟨currentAssignment, assignmentToCurrent, currentHolds, currentRep,
    currentPacket, log, commit, currentLength, currentEntries, currentCommit,
    currentConstraint⟩

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

theorem receive_append_model_complete {width : PNat} [Bootstrap (Fin width)]
    (source destination : Fin width) (before after : Encoding width)
    (run : (receiveAppend source destination).run before = .ok ((), after))
    (assignment : Assignment)
    (holds : Holds before.assertions.toList assignment)
    (valid : ReferencesValid before)
    (frame : NativeArrayVote.Frame (Fin width) Nat) (state : State (Fin width) Nat)
    (columnsRep : FrameColumnsRep assignment before.toColumns frame)
    (modelRep : frame.Rep state)
    (request : AppendEntriesRequest (Fin width) Nat)
    (selected : NativeArrayAppendNetwork.SelectedAppend
      frame source destination request)
    (enabled : CCFRaft.Enabled state (.receive source destination))
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION) :
    exists extended : Assignment,
      assignment.AgreesBelow before.next extended /\
      Holds after.assertions.toList extended /\
      exists written : NativeArrayVote.Frame (Fin width) Nat,
        FrameColumnsRep extended after.toColumns written /\
        written.Rep (CCFRaft.next state (.receive source destination)) := by
  obtain ⟨states, execution⟩ :=
    receive_append_success source destination before after run
  obtain ⟨currentAssignment, currentAgreement, currentHolds, currentRep,
      currentPacket, log, commit, currentLength, currentEntries, currentCommit,
      currentConstraint⟩ :=
    append_receive_current_assignment source destination before after states execution
      assignment holds valid frame state columnsRep modelRep request selected enabled
      sameBootstrap
  obtain ⟨tailAssignment, tailAgreement, tailHolds, tailRep⟩ :=
    append_receive_tail_assignment source destination before after states execution
      currentAssignment frame currentHolds valid currentRep request currentPacket log
      currentLength currentEntries commit currentCommit sameBootstrap currentConstraint
  obtain ⟨extended, finishAgreement, afterHolds, written, writtenRep, writtenModel⟩ :=
    append_receive_finish_assignment source destination before after states execution
      tailAssignment tailHolds valid frame state tailRep modelRep sameBootstrap
  let terms := appendReceiveExecutionTerms before source destination
  have completedShape :=
    retirement_completed_constraints_success before.bootstrap terms.consumes terms.logLength
      terms.logEntries terms.commit terms.current states.middle.suffix.currentAsserted
      states.middle.suffix.completedState (before.next + 12)
      execution.runs.middleRuns.suffixRuns.completedRun
  have currentStart :
      states.middle.suffix.currentAsserted.next = before.next + 12 :=
    completedShape.completedId.symm
  have originalToTail : assignment.AgreesBelow before.next tailAssignment :=
    currentAgreement.trans (tailAgreement.restrict (by rw [currentStart]; omega))
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
