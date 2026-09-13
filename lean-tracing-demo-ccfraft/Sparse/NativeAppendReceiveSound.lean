-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendReceiveExecution
import Sparse.NativeAppendReceiveLocalEncoding
import Sparse.NativeAppendReceiveFrameEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem append_receive_execution_model_sound {width : PNat} [Bootstrap (Fin width)]
    (source destination : Fin width) (before after : Encoding width)
    (states : AppendReceivePrefixStates width)
    (execution : AppendReceiveExecutionResult source destination before after states)
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (constraints : AppendReceivePrefixConstraints before source destination
      (appendReceiveExecutionTerms before source destination) assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat) (state : State (Fin width) Nat)
    (columnsRep : FrameColumnsRep assignment before.toColumns frame)
    (modelRep : frame.Rep state)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION) :
    exists request : AppendEntriesRequest (Fin width) Nat,
      NativeArrayAppendNetwork.SelectedAppend frame source destination request /\
      CCFRaft.Enabled state (.receive source destination) /\
      exists written : NativeArrayVote.Frame (Fin width) Nat,
        FrameColumnsRep assignment after.toColumns written /\
        written.Rep (CCFRaft.next state (.receive source destination)) := by
  let terms := appendReceiveExecutionTerms before source destination
  obtain ⟨allocated, nonempty, request, selected, recipient, action⟩ :=
    (append_receive_guards_correct assignment before.toColumns frame columnsRep
      source destination).mp constraints.guards
  have sourceHeader :=
    NativeArrayAppendReceiveGuard.selected_append_source frame state modelRep
      source destination request selected
  have selectedAppend : NativeArrayAppendNetwork.SelectedAppend
      frame source destination request :=
    ⟨selected, allocated, sourceHeader, recipient⟩
  have enabled : CCFRaft.Enabled state (.receive source destination) :=
    (NativeArrayAppendReceiveGuard.enabled_correct frame state modelRep source destination
      request (NativeArrayCheckQuorum.Log.ofList request.entries) selected (by simp)).mpr
      ⟨allocated, recipient, action⟩
  have headValue :
      (frame.queues destination source).cells (frame.queues destination source).head =
        .appendEntriesRequest request := by
    simpa only [NativeArrayQueue.Queue.peek, if_pos nonempty, Option.some.injEq]
      using selected
  have samePacket : terms.packet.eval assignment Locals.empty =
      packetValue (.appendEntriesRequest request) := by
    change assignment (packetTy width) before.next = _
    rw [constraints.packet,
      queue_head_packet_term_correct assignment before.toColumns frame columnsRep
        source destination nonempty, headValue]
  have localEnabled :
      (Term.or terms.branches.stepDown terms.branches.handles).eval
        assignment Locals.empty = true := by
    change (terms.branches.stepDown.eval assignment Locals.empty ||
      terms.branches.handles.eval assignment Locals.empty) = true
    rw [Bool.or_eq_true]
    exact action.imp
      (append_receive_step_down_correct assignment before.toColumns frame.nodes
        columnsRep.nodes destination terms.packet request samePacket).mpr
      (append_receive_handles_correct assignment before.toColumns frame.nodes
        columnsRep.nodes destination terms.packet request
        (NativeArrayCheckQuorum.Log.ofList request.entries) samePacket (by simp)).mpr
  obtain ⟨candidate, output, response, candidateRep, outputRep, responseValue,
    responseSource, responseDestination, stepDownCorrect, consumeCorrect, _, _⟩ :=
    append_receive_local_correct assignment before.toColumns frame.nodes columnsRep.nodes
      source destination terms.packet request samePacket sourceHeader recipient
      before.bootstrap sameBootstrap terms.grows terms.spliced terms.logEntries
      terms.logLength terms.commitSignature terms.commit terms.first terms.retirement
      terms.signature terms.retired terms.best constraints.grows constraints.splice
      constraints.length constraints.entries constraints.boundedSignature constraints.commit
      constraints.refresh constraints.nack localEnabled
  let step := terms.branches.stepDown.eval assignment Locals.empty
  let completed := decodeBits (terms.completed.eval assignment Locals.empty)
  have sameCompleted : terms.completed.eval assignment Locals.empty =
      encodeBits completed := (encode_decode_bits _).symm
  have completedCorrect : step = false ->
      completed = retirementCompletedNodes candidate.log.decode candidate.commit := by
    intro stepFalse
    have consumesTrue : terms.consumes.eval assignment Locals.empty = true := by
      change (!step) = true
      rw [stepFalse]
      rfl
    have currentAccepted :
        (currentConfigurationIndexTerm width terms.logLength terms.logEntries
          terms.commit terms.current).eval assignment Locals.empty = true :=
      (implies_eval terms.consumes _ assignment Locals.empty).mp
        constraints.current consumesTrue
    have witnesses := retirement_completed_peer_constraints_sound before.bootstrap
      terms.consumes terms.logEntries (logRangeMinTerm terms.commit terms.logLength)
      terms.current
      (currentConfigurationMembersTerm width before.bootstrap terms.logEntries terms.current)
      (before.next + 12) (before.next + 12 + 1) (List.finRange width)
      assignment constraints.completed consumesTrue
    have allWitnesses : forall peer : Fin width, exists first retirement retired : Int,
        (retirementIndexTerm width before.bootstrap
          (logRangeMinTerm terms.commit terms.logLength) terms.logEntries peer
          (.integer first) (.integer retirement)).eval assignment Locals.empty = true /\
        (retiredRecordTerm width (logRangeMinTerm terms.commit terms.logLength)
          terms.logEntries peer (.integer retired)).eval assignment Locals.empty = true /\
        (Term.bit terms.completed peer).eval assignment Locals.empty =
          (retirementCompletedMemberTerm peer terms.current
            (currentConfigurationMembersTerm width before.bootstrap terms.logEntries
              terms.current)
            (.integer first) (.integer retirement) (.integer retired)).eval
              assignment Locals.empty := by
      intro peer
      exact witnesses peer (List.mem_finRange peer)
    choose first retirement retired accepted using allWitnesses
    have bitsCorrect := retirement_completed_bits_constraints_correct assignment
      Locals.empty before.bootstrap terms.logLength terms.logEntries terms.commit
      terms.current (fun peer => .integer (first peer))
      (fun peer => .integer (retirement peer)) (fun peer => .integer (retired peer))
      terms.completed candidate.log candidate.commit candidateRep.logLength
      candidateRep.commit sameBootstrap candidateRep.logEntries currentAccepted
      (fun peer => (accepted peer).1) (fun peer => (accepted peer).2.1)
      (fun peer => (accepted peer).2.2)
    exact (congrArg decodeBits bitsCorrect).trans (decode_encode_bits _)
  have writerRep : FrameColumnsRep assignment
      states.middle.suffix.writerBefore.toColumns frame := by
    rw [execution.writerColumns]
    exact columnsRep
  obtain ⟨writtenRep, writtenModel⟩ :=
    append_receive_writes_model_sound source destination terms.branches.stepDown
      terms.values output terms.response response terms.completed completed
      states.middle.suffix.writerBefore after execution.runs.middleRuns.suffixRuns.writeRun
      assignment holds frame state writerRep modelRep outputRep step rfl responseValue
      responseSource responseDestination sameCompleted request selectedAppend candidate
      stepDownCorrect (fun stepFalse =>
        ⟨(consumeCorrect stepFalse).1, (consumeCorrect stepFalse).2,
          completedCorrect stepFalse⟩)
  exact ⟨request, selectedAppend, enabled, _, writtenRep, writtenModel⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
