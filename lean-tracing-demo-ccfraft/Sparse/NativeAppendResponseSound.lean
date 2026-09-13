-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendResponseExecution
import Sparse.NativeAppendResponseTermsEncoding
import Sparse.NativeArrayVoteReceive

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem append_response_frame_sound {width : PNat}
    [Bootstrap (Fin width)] (source destination : Fin width)
    (before after : Encoding width)
    (run :
      (receiveAppendResponse source destination).run before =
        .ok ((), after))
    (assignment : Assignment)
    (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame) :
    exists response : AppendEntriesResponse (Fin width),
      (frame.queues destination source).peek =
          some (.appendEntriesResponse response) /\
        NativeArrayAppendResponse.enabled frame destination response /\
        FrameColumnsRep assignment after.toColumns
          (NativeArrayAppendResponse.receive frame destination response) := by
  obtain ⟨states, execution⟩ :=
    append_response_success source destination before after run
  let terms := appendResponseExecutionTerms before source destination
  have rowHolds :=
    ((pop_queue_holds destination source states.rowWritten after
      execution.runs.popRun assignment).mp holds).1
  have scanHolds :=
    write_node_row_prior_holds destination terms.values states.scanAsserted
      states.rowWritten execution.runs.rowRun assignment rowHolds
  have scanFacts :=
    assertion_holds terms.scan states.witnessFresh states.scanAsserted
      execution.runs.scanRun assignment scanHolds
  have guardHolds :=
    fresh_prior_holds states.guardsAsserted states.witnessFresh before.next
      execution.runs.witnessRun assignment scanFacts.1
  have guards :=
    ((assert_all_holds
      (appendResponseGuards before.toColumns source destination)
      before states.guardsAsserted execution.runs.guardsRun assignment).mp
        guardHolds).2
  obtain ⟨response, selected, enabled⟩ :=
    (append_response_guards_correct assignment before.toColumns frame rep
      source destination).mp guards
  have nonempty : 0 < (frame.queues destination source).length := by
    by_contra notPositive
    have empty : (frame.queues destination source).length = 0 := by omega
    simp [NativeArrayQueue.Queue.peek, empty] at selected
  have head :
      (frame.queues destination source).cells
          (frame.queues destination source).head =
        .appendEntriesResponse response := by
    simpa only [NativeArrayQueue.Queue.peek, if_pos nonempty,
      Option.some.injEq] using selected
  have selectedPacket :
      terms.packet.eval assignment Locals.empty =
        packetValue (.appendEntriesResponse response) := by
    have packetValue :=
      queue_head_packet_term_correct assignment before.toColumns frame rep
        source destination nonempty
    rw [head] at packetValue
    simpa only [terms, appendResponseExecutionTerms] using packetValue
  let old := NativeArrayCheckQuorum.get frame.nodes destination
  have oldRep : terms.old.Rep assignment old := by
    simpa only [terms, appendResponseExecutionTerms, old] using
      node_row_snapshot_rep assignment before.toColumns frame.nodes rep.nodes
        destination
  obtain ⟨possible, possibleValue, possibleCorrect⟩ :=
    append_response_scan_constraint_sound assignment terms.old old oldRep
      terms.packet response selectedPacket terms.witness
      (by simpa only [terms, appendResponseExecutionTerms] using scanFacts.2)
  have witnessValue :
      terms.witness.eval assignment Locals.empty =
        (findHighestPossibleMatch old.log.decode response.lastLogIndex
          response.term : Int) := by
    rw [possibleValue, possibleCorrect]
  let row :=
    if (frame.nodes response.source).isSome then
      NativeArrayAppendResponse.nextRow old response
    else old
  have valuesRep : terms.values.Rep assignment row := by
    simpa only [terms, appendResponseExecutionTerms, row, old] using
      append_response_row_terms_rep assignment before.toColumns frame rep
        source destination response selected terms.witness witnessValue
  have member :
      (Message.appendEntriesResponse response : Message (Fin width) Nat) ∈
        (frame.queues destination source).decode := by
    rw [(frame.queues destination source).head_tail nonempty, head]
    simp
  have responseSource : response.source = source := by
    simpa only [NativeArrayAppendResponse.packet_source] using
      rep.valid destination source
        (Message.appendEntriesResponse response : Message (Fin width) Nat) member
  subst source
  have scanRep :
      FrameColumnsRep assignment states.scanAsserted.toColumns frame := by
    rw [execution.scanAssertedColumns]
    exact rep
  have writtenRep :=
    write_node_row_frame_sound destination terms.values row states.scanAsserted
      states.rowWritten execution.runs.rowRun assignment rowHolds frame scanRep
      valuesRep
  let writtenFrame : NativeArrayVote.Frame (Fin width) Nat :=
    { frame with
      nodes := Function.update frame.nodes destination (some row) }
  have finalRep :=
    pop_queue_frame_success response.source destination states.rowWritten after
      execution.runs.popRun assignment holds writtenFrame
      (by simpa only [writtenFrame] using writtenRep)
  refine ⟨response, selected, enabled, ?_⟩
  rw [NativeArrayAppendResponse.receive_eq_write_pop frame destination response
    enabled.1]
  simpa only [writtenFrame, row, old] using finalRep

theorem append_response_model_sound {width : PNat}
    [Bootstrap (Fin width)] (source destination : Fin width)
    (before after : Encoding width)
    (run :
      (receiveAppendResponse source destination).run before =
        .ok ((), after))
    (assignment : Assignment)
    (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (state : State (Fin width) Nat)
    (columnsRep : FrameColumnsRep assignment before.toColumns frame)
    (modelRep : frame.Rep state) :
    CCFRaft.Enabled state (.receive source destination) /\
      exists response : AppendEntriesResponse (Fin width),
        FrameColumnsRep assignment after.toColumns
            (NativeArrayAppendResponse.receive frame destination response) /\
          (NativeArrayAppendResponse.receive frame destination response).Rep
            (CCFRaft.next state (.receive source destination)) := by
  obtain ⟨response, selected, nativeEnabled, finalColumns⟩ :=
    append_response_frame_sound source destination before after run assignment
      holds frame columnsRep
  obtain ⟨remaining, taken⟩ :=
    NativeArrayVoteReceive.selected_model_take frame state modelRep source
      destination (.appendEntriesResponse response) selected
  have responseSource : response.source = source :=
    (NativeArrayAppendResponse.packet_source response).symm.trans
      (Sparse.Queue.take_some_spec source (state.network destination)
        (.appendEntriesResponse response) remaining taken).1
  subst source
  have enabled :
      CCFRaft.Enabled state (.receive response.source destination) :=
    (NativeArrayAppendResponse.enabled_correct frame state modelRep destination
      response remaining taken).mp nativeEnabled
  have finalModel :=
    NativeArrayAppendResponse.receive_rep frame state modelRep destination
      response remaining taken nativeEnabled
  exact ⟨enabled, response, finalColumns, finalModel⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
