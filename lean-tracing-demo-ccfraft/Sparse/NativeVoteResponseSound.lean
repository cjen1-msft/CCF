-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeVoteResponseExecution
import Sparse.NativeVoteResponseTermsEncoding
import Sparse.NativeArrayVoteReceive

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem vote_response_frame_sound {width : PNat} (preVote : Bool)
    (source destination : Fin width) (before after : Encoding width)
    (run :
      (receiveVoteResponse preVote source destination).run before =
        .ok ((), after))
    (assignment : Assignment)
    (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame) :
    exists response : RequestVoteResponse (Fin width),
      (frame.queues destination source).peek =
          some (NativeArrayVoteResponse.packet preVote response) /\
        NativeArrayVoteResponse.enabled frame preVote destination response /\
        FrameColumnsRep assignment after.toColumns
          (NativeArrayVoteResponse.receive frame preVote destination response) := by
  obtain ⟨states, execution⟩ :=
    vote_response_success preVote source destination before after run
  have rowHolds :=
    ((pop_queue_holds destination source states.rowWritten after
      execution.runs.popRun assignment).mp holds).1
  have guardedHolds :=
    write_node_row_prior_holds destination
      (voteResponseRowTerms before.toColumns preVote source destination)
      states.guardsAsserted states.rowWritten execution.runs.rowRun assignment
      rowHolds
  have guards :=
    ((assert_all_holds
      (voteResponseGuards before.toColumns preVote source destination)
      before states.guardsAsserted execution.runs.guardsRun assignment).mp
        guardedHolds).2
  obtain ⟨response, selected, enabled⟩ :=
    (vote_response_guards_correct assignment before.toColumns frame rep
      preVote source destination).mp guards
  have nonempty : 0 < (frame.queues destination source).length := by
    by_contra notPositive
    have empty : (frame.queues destination source).length = 0 := by omega
    simp [NativeArrayQueue.Queue.peek, empty] at selected
  have head :
      (frame.queues destination source).cells
          (frame.queues destination source).head =
        NativeArrayVoteResponse.packet preVote response := by
    simpa only [NativeArrayQueue.Queue.peek, if_pos nonempty,
      Option.some.injEq] using selected
  have member :
      NativeArrayVoteResponse.packet preVote response ∈
        (frame.queues destination source).decode := by
    rw [(frame.queues destination source).head_tail nonempty, head]
    simp
  have responseSource : response.source = source := by
    simpa only [NativeArrayVoteResponse.packet_source] using
      rep.valid destination source
        (NativeArrayVoteResponse.packet preVote response) member
  subst source
  let row :=
    if (frame.nodes response.source).isSome then
      NativeArrayVoteResponse.nextRow
        (NativeArrayCheckQuorum.get frame.nodes destination) preVote response
    else NativeArrayCheckQuorum.get frame.nodes destination
  have valuesRep :
      (voteResponseRowTerms before.toColumns preVote response.source destination).Rep
        assignment row := by
    simpa only [row] using
      vote_response_row_terms_rep assignment before.toColumns frame rep preVote
        response.source destination response selected
  have guardedRep :
      FrameColumnsRep assignment states.guardsAsserted.toColumns frame := by
    rw [execution.guardsAssertedColumns]
    exact rep
  have writtenRep :=
    write_node_row_frame_sound destination
      (voteResponseRowTerms before.toColumns preVote response.source destination)
      row states.guardsAsserted states.rowWritten execution.runs.rowRun assignment
      rowHolds frame guardedRep valuesRep
  let writtenFrame : NativeArrayVote.Frame (Fin width) Nat :=
    { frame with
      nodes := Function.update frame.nodes destination (some row) }
  have finalRep :=
    pop_queue_frame_success response.source destination states.rowWritten after
      execution.runs.popRun assignment holds writtenFrame
      (by simpa only [writtenFrame] using writtenRep)
  refine ⟨response, selected, enabled, ?_⟩
  rw [NativeArrayVoteResponse.receive_eq_write_pop frame preVote destination response
    enabled.1]
  simpa only [writtenFrame, row] using finalRep

theorem vote_response_model_sound {width : PNat} [Bootstrap (Fin width)]
    (preVote : Bool) (source destination : Fin width)
    (before after : Encoding width)
    (run :
      (receiveVoteResponse preVote source destination).run before =
        .ok ((), after))
    (assignment : Assignment)
    (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (state : State (Fin width) Nat)
    (columnsRep : FrameColumnsRep assignment before.toColumns frame)
    (modelRep : frame.Rep state) :
    CCFRaft.Enabled state (.receive source destination) /\
      exists response : RequestVoteResponse (Fin width),
        FrameColumnsRep assignment after.toColumns
            (NativeArrayVoteResponse.receive frame preVote destination response) /\
          (NativeArrayVoteResponse.receive frame preVote destination response).Rep
            (CCFRaft.next state (.receive source destination)) := by
  obtain ⟨response, selected, nativeEnabled, finalColumns⟩ :=
    vote_response_frame_sound preVote source destination before after run
      assignment holds frame columnsRep
  obtain ⟨remaining, taken⟩ :=
    NativeArrayVoteReceive.selected_model_take frame state modelRep source
      destination (NativeArrayVoteResponse.packet preVote response) selected
  have responseSource : response.source = source :=
    (NativeArrayVoteResponse.packet_source preVote response).symm.trans
      (Sparse.Queue.take_some_spec source (state.network destination)
        (NativeArrayVoteResponse.packet preVote response) remaining taken).1
  subst source
  have enabled : CCFRaft.Enabled state (.receive response.source destination) :=
    (NativeArrayVoteResponse.enabled_correct frame state modelRep preVote
      destination response remaining taken).mp nativeEnabled
  have finalModel :=
    NativeArrayVoteResponse.receive_rep frame state modelRep preVote destination
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
