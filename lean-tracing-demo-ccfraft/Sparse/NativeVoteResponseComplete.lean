-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeVoteResponseExecution
import Sparse.NativeVoteResponseTermsEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem vote_response_complete {width : PNat} (preVote : Bool)
    (source destination : Fin width) (before after : Encoding width)
    (run :
      (receiveVoteResponse preVote source destination).run before =
        .ok ((), after))
    (assignment : Assignment)
    (holds : Holds before.assertions.toList assignment)
    (valid : ReferencesValid before)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (response : RequestVoteResponse (Fin width))
    (selected :
      (frame.queues destination source).peek =
        some (NativeArrayVoteResponse.packet preVote response))
    (enabled : NativeArrayVoteResponse.enabled frame preVote destination response) :
    exists extended : Assignment,
      assignment.AgreesBelow before.next extended /\
      Holds after.assertions.toList extended /\
      FrameColumnsRep extended after.toColumns
        (NativeArrayVoteResponse.receive frame preVote destination response) := by
  obtain ⟨states, execution⟩ :=
    vote_response_success preVote source destination before after run
  have guardHolds :
      Holds (voteResponseGuards before.toColumns preVote source destination)
        assignment :=
    (vote_response_guards_correct assignment before.toColumns frame rep preVote
      source destination).mpr ⟨response, selected, enabled⟩
  have guardedHolds : Holds states.guardsAsserted.assertions.toList assignment :=
    (assert_all_holds
      (voteResponseGuards before.toColumns preVote source destination)
      before states.guardsAsserted execution.runs.guardsRun assignment).mpr
        ⟨holds, guardHolds⟩
  have guardedRep :
      FrameColumnsRep assignment states.guardsAsserted.toColumns frame := by
    rw [execution.guardsAssertedColumns]
    exact rep
  have guardedValid : ReferencesValid states.guardsAsserted :=
    valid.same_references
      (assert_all_success
        (voteResponseGuards before.toColumns preVote source destination)
        before states.guardsAsserted execution.runs.guardsRun).1
  let output :=
    if (frame.nodes response.source).isSome then
      NativeArrayVoteResponse.nextRow
        (NativeArrayCheckQuorum.get frame.nodes destination) preVote response
    else NativeArrayCheckQuorum.get frame.nodes destination
  have outputRep :
      (voteResponseRowTerms before.toColumns preVote source destination).Rep
        assignment output := by
    simpa [output] using
      vote_response_row_terms_rep assignment before.toColumns frame rep preVote
        source destination response selected
  let rowFrame : NativeArrayVote.Frame (Fin width) Nat :=
    { frame with nodes := Function.update frame.nodes destination (some output) }
  obtain ⟨rowAssignment, rowAgreement, rowHolds, rowRep⟩ :=
    write_node_row_complete destination
      (voteResponseRowTerms before.toColumns preVote source destination) output
      states.guardsAsserted states.rowWritten execution.runs.rowRun assignment
      guardedHolds frame guardedRep outputRep guardedValid
  have rowValid :=
    write_node_row_references destination
      (voteResponseRowTerms before.toColumns preVote source destination)
      states.guardsAsserted states.rowWritten execution.runs.rowRun guardedValid
  obtain ⟨extended, popAgreement, afterHolds, afterRep⟩ :=
    pop_queue_complete source destination states.rowWritten after execution.runs.popRun
      rowAssignment rowHolds rowFrame (by simpa [rowFrame] using rowRep) rowValid
  have agreement : assignment.AgreesBelow before.next extended := by
    have assignmentToRow :
        assignment.AgreesBelow before.next rowAssignment := by
      simpa only [execution.guardsAssertedNext] using rowAgreement
    exact assignmentToRow.trans
      (popAgreement.restrict (by rw [execution.rowWrittenNext]; omega))
  have nonempty : 0 < (frame.queues destination source).length := by
    by_contra notPositive
    have empty : (frame.queues destination source).length = 0 := by omega
    simp [NativeArrayQueue.Queue.peek, empty] at selected
  have headValue :
      (frame.queues destination source).cells
          (frame.queues destination source).head =
        NativeArrayVoteResponse.packet preVote response := by
    simpa only [NativeArrayQueue.Queue.peek, if_pos nonempty,
      Option.some.injEq] using selected
  have responseSource : response.source = source := by
    have headSource := rep.queue_head_source source destination nonempty
    have packetSource :
        (NativeArrayVoteResponse.packet (T := Nat) preVote response).source =
          source := by
      simpa only [headValue] using headSource
    simpa only [NativeArrayVoteResponse.packet_source] using packetSource
  refine ⟨extended, agreement, afterHolds, ?_⟩
  rw [NativeArrayVoteResponse.receive_eq_write_pop frame preVote destination
    response enabled.1]
  simpa only [rowFrame, output, responseSource] using afterRep

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
