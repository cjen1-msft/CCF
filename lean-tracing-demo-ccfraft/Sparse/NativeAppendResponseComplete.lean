-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendResponseExecution
import Sparse.NativeAppendResponseTermsEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem append_response_complete {width : PNat} [Bootstrap (Fin width)]
    (source destination : Fin width) (before after : Encoding width)
    (run :
      (receiveAppendResponse source destination).run before =
        .ok ((), after))
    (assignment : Assignment)
    (holds : Holds before.assertions.toList assignment)
    (valid : ReferencesValid before)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (response : AppendEntriesResponse (Fin width))
    (selected :
      (frame.queues destination source).peek =
        some (.appendEntriesResponse response))
    (enabled : NativeArrayAppendResponse.enabled frame destination response) :
    exists extended : Assignment,
      assignment.AgreesBelow before.next extended /\
      Holds after.assertions.toList extended /\
      FrameColumnsRep extended after.toColumns
        (NativeArrayAppendResponse.receive frame destination response) := by
  obtain ⟨states, execution⟩ :=
    append_response_success source destination before after run
  let terms := appendResponseExecutionTerms before source destination
  let old := NativeArrayCheckQuorum.get frame.nodes destination
  let best :=
    findHighestPossibleMatch old.log.decode response.lastLogIndex response.term
  have guardHolds :
      Holds (appendResponseGuards before.toColumns source destination) assignment :=
    (append_response_guards_correct assignment before.toColumns frame rep
      source destination).mpr ⟨response, selected, enabled⟩
  have guardedHolds : Holds states.guardsAsserted.assertions.toList assignment :=
    (assert_all_holds
      (appendResponseGuards before.toColumns source destination)
      before states.guardsAsserted execution.runs.guardsRun assignment).mpr
        ⟨holds, guardHolds⟩
  have guardedValid : ReferencesValid states.guardsAsserted :=
    valid.same_references
      (assert_all_success
        (appendResponseGuards before.toColumns source destination)
        before states.guardsAsserted execution.runs.guardsRun).1
  let witnessAssignment := assignment.set .int before.next (best : Int)
  have witnessAgreement :
      assignment.AgreesBelow before.next witnessAssignment :=
    assignment.agrees_below_set before.next .int before.next (best : Int)
      (le_refl _)
  have witnessFrameRep :=
    rep.agrees_below before assignment witnessAssignment frame valid
      witnessAgreement
  have witnessGuardedHolds :
      Holds states.guardsAsserted.assertions.toList witnessAssignment := by
    have same :
        assignment.AgreesBelow states.guardsAsserted.next witnessAssignment := by
      rw [execution.guardsAssertedNext]
      exact witnessAgreement
    exact states.guardsAsserted.holds_agrees_below assignment witnessAssignment
      guardedHolds same
  have witnessFreshHolds :
      Holds states.witnessFresh.assertions.toList witnessAssignment :=
    fresh_holds states.guardsAsserted states.witnessFresh before.next
      execution.runs.witnessRun witnessAssignment witnessGuardedHolds
  have witnessValid : ReferencesValid states.witnessFresh := by
    have shape :=
      fresh_success states.guardsAsserted states.witnessFresh before.next
        execution.runs.witnessRun
    cases guardedValid
    constructor <;> simp only [shape.2.1, shape.2.2.2.1] <;> omega
  have nonempty : 0 < (frame.queues destination source).length := by
    by_contra notPositive
    have empty : (frame.queues destination source).length = 0 := by omega
    simp [NativeArrayQueue.Queue.peek, empty] at selected
  have samePacket :=
    queue_head_packet_term_correct witnessAssignment before.toColumns frame
      witnessFrameRep source destination nonempty
  have headValue :
      (frame.queues destination source).cells
          (frame.queues destination source).head =
        .appendEntriesResponse response := by
    simpa only [NativeArrayQueue.Queue.peek, if_pos nonempty,
      Option.some.injEq] using selected
  have selectedPacket :
      terms.packet.eval witnessAssignment Locals.empty =
        packetValue (.appendEntriesResponse response) := by
    simpa [terms, appendResponseExecutionTerms, headValue] using samePacket
  have oldRep : terms.old.Rep witnessAssignment old := by
    simpa [terms, old, appendResponseExecutionTerms] using
      node_row_snapshot_rep witnessAssignment before.toColumns frame.nodes
        witnessFrameRep.nodes destination
  have sameWitness :
      terms.witness.eval witnessAssignment Locals.empty = (best : Int) := by
    simp [terms, appendResponseExecutionTerms, witnessAssignment,
      Assignment.set, Term.eval]
  have scanAccepted : terms.scan.eval witnessAssignment Locals.empty = true := by
    simpa [terms, appendResponseExecutionTerms] using
      append_response_scan_constraint_complete witnessAssignment terms.old old
        oldRep terms.packet response selectedPacket terms.witness
        (by simpa [best] using sameWitness)
  have scanHolds : Holds states.scanAsserted.assertions.toList witnessAssignment :=
    assertion_extension_holds terms.scan states.witnessFresh states.scanAsserted
      execution.runs.scanRun witnessAssignment witnessFreshHolds scanAccepted
  have scanValid : ReferencesValid states.scanAsserted :=
    witnessValid.same_references
      (assertion_success terms.scan states.witnessFresh states.scanAsserted
        execution.runs.scanRun).1
  let output :=
    if (frame.nodes response.source).isSome then
      NativeArrayAppendResponse.nextRow old response
    else old
  have outputRep : terms.values.Rep witnessAssignment output := by
    simpa [terms, old, output, appendResponseExecutionTerms] using
      append_response_row_terms_rep witnessAssignment before.toColumns frame
        witnessFrameRep source destination response selected terms.witness
        (by simpa [best] using sameWitness)
  have scanFrameRep :
      FrameColumnsRep witnessAssignment states.scanAsserted.toColumns frame := by
    rw [execution.scanAssertedColumns]
    exact witnessFrameRep
  let rowFrame : NativeArrayVote.Frame (Fin width) Nat :=
    { frame with nodes := Function.update frame.nodes destination (some output) }
  obtain ⟨rowAssignment, rowAgreement, rowHolds, rowRep⟩ :=
    write_node_row_complete destination terms.values output states.scanAsserted
      states.rowWritten execution.runs.rowRun witnessAssignment scanHolds frame
      scanFrameRep outputRep scanValid
  have rowValid :=
    write_node_row_references destination terms.values states.scanAsserted
      states.rowWritten execution.runs.rowRun scanValid
  obtain ⟨extended, popAgreement, afterHolds, afterRep⟩ :=
    pop_queue_complete source destination states.rowWritten after
      execution.runs.popRun rowAssignment rowHolds rowFrame
      (by simpa [rowFrame] using rowRep) rowValid
  have agreement : assignment.AgreesBelow before.next extended := by
    have witnessToRow :
        witnessAssignment.AgreesBelow states.scanAsserted.next rowAssignment :=
      rowAgreement
    have originalToRow :
        assignment.AgreesBelow before.next rowAssignment :=
      witnessAgreement.trans
        (witnessToRow.restrict (by rw [execution.scanAssertedNext]; omega))
    exact originalToRow.trans
      (popAgreement.restrict (by rw [execution.rowWrittenNext]; omega))
  have responseSource : response.source = source := by
    have headSource := rep.queue_head_source source destination nonempty
    have packetSource :
        (Message.appendEntriesResponse response :
          Message (Fin width) Nat).source = source := by
      simpa only [headValue] using headSource
    simpa only [NativeArrayAppendResponse.packet_source] using packetSource
  refine ⟨extended, agreement, afterHolds, ?_⟩
  rw [NativeArrayAppendResponse.receive_eq_write_pop frame destination response
    enabled.1]
  simpa only [rowFrame, output, old, responseSource] using afterRep

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
