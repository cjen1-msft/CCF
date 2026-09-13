-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendReceiveExecution
import Sparse.NativeAppendReceiveCandidateEncoding
import Sparse.NativeLogSpliceAssignment

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem append_receive_log_assignment {width : PNat} [Bootstrap (Fin width)]
    (source destination : Fin width) (before after : Encoding width)
    (states : AppendReceivePrefixStates width)
    (execution : AppendReceiveExecutionResult source destination before after states)
    (assignment : Assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (beforeHolds : Holds before.assertions.toList assignment)
    (valid : ReferencesValid before)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (guards : Holds (appendReceiveGuards before.toColumns source destination) assignment)
    (request : AppendEntriesRequest (Fin width) Nat)
    (samePacket :
      (queueHeadPacketTerm before.toColumns source destination).eval assignment Locals.empty =
        packetValue (.appendEntriesRequest request)) :
    exists extended : Assignment,
      assignment.AgreesBelow before.next extended /\
        Holds states.middle.entriesDefined.assertions.toList extended /\
        FrameColumnsRep extended before.toColumns frame /\
        (appendReceiveExecutionTerms before source destination).packet.eval
            extended Locals.empty =
          packetValue (.appendEntriesRequest request) /\
        let terms := appendReceiveExecutionTerms before source destination
        let payload := NativeArrayCheckQuorum.Log.ofList request.entries
        let row := NativeArrayCheckQuorum.get frame.nodes destination
        let candidate := NativeArrayAppendCandidate.candidateLog row request payload
          (terms.branches.acceptable.eval extended Locals.empty)
          (terms.branches.alreadyDone.eval extended Locals.empty)
        terms.logLength.eval extended Locals.empty = (candidate.length : Int) /\
          forall index, index < candidate.length ->
            modelEntry (terms.logEntries.eval extended Locals.empty (index : Int)) =
              candidate.entries index := by
  let terms := appendReceiveExecutionTerms before source destination
  let runs := execution.runs
  let middle := states.middle
  let middleRuns := runs.middleRuns
  have guardShape :=
    (assert_all_success (appendReceiveGuards before.toColumns source destination)
      before states.guarded runs.guardsRun).1
  have guardedHolds : Holds states.guarded.assertions.toList assignment :=
    (assert_all_holds _ before states.guarded runs.guardsRun assignment).mpr
      ⟨beforeHolds, guards⟩
  obtain ⟨packetAssignment, packetAgreement, packetHolds⟩ :=
    define_extension (queueHeadPacketTerm before.toColumns source destination)
      states.guarded states.packetDefined before.next runs.packetRun assignment guardedHolds
  obtain ⟨_, packetNext, _, _, packetClauses⟩ :=
    define_success (queueHeadPacketTerm before.toColumns source destination)
      states.guarded states.packetDefined before.next runs.packetRun
  obtain ⟨_, splicedNext, _, _, splicedClauses⟩ :=
    fresh_success states.packetDefined states.splicedFresh (before.next + 1)
      runs.splicedRun
  have packetDefinedNext : states.packetDefined.next = before.next + 1 := by
    rw [packetNext, guardShape.next]
  have splicedFreshNext : states.splicedFresh.next = before.next + 2 := by
    rw [splicedNext, packetDefinedNext]
  have originalToPacket : assignment.AgreesBelow before.next packetAssignment := by
    simpa only [guardShape.next] using packetAgreement
  have packetRep :=
    rep.agrees_below before assignment packetAssignment frame valid originalToPacket
  have packetBinding :
      packetAssignment (packetTy width) before.next =
        (queueHeadPacketTerm before.toColumns source destination).eval
          packetAssignment Locals.empty := by
    apply definition_clause_binding packetHolds
    rw [packetClauses, Array.toList_push]
    simp
  have queueKnown :
      (queueHeadPacketTerm before.toColumns source destination :
        Expr (packetTy width)).symbols.all
        (fun symbol => symbol.2 < before.next) = true := by
    simpa only [guardShape.next] using
      define_known (queueHeadPacketTerm before.toColumns source destination)
        states.guarded states.packetDefined before.next runs.packetRun
  have queueSame :
      (queueHeadPacketTerm before.toColumns source destination :
        Expr (packetTy width)).eval
          assignment Locals.empty =
        (queueHeadPacketTerm before.toColumns source destination :
          Expr (packetTy width)).eval
          packetAssignment Locals.empty :=
    (queueHeadPacketTerm before.toColumns source destination :
      Expr (packetTy width)).eval_agrees_below
      assignment packetAssignment Locals.empty before.next
      (fun symbol member => by
        simpa using List.all_eq_true.mp queueKnown symbol member)
      originalToPacket
  have selectedPacket :
      terms.packet.eval packetAssignment Locals.empty =
        packetValue (.appendEntriesRequest request) := by
    calc
      terms.packet.eval packetAssignment Locals.empty =
          (queueHeadPacketTerm before.toColumns source destination).eval
            packetAssignment Locals.empty := by
              simpa [terms, appendReceiveExecutionTerms, Term.eval] using packetBinding
      _ = (queueHeadPacketTerm before.toColumns source destination).eval
            assignment Locals.empty := queueSame.symm
      _ = packetValue (.appendEntriesRequest request) := samePacket
  let payload := NativeArrayCheckQuorum.Log.ofList request.entries
  let row := NativeArrayCheckQuorum.get frame.nodes destination
  have oldRep :=
    node_row_snapshot_rep packetAssignment before.toColumns frame.nodes packetRep.nodes destination
  have payloadValue :=
    append_request_payload_term_correct terms.packet packetAssignment Locals.empty request
      selectedPacket
  have previousValue :
      terms.payload.fst.eval packetAssignment Locals.empty = (request.prevLogIndex : Int) := by
    simpa [terms, appendReceiveExecutionTerms, Term.eval] using congrArg Prod.fst payloadValue
  obtain ⟨_, payloadLengthValue, payloadEntriesValue⟩ :=
    append_request_log_term_correct terms.packet packetAssignment Locals.empty request payload
      selectedPacket (by exact (NativeArrayCheckQuorum.Log.decode_ofList request.entries).symm)
  have oldLengthBounded :
      terms.old.logLength.symbols.all
        (fun symbol => symbol.2 < states.packetDefined.next) = true := by
    rw [List.all_eq_true]
    intro symbol member
    rw [packetDefinedNext]
    simp only [decide_eq_true_eq]
    simp only [terms, appendReceiveExecutionTerms, nodeRowSnapshot, NativeEncode.length,
      read, allocated, Term.symbols, List.append_nil, List.mem_append,
      List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl
    · exact Nat.lt_succ_of_lt valid.allocated
    · exact Nat.lt_succ_of_lt valid.logLength
  have oldEntriesBounded :
      terms.old.logEntries.symbols.all
        (fun symbol => symbol.2 < states.packetDefined.next) = true := by
    rw [List.all_eq_true]
    intro symbol member
    rw [packetDefinedNext]
    simp only [decide_eq_true_eq]
    simp only [terms, appendReceiveExecutionTerms, nodeRowSnapshot, Term.symbols,
      List.append_nil, List.mem_cons, List.not_mem_nil, or_false] at member
    subst symbol
    exact Nat.lt_succ_of_lt valid.logEntries
  have payloadLengthBounded :
      terms.payload.snd.snd.snd.fst.symbols.all
        (fun symbol => symbol.2 < states.packetDefined.next) = true := by
    rw [List.all_eq_true]
    intro symbol member
    rw [packetDefinedNext]
    simp only [decide_eq_true_eq]
    simp only [terms, appendReceiveExecutionTerms, appendRequestPayloadTerm, Term.symbols,
      List.append_nil, List.mem_cons, List.not_mem_nil, or_false] at member
    subst symbol
    omega
  have payloadEntriesBounded :
      terms.payload.snd.snd.snd.snd.symbols.all
        (fun symbol => symbol.2 < states.packetDefined.next) = true := by
    rw [List.all_eq_true]
    intro symbol member
    rw [packetDefinedNext]
    simp only [decide_eq_true_eq]
    simp only [terms, appendReceiveExecutionTerms, appendRequestPayloadTerm, Term.symbols,
      List.append_nil, List.mem_cons, List.not_mem_nil, or_false] at member
    subst symbol
    omega
  have previousBounded :
      terms.payload.fst.symbols.all
        (fun symbol => symbol.2 < states.packetDefined.next) = true := by
    rw [List.all_eq_true]
    intro symbol member
    rw [packetDefinedNext]
    simp only [decide_eq_true_eq]
    simp only [terms, appendReceiveExecutionTerms, appendRequestPayloadTerm, Term.symbols,
      List.append_nil, List.mem_cons, List.not_mem_nil, or_false] at member
    subst symbol
    omega
  let tail : Int -> (entryTy width).denote :=
    fun index => packetAssignment (.array .int (entryTy width)) (before.next + 1) index
  obtain ⟨spliceAssignment, spliceAgreement, spliceBaseHolds, spliceOutput, _⟩ :=
    log_splice_assignment states.packetDefined packetAssignment packetHolds
      terms.old.logLength terms.old.logEntries terms.payload.snd.snd.snd.fst
      terms.payload.snd.snd.snd.snd terms.payload.fst row.log.length payload.length
      request.prevLogIndex tail oldLengthBounded oldEntriesBounded payloadLengthBounded
      payloadEntriesBounded previousBounded oldRep.logLength payloadLengthValue previousValue
  have splicedHolds : Holds states.splicedFresh.assertions.toList spliceAssignment := by
    rw [splicedClauses]
    exact spliceBaseHolds
  obtain ⟨growsAssignment, growsAgreement, growsHolds⟩ :=
    define_extension (.and terms.branches.acceptable (.not terms.branches.alreadyDone))
      states.splicedFresh states.growsDefined (before.next + 2) runs.growsRun
      spliceAssignment splicedHolds
  obtain ⟨_, growsNext, _, _, growsClauses⟩ :=
    define_success (.and terms.branches.acceptable (.not terms.branches.alreadyDone))
      states.splicedFresh states.growsDefined (before.next + 2) runs.growsRun
  have packetToGrows : packetAssignment.AgreesBelow states.packetDefined.next growsAssignment :=
    spliceAgreement.trans (growsAgreement.restrict (by omega))
  have oldLengthAtGrows :
      terms.old.logLength.eval growsAssignment Locals.empty = (row.log.length : Int) := by
    exact (terms.old.logLength.eval_agrees_below packetAssignment growsAssignment Locals.empty
      states.packetDefined.next
      (fun symbol member => by
        simpa using List.all_eq_true.mp oldLengthBounded symbol member)
      packetToGrows).symm.trans oldRep.logLength
  have payloadLengthAtGrows :
      terms.payload.snd.snd.snd.fst.eval growsAssignment Locals.empty =
        (payload.length : Int) := by
    exact (terms.payload.snd.snd.snd.fst.eval_agrees_below packetAssignment growsAssignment
      Locals.empty states.packetDefined.next
      (fun symbol member => by
        simpa using List.all_eq_true.mp payloadLengthBounded symbol member)
      packetToGrows).symm.trans payloadLengthValue
  have previousAtGrows :
      terms.payload.fst.eval growsAssignment Locals.empty = (request.prevLogIndex : Int) := by
    exact (terms.payload.fst.eval_agrees_below packetAssignment growsAssignment Locals.empty
      states.packetDefined.next
      (fun symbol member => by
        simpa using List.all_eq_true.mp previousBounded symbol member)
      packetToGrows).symm.trans previousValue
  have oldEntriesAtGrows :
      terms.old.logEntries.eval growsAssignment Locals.empty =
        terms.old.logEntries.eval packetAssignment Locals.empty :=
    (terms.old.logEntries.eval_agrees_below packetAssignment growsAssignment Locals.empty
      states.packetDefined.next
      (fun symbol member => by
        simpa using List.all_eq_true.mp oldEntriesBounded symbol member)
      packetToGrows).symm
  have payloadEntriesAtGrows :
      terms.payload.snd.snd.snd.snd.eval growsAssignment Locals.empty =
        terms.payload.snd.snd.snd.snd.eval packetAssignment Locals.empty :=
    (terms.payload.snd.snd.snd.snd.eval_agrees_below packetAssignment growsAssignment
      Locals.empty states.packetDefined.next
      (fun symbol member => by
        simpa using List.all_eq_true.mp payloadEntriesBounded symbol member)
      packetToGrows).symm
  have spliceValueAtGrows :
      terms.spliced.eval growsAssignment Locals.empty =
        spliceRawOutput
          (terms.old.logEntries.eval growsAssignment Locals.empty)
          (terms.payload.snd.snd.snd.snd.eval growsAssignment Locals.empty)
          tail row.log.length payload.length request.prevLogIndex := by
    have sameSpliced := growsAgreement (.array .int (entryTy width))
      states.packetDefined.next (by omega)
    rw [oldEntriesAtGrows, payloadEntriesAtGrows]
    simpa [terms, appendReceiveExecutionTerms, Term.eval, packetDefinedNext] using
      sameSpliced.symm.trans spliceOutput
  have rawSpliceAtGrows :
      (logSpliceTerm width terms.old.logLength terms.old.logEntries
        terms.payload.snd.snd.snd.fst terms.payload.snd.snd.snd.snd terms.payload.fst
        terms.spliced).eval growsAssignment Locals.empty = true := by
    exact log_splice_term_complete growsAssignment Locals.empty terms.old.logLength
      terms.old.logEntries terms.payload.snd.snd.snd.fst terms.payload.snd.snd.snd.snd
      terms.payload.fst terms.spliced row.log.length payload.length request.prevLogIndex tail
      oldLengthAtGrows payloadLengthAtGrows previousAtGrows spliceValueAtGrows
  have spliceFormula :
      (implies terms.grows
        (logSpliceTerm width terms.old.logLength terms.old.logEntries
          terms.payload.snd.snd.snd.fst terms.payload.snd.snd.snd.snd terms.payload.fst
          terms.spliced)).eval growsAssignment Locals.empty = true := by
    simp [implies, Term.eval, rawSpliceAtGrows]
  have spliceHolds : Holds states.spliceAsserted.assertions.toList growsAssignment :=
    assertion_extension_holds _ states.growsDefined states.spliceAsserted runs.spliceRun
      growsAssignment growsHolds spliceFormula
  obtain ⟨lengthAssignment, lengthAgreement, lengthHolds⟩ :=
    define_extension
      (terms.grows.ite
        (logSpliceLength terms.old.logLength terms.payload.snd.snd.snd.fst terms.payload.fst)
        terms.old.logLength)
      states.spliceAsserted middle.lengthDefined (before.next + 3) middleRuns.lengthRun
      growsAssignment spliceHolds
  obtain ⟨entriesAssignment, entriesAgreement, entriesHolds⟩ :=
    define_extension (terms.grows.ite terms.spliced terms.old.logEntries)
      middle.lengthDefined middle.entriesDefined (before.next + 4) middleRuns.entriesRun
      lengthAssignment lengthHolds
  obtain ⟨spliceFrame, spliceClauses⟩ :=
    assertion_success _ states.growsDefined states.spliceAsserted runs.spliceRun
  obtain ⟨_, lengthNext, _, _, lengthClauses⟩ :=
    define_success _ states.spliceAsserted middle.lengthDefined (before.next + 3)
      middleRuns.lengthRun
  obtain ⟨_, _, _, _, entriesClauses⟩ :=
    define_success _ middle.lengthDefined middle.entriesDefined (before.next + 4)
      middleRuns.entriesRun
  have packetToEntries : packetAssignment.AgreesBelow states.packetDefined.next
      entriesAssignment :=
    (spliceAgreement.trans
      ((growsAgreement.restrict (by omega)).trans
        ((lengthAgreement.restrict (by
          rw [spliceFrame.next, growsNext, splicedFreshNext, packetDefinedNext]
          omega)).trans
          (entriesAgreement.restrict (by
            rw [lengthNext, spliceFrame.next, growsNext, splicedFreshNext,
              packetDefinedNext]
            omega))))).restrict (le_refl _)
  have originalToEntries : assignment.AgreesBelow before.next entriesAssignment :=
    originalToPacket.trans (packetToEntries.restrict (by omega))
  have finalRep :=
    rep.agrees_below before assignment entriesAssignment frame valid originalToEntries
  have finalPacket :
      terms.packet.eval entriesAssignment Locals.empty =
        packetValue (.appendEntriesRequest request) := by
    have same := packetToEntries (packetTy width) before.next (by
      rw [packetDefinedNext]
      omega)
    simpa [terms, appendReceiveExecutionTerms, Term.eval] using same.symm.trans selectedPacket
  have finalGrows :
      terms.grows.eval entriesAssignment Locals.empty =
        (Term.and terms.branches.acceptable (Term.not terms.branches.alreadyDone)).eval
          entriesAssignment Locals.empty := by
    apply definition_clause_binding entriesHolds
    rw [entriesClauses, lengthClauses, spliceClauses, growsClauses]
    simp [terms, appendReceiveExecutionTerms]
  have finalSplice :
      (implies terms.grows
        (logSpliceTerm width terms.old.logLength terms.old.logEntries
          terms.payload.snd.snd.snd.fst terms.payload.snd.snd.snd.snd terms.payload.fst
          terms.spliced)).eval entriesAssignment Locals.empty = true := by
    exact entriesHolds _ (by
      rw [entriesClauses, lengthClauses, spliceClauses, Array.toList_push]
      simp [terms, appendReceiveExecutionTerms])
  have finalLength :
      terms.logLength.eval entriesAssignment Locals.empty =
        (terms.grows.ite
          (logSpliceLength terms.old.logLength terms.payload.snd.snd.snd.fst terms.payload.fst)
          terms.old.logLength).eval entriesAssignment Locals.empty := by
    apply definition_clause_binding entriesHolds
    rw [entriesClauses, lengthClauses]
    simp [terms, appendReceiveExecutionTerms]
  have finalEntries :
      terms.logEntries.eval entriesAssignment Locals.empty =
        (terms.grows.ite terms.spliced terms.old.logEntries).eval
          entriesAssignment Locals.empty := by
    apply definition_clause_binding entriesHolds
    rw [entriesClauses]
    simp [terms, appendReceiveExecutionTerms]
  have candidateRep :=
    append_receive_candidate_log_rep entriesAssignment before.toColumns frame.nodes
      finalRep.nodes destination terms.packet request finalPacket terms.grows terms.spliced
      terms.logEntries terms.logLength finalGrows finalSplice finalLength finalEntries
  exact ⟨entriesAssignment, originalToEntries, entriesHolds, finalRep, finalPacket, candidateRep⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
