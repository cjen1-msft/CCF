-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendReceiveExecution
import Sparse.NativeAppendReceiveTermsEncoding
import Sparse.NativeLogSummaryAssignment

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem append_receive_commit_assignment {width : PNat} [Bootstrap (Fin width)]
    (source destination : Fin width) (before after : Encoding width)
    (states : AppendReceivePrefixStates width)
    (execution : AppendReceiveExecutionResult source destination before after states)
    (assignment : Assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (holds : Holds states.middle.entriesDefined.assertions.toList assignment)
    (valid : ReferencesValid before)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (request : AppendEntriesRequest (Fin width) Nat)
    (samePacket :
      (appendReceiveExecutionTerms before source destination).packet.eval
          assignment Locals.empty =
        packetValue (.appendEntriesRequest request))
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (sameLength :
      (appendReceiveExecutionTerms before source destination).logLength.eval
          assignment Locals.empty = (log.length : Int))
    (sameEntries : forall position, position < log.length ->
      modelEntry
          ((appendReceiveExecutionTerms before source destination).logEntries.eval
            assignment Locals.empty (position : Int)) =
        log.entries position) :
    exists extended : Assignment,
      assignment.AgreesBelow states.middle.entriesDefined.next extended /\
        Holds states.middle.commitDefined.assertions.toList extended /\
        FrameColumnsRep extended before.toColumns frame /\
        (appendReceiveExecutionTerms before source destination).packet.eval
            extended Locals.empty =
          packetValue (.appendEntriesRequest request) /\
        (appendReceiveExecutionTerms before source destination).logLength.eval
            extended Locals.empty = (log.length : Int) /\
        (forall position, position < log.length ->
          modelEntry
              ((appendReceiveExecutionTerms before source destination).logEntries.eval
                extended Locals.empty (position : Int)) =
            log.entries position) /\
        exists commit : Nat,
          (appendReceiveExecutionTerms before source destination).commit.eval
            extended Locals.empty = (commit : Int) := by
  let terms := appendReceiveExecutionTerms before source destination
  let middle := states.middle
  let middleRuns := execution.runs.middleRuns
  let cap := logRangeMinTerm terms.payload.snd.snd.fst
    (.add terms.payload.fst terms.payload.snd.snd.snd.fst)
  let capNat := min request.leaderCommit (request.prevLogIndex + request.entries.length)
  have entriesNext : middle.entriesDefined.next = before.next + 5 := by
    exact
      (fresh_success middle.entriesDefined middle.commitSignatureFresh
        (before.next + 5) middleRuns.commitSignatureRun).1.symm
  have payloadValue :=
    append_request_payload_term_correct terms.packet assignment Locals.empty request samePacket
  have sameLeaderCommit :
      terms.payload.snd.snd.fst.eval assignment Locals.empty =
        (request.leaderCommit : Int) := by
    simpa [terms, appendReceiveExecutionTerms, Term.eval] using
      congrArg (fun value => value.2.2.1) payloadValue
  have samePrevious :
      terms.payload.fst.eval assignment Locals.empty =
        (request.prevLogIndex : Int) := by
    simpa [terms, appendReceiveExecutionTerms, Term.eval] using congrArg Prod.fst payloadValue
  have samePayloadLength :
      terms.payload.snd.snd.snd.fst.eval assignment Locals.empty =
        (request.entries.length : Int) := by
    have sameLog := congrArg (fun value => value.2.2.2) payloadValue
    simpa [terms, appendReceiveExecutionTerms, Term.eval, logValue] using
      congrArg Prod.fst sameLog
  have sameCap : cap.eval assignment Locals.empty = (capNat : Int) := by
    rw [log_range_min_term_eval]
    change min (terms.payload.snd.snd.fst.eval assignment Locals.empty)
        (terms.payload.fst.eval assignment Locals.empty +
          terms.payload.snd.snd.snd.fst.eval assignment Locals.empty) =
      (capNat : Int)
    rw [sameLeaderCommit, samePrevious, samePayloadLength, Nat.cast_min, Nat.cast_add]
  have lengthBounded :
      terms.logLength.symbols.all
        (fun symbol => symbol.2 < middle.entriesDefined.next) = true := by
    simp [terms, appendReceiveExecutionTerms, Term.symbols, entriesNext]
  have entriesBounded :
      terms.logEntries.symbols.all
        (fun symbol => symbol.2 < middle.entriesDefined.next) = true := by
    simp [terms, appendReceiveExecutionTerms, Term.symbols, entriesNext]
  have capBounded :
      cap.symbols.all (fun symbol => symbol.2 < middle.entriesDefined.next) = true := by
    simp [cap, terms, appendReceiveExecutionTerms, appendRequestPayloadTerm,
      logRangeMinTerm, Term.symbols, entriesNext]
  obtain ⟨signatureAssignment, signatureAgreement, signatureBaseHolds, scanAccepted⟩ :=
    bounded_signature_assignment middle.entriesDefined assignment holds terms.logLength
      terms.logEntries cap log capNat lengthBounded entriesBounded capBounded sameLength
      sameCap sameEntries
  have actualScan :
      (boundedSignatureTerm width terms.logLength terms.logEntries cap
        terms.commitSignature).eval signatureAssignment Locals.empty = true := by
    simpa [terms, middle, appendReceiveExecutionTerms, entriesNext] using scanAccepted
  have signatureFormula :
      (implies terms.branches.acceptable
        (boundedSignatureTerm width terms.logLength terms.logEntries cap
          terms.commitSignature)).eval signatureAssignment Locals.empty = true := by
    simp [implies, Term.eval, actualScan]
  have freshShape :=
    fresh_success middle.entriesDefined middle.commitSignatureFresh
      (before.next + 5) middleRuns.commitSignatureRun
  have signatureFreshHolds :
      Holds middle.commitSignatureFresh.assertions.toList signatureAssignment := by
    rw [freshShape.2.2.2.2]
    exact signatureBaseHolds
  have signatureHolds : Holds middle.signatureAsserted.assertions.toList
      signatureAssignment :=
    assertion_extension_holds _ middle.commitSignatureFresh middle.signatureAsserted
      middleRuns.signatureRun signatureAssignment signatureFreshHolds signatureFormula
  obtain ⟨extended, commitAgreement, commitHolds⟩ :=
    define_extension
      (.ite terms.branches.acceptable
        (intMaxTerm terms.old.commit terms.commitSignature) terms.old.commit)
      middle.signatureAsserted middle.commitDefined (before.next + 6)
      middleRuns.commitRun signatureAssignment signatureHolds
  have freshNext : middle.commitSignatureFresh.next = middle.entriesDefined.next + 1 :=
    freshShape.2.1
  have assertedNext :
      middle.signatureAsserted.next = middle.commitSignatureFresh.next :=
    (assertion_success _ middle.commitSignatureFresh middle.signatureAsserted
      middleRuns.signatureRun).1.next
  have totalAgreement : assignment.AgreesBelow middle.entriesDefined.next extended :=
    signatureAgreement.trans (commitAgreement.restrict (by omega))
  have originalAgreement : assignment.AgreesBelow before.next extended :=
    totalAgreement.restrict (by omega)
  have finalRep := rep.agrees_below before assignment extended frame valid originalAgreement
  have finalPacket :
      terms.packet.eval extended Locals.empty =
        packetValue (.appendEntriesRequest request) := by
    have same := totalAgreement (packetTy width) before.next (by omega)
    simpa [terms, appendReceiveExecutionTerms, Term.eval] using same.symm.trans samePacket
  have finalLength :
      terms.logLength.eval extended Locals.empty = (log.length : Int) := by
    have sameEval := terms.logLength.eval_agrees_below assignment extended Locals.empty
      middle.entriesDefined.next
      (fun symbol member => by
        simpa using List.all_eq_true.mp lengthBounded symbol member)
      totalAgreement
    exact sameEval.symm.trans sameLength
  have finalEntries : forall position, position < log.length ->
      modelEntry (terms.logEntries.eval extended Locals.empty (position : Int)) =
        log.entries position := by
    intro position live
    have sameEval := terms.logEntries.eval_agrees_below assignment extended Locals.empty
      middle.entriesDefined.next
      (fun symbol member => by
        simpa using List.all_eq_true.mp entriesBounded symbol member)
      totalAgreement
    rw [<- sameEval]
    exact sameEntries position live
  have signatureLength :
      terms.logLength.eval signatureAssignment Locals.empty = (log.length : Int) := by
    have sameEval := terms.logLength.eval_agrees_below assignment signatureAssignment
      Locals.empty middle.entriesDefined.next
      (fun symbol member => by
        simpa using List.all_eq_true.mp lengthBounded symbol member)
      signatureAgreement
    exact sameEval.symm.trans sameLength
  have signatureCap : cap.eval signatureAssignment Locals.empty = (capNat : Int) := by
    have sameEval := cap.eval_agrees_below assignment signatureAssignment Locals.empty
      middle.entriesDefined.next
      (fun symbol member => by
        simpa using List.all_eq_true.mp capBounded symbol member)
      signatureAgreement
    exact sameEval.symm.trans sameCap
  have signatureEntries : forall position, position < log.length ->
      modelEntry (terms.logEntries.eval signatureAssignment Locals.empty (position : Int)) =
        log.entries position := by
    intro position live
    have sameEval := terms.logEntries.eval_agrees_below assignment signatureAssignment
      Locals.empty middle.entriesDefined.next
      (fun symbol member => by
        simpa using List.all_eq_true.mp entriesBounded symbol member)
      signatureAgreement
    rw [<- sameEval]
    exact sameEntries position live
  obtain ⟨signature, sameSignature, _⟩ :=
    bounded_signature_term_sound signatureAssignment Locals.empty terms.logLength
      terms.logEntries cap terms.commitSignature log capNat signatureLength signatureCap
      signatureEntries actualScan
  have finalSignature :
      terms.commitSignature.eval extended Locals.empty = (signature : Int) := by
    have sameValue := commitAgreement .int (before.next + 5) (by
      rw [assertedNext, freshNext, entriesNext]
      omega)
    simpa [terms, appendReceiveExecutionTerms, Term.eval] using
      sameValue.symm.trans sameSignature
  have oldRep :=
    node_row_snapshot_rep extended before.toColumns frame.nodes finalRep.nodes destination
  have oldCommit :
      terms.old.commit.eval extended Locals.empty =
        ((NativeArrayCheckQuorum.get frame.nodes destination).commit : Int) := by
    simpa [terms, appendReceiveExecutionTerms] using oldRep.commit
  obtain ⟨_, _, _, _, commitClauses⟩ :=
    define_success
      (Term.ite terms.branches.acceptable
        (intMaxTerm terms.old.commit terms.commitSignature) terms.old.commit)
      middle.signatureAsserted middle.commitDefined (before.next + 6)
      middleRuns.commitRun
  have commitBinding :
      terms.commit.eval extended Locals.empty =
        (Term.ite terms.branches.acceptable
          (intMaxTerm terms.old.commit terms.commitSignature) terms.old.commit).eval
            extended Locals.empty := by
    apply definition_clause_binding commitHolds
    rw [commitClauses, Array.toList_push]
    simp [terms, appendReceiveExecutionTerms]
  have naturalCommit : exists commit : Nat,
      terms.commit.eval extended Locals.empty = (commit : Int) := by
    by_cases accepted : terms.branches.acceptable.eval extended Locals.empty = true
    · refine ⟨max (NativeArrayCheckQuorum.get frame.nodes destination).commit signature, ?_⟩
      calc
        terms.commit.eval extended Locals.empty =
            max (terms.old.commit.eval extended Locals.empty)
              (terms.commitSignature.eval extended Locals.empty) := by
          rw [commitBinding]
          simp [accepted, Term.eval, int_max_term_eval]
        _ = (max (NativeArrayCheckQuorum.get frame.nodes destination).commit
              signature : Nat) := by
          rw [oldCommit, finalSignature, Nat.cast_max]
    · have rejected : terms.branches.acceptable.eval extended Locals.empty = false :=
        Bool.eq_false_iff.mpr accepted
      refine ⟨(NativeArrayCheckQuorum.get frame.nodes destination).commit, ?_⟩
      calc
        terms.commit.eval extended Locals.empty =
            terms.old.commit.eval extended Locals.empty := by
          rw [commitBinding]
          simp [rejected, Term.eval]
        _ = ((NativeArrayCheckQuorum.get frame.nodes destination).commit : Int) :=
          oldCommit
  exact ⟨extended, totalAgreement, commitHolds, finalRep, finalPacket, finalLength,
    finalEntries, naturalCommit⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
