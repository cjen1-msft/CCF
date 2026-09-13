-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendReceiveExecution
import Sparse.NativeAppendReceiveTermsEncoding
import Sparse.NativeLogSummaryAssignment

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem append_receive_tail_assignment {width : PNat} [Bootstrap (Fin width)]
    (source destination : Fin width) (before after : Encoding width)
    (states : AppendReceivePrefixStates width)
    (execution : AppendReceiveExecutionResult source destination before after states)
    (assignment : Assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (holds : Holds states.middle.suffix.currentAsserted.assertions.toList assignment)
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
        log.entries position)
    (commit : Nat)
    (sameCommit :
      (appendReceiveExecutionTerms before source destination).commit.eval
          assignment Locals.empty = (commit : Int))
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION)
    (currentAccepted :
      (currentConfigurationIndexTerm width
        (appendReceiveExecutionTerms before source destination).logLength
        (appendReceiveExecutionTerms before source destination).logEntries
        (appendReceiveExecutionTerms before source destination).commit
        (appendReceiveExecutionTerms before source destination).current).eval
          assignment Locals.empty = true) :
    exists extended : Assignment,
      assignment.AgreesBelow states.middle.suffix.currentAsserted.next extended /\
        Holds states.middle.suffix.writerBefore.assertions.toList extended /\
        FrameColumnsRep extended before.toColumns frame := by
  let terms := appendReceiveExecutionTerms before source destination
  let suffix := states.middle.suffix
  let suffixRuns := execution.runs.middleRuns.suffixRuns
  have completedShape :=
    retirement_completed_constraints_success before.bootstrap terms.consumes terms.logLength
      terms.logEntries terms.commit terms.current suffix.currentAsserted
      suffix.completedState (before.next + 12) suffixRuns.completedRun
  have currentAssertedNext : suffix.currentAsserted.next = before.next + 12 :=
    completedShape.completedId.symm
  obtain ⟨completedAssignment, completedAgreement, completedHolds⟩ :
      exists extended : Assignment,
        assignment.AgreesBelow suffix.currentAsserted.next extended /\
          Holds suffix.completedState.assertions.toList extended := by
    by_cases consumes : terms.consumes.eval assignment Locals.empty = true
    · obtain ⟨extended, agreement, extendedHolds, _⟩ :=
        retirement_completed_constraints_complete_enabled before.bootstrap terms.consumes
          terms.logLength terms.logEntries terms.commit terms.current
          suffix.currentAsserted suffix.completedState (before.next + 12)
          suffixRuns.completedRun assignment holds log commit sameLength sameCommit
          sameBootstrap sameEntries consumes currentAccepted
      exact ⟨extended, agreement, extendedHolds⟩
    · have disabled : terms.consumes.eval assignment Locals.empty = false :=
        Bool.eq_false_iff.mpr consumes
      exact retirement_completed_constraints_complete_disabled before.bootstrap
        terms.consumes terms.logLength terms.logEntries terms.commit terms.current
        suffix.currentAsserted suffix.completedState (before.next + 12)
        suffixRuns.completedRun assignment holds disabled
  have bestStart : suffix.completedState.next = before.next + 13 + 3 * width :=
    (fresh_success suffix.completedState suffix.bestFresh
      (before.next + 13 + 3 * width) suffixRuns.bestRun).1.symm
  have completedOriginalAgreement :
      assignment.AgreesBelow before.next completedAssignment :=
    completedAgreement.restrict (by omega)
  have completedRep :=
    rep.agrees_below before assignment completedAssignment frame valid
      completedOriginalAgreement
  have completedPacket :
      terms.packet.eval completedAssignment Locals.empty =
        packetValue (.appendEntriesRequest request) := by
    have same := completedAgreement (packetTy width) before.next (by omega)
    simpa [terms, appendReceiveExecutionTerms, Term.eval] using same.symm.trans samePacket
  have payloadValue :=
    append_request_payload_term_correct terms.packet completedAssignment Locals.empty request
      completedPacket
  have samePrevious :
      terms.payload.fst.eval completedAssignment Locals.empty =
        (request.prevLogIndex : Int) := by
    simpa [terms, appendReceiveExecutionTerms, Term.eval] using congrArg Prod.fst payloadValue
  have samePreviousTerm :
      terms.payload.snd.fst.eval completedAssignment Locals.empty =
        (request.prevLogTerm : Int) := by
    simpa [terms, appendReceiveExecutionTerms, Term.eval] using
      congrArg (fun value => value.2.1) payloadValue
  let receiver := NativeArrayCheckQuorum.get frame.nodes destination
  have oldRep :=
    node_row_snapshot_rep completedAssignment before.toColumns frame.nodes
      completedRep.nodes destination
  have oldLengthBounded :
      terms.old.logLength.symbols.all
        (fun symbol => symbol.2 < suffix.completedState.next) = true := by
    rw [List.all_eq_true]
    intro symbol member
    simp [terms, appendReceiveExecutionTerms, nodeRowSnapshot, NativeEncode.length,
      read, allocated, Term.symbols] at member
    rcases member with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩
    · rw [bestStart]
      simpa only [decide_eq_true_eq] using
        lt_trans valid.allocated
          (show before.next < before.next + 13 + 3 * width by omega)
    · rw [bestStart]
      simpa only [decide_eq_true_eq] using
        lt_trans valid.logLength
          (show before.next < before.next + 13 + 3 * width by omega)
  have oldEntriesBounded :
      terms.old.logEntries.symbols.all
        (fun symbol => symbol.2 < suffix.completedState.next) = true := by
    rw [List.all_eq_true]
    intro symbol member
    simp [terms, appendReceiveExecutionTerms, nodeRowSnapshot, Term.symbols] at member
    rcases member with ⟨rfl, rfl⟩
    rw [bestStart]
    simpa only [decide_eq_true_eq] using
      lt_trans valid.logEntries
        (show before.next < before.next + 13 + 3 * width by omega)
  have previousBounded :
      terms.payload.fst.symbols.all
        (fun symbol => symbol.2 < suffix.completedState.next) = true := by
    rw [List.all_eq_true]
    intro symbol member
    have same : symbol = (packetTy width, before.next) := by
      simpa [terms, appendReceiveExecutionTerms, appendRequestPayloadTerm, Term.symbols]
        using member
    subst symbol
    simp only [decide_eq_true_eq]
    rw [bestStart]
    omega
  have previousTermBounded :
      terms.payload.snd.fst.symbols.all
        (fun symbol => symbol.2 < suffix.completedState.next) = true := by
    rw [List.all_eq_true]
    intro symbol member
    have same : symbol = (packetTy width, before.next) := by
      simpa [terms, appendReceiveExecutionTerms, appendRequestPayloadTerm, Term.symbols]
        using member
    subst symbol
    simp only [decide_eq_true_eq]
    rw [bestStart]
    omega
  obtain ⟨bestAssignment, bestAgreement, bestBaseHolds, nackAccepted⟩ :=
    nack_match_assignment suffix.completedState completedAssignment completedHolds
      terms.old.logLength terms.old.logEntries terms.payload.fst terms.payload.snd.fst
      receiver.log request.prevLogIndex request.prevLogTerm oldLengthBounded
      oldEntriesBounded previousBounded previousTermBounded oldRep.logLength
      samePrevious samePreviousTerm oldRep.logEntries
  have actualNack :
      (nackMatchTerm width terms.old.logLength terms.old.logEntries terms.payload.fst
        terms.payload.snd.fst terms.best).eval bestAssignment Locals.empty = true := by
    simpa [terms, suffix, appendReceiveExecutionTerms, bestStart] using nackAccepted
  have bestHolds := fresh_holds suffix.completedState suffix.bestFresh
    (before.next + 13 + 3 * width) suffixRuns.bestRun bestAssignment bestBaseHolds
  have nackFormula :
      (implies
        (.and terms.branches.rejects
          (appendReceiveNackHint before.toColumns destination terms.packet))
        (nackMatchTerm width terms.old.logLength terms.old.logEntries terms.payload.fst
          terms.payload.snd.fst terms.best)).eval bestAssignment Locals.empty = true :=
    (implies_eval _ _ bestAssignment Locals.empty).mpr fun _ => actualNack
  have writerHolds : Holds suffix.writerBefore.assertions.toList bestAssignment :=
    assertion_extension_holds _ suffix.bestFresh suffix.writerBefore suffixRuns.nackRun
      bestAssignment bestHolds nackFormula
  have totalAgreement :
      assignment.AgreesBelow suffix.currentAsserted.next bestAssignment :=
    completedAgreement.trans (bestAgreement.restrict (by omega))
  have finalOriginalAgreement : assignment.AgreesBelow before.next bestAssignment :=
    totalAgreement.restrict (by omega)
  have finalRep :=
    rep.agrees_below before assignment bestAssignment frame valid finalOriginalAgreement
  exact ⟨bestAssignment, totalAgreement, writerHolds, finalRep⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
