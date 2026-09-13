-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayClientRequestModel
import Sparse.NativeClientRequestExecution
import Sparse.NativeClientRequestTermsEncoding
import Sparse.NativeLeaderLogPrefix
import Sparse.NativeNodeRowModelEncoding
import Sparse.NativeRetirementTailSound
import Sparse.NativeSubmittedWriteEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem client_request_frame_sound {width : PNat} [Bootstrap (Fin width)]
    (source : Fin width) (transaction : Expr .int) (transactionNat : Nat)
    (before after : Encoding width)
    (run : (clientRequest source transaction).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (columnsRep : FrameColumnsRep assignment before.toColumns frame)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION)
    (sameTransaction :
      transaction.eval assignment Locals.empty = (transactionNat : Int)) :
    exists nextFrame : NativeArrayVote.Frame (Fin width) Nat,
      NativeArrayClientRequest.Request frame source transactionNat nextFrame /\
        FrameColumnsRep assignment after.toColumns nextFrame := by
  obtain ⟨states, execution⟩ :=
    client_request_execution source transaction before after run
  have retiredHolds :=
    (insert_submitted_holds transaction states.retired after execution.submittedRun
      assignment).mp holds |>.1
  have preparedHolds :=
    retirement_tail_prior_holds before.bootstrap source states.appended
      (nodeRowSnapshot before.toColumns source).commit
      (clientRequestGuards before.toColumns source transaction)
      states.prepared states.retired execution.tailRun assignment retiredHolds
  obtain ⟨prefixStates, prefixResult⟩ :=
    prepare_leader_log_success source (.inr (.inl transaction)) before states.prepared
      states.appended execution.prepareRun
  let prefixTerms := leaderLogPrefixTerms before source
  let old := NativeArrayCheckQuorum.get frame.nodes source
  let appended :=
    NativeArrayLeaderLogWrite.appendRow old (.transaction transactionNat)
  have prefixFacts :=
    leader_log_prefix_facts source (.inr (.inl transaction)) before states.prepared
      states.appended prefixStates prefixResult assignment preparedHolds
  have sameContent :
      decodeContent ((.inr (.inl transaction) : Expr (contentTy width)).eval
        assignment Locals.empty) = .transaction transactionNat := by
    simp [Term.eval, decodeContent, sameTransaction]
  have canonicalAppendedRep : prefixTerms.appended.Rep assignment appended :=
    leader_log_prefix_row_rep source (.inr (.inl transaction))
      (.transaction transactionNat) before assignment frame columnsRep prefixFacts
      sameContent
  have appendedRep : states.appended.Rep assignment appended := by
    rw [prefixResult.outputTerms]
    exact canonicalAppendedRep
  have oldRep :=
    node_row_snapshot_rep assignment before.toColumns frame.nodes columnsRep.nodes source
  have preparedColumnsRep :
      FrameColumnsRep assignment states.prepared.toColumns frame := by
    rw [prefixResult.afterColumns]
    exact columnsRep
  obtain ⟨output, outputRep, outputModelRaw, guardHolds, writtenColumns⟩ :=
    retirement_tail_sound before.bootstrap source states.appended
      (nodeRowSnapshot before.toColumns source).commit
      (clientRequestGuards before.toColumns source transaction)
      states.prepared states.retired execution.tailRun assignment retiredHolds frame
      preparedColumnsRep appended appendedRep old.commit
      (by simpa [old] using oldRep.commit) sameBootstrap
  have outputModel :
      output.toModel = refreshRetirementState source appended.toModel := by
    simpa [appended, NativeArrayLeaderLogWrite.appendRow,
      NativeArrayCheckQuorum.Local.toModel] using outputModelRaw
  obtain ⟨tailStates, tailExecution⟩ :=
    retirement_tail_success before.bootstrap source states.appended
      (nodeRowSnapshot before.toColumns source).commit
      (clientRequestGuards before.toColumns source transaction)
      states.prepared states.retired execution.tailRun
  let tailTerms :=
    retirementTailTerms states.prepared states.appended
      (nodeRowSnapshot before.toColumns source).commit
  have writerHolds :=
    retirement_writes_prior_holds source tailTerms.values tailTerms.completed
      tailStates.writerBefore states.retired tailExecution.runs.writeRun assignment
      retiredHolds
  have constraints :=
    retirement_tail_constraints before.bootstrap source states.appended
      (nodeRowSnapshot before.toColumns source).commit
      (clientRequestGuards before.toColumns source transaction)
      states.prepared states.retired tailStates tailExecution assignment writerHolds
  obtain ⟨_, retirement, signaturePosition, retiredPosition, _, _, _, _,
      _, retirementCorrect, signatureScan, retiredScan⟩ :=
    retirement_refresh_constraints_sound assignment Locals.empty before.bootstrap
      states.appended.logLength states.appended.logEntries source tailTerms.first
      tailTerms.retirement tailTerms.signature tailTerms.retired appended.log
      (by simpa [tailTerms] using appendedRep.logLength) sameBootstrap
      (by
        intro position live
        simpa [tailTerms] using appendedRep.logEntries position live)
      (by simpa [tailTerms] using constraints.refresh)
  let signature := signaturePosition.map (1 + ·)
  let retired := retiredPosition.map (1 + ·)
  have signatureCorrect :
      retirement.bind
          (retirementCommittableIndexInLog appended.log.decode) =
        signature := by
    cases retirement with
    | none =>
      simp only [RetirementSignatureScan] at signatureScan
      simp [signature, signatureScan]
    | some retirementIndex =>
      exact
        (NativeArrayRetirement.signature_scan_correct appended.log retirementIndex
          signaturePosition).mp (by
            simpa only [RetirementSignatureScan] using signatureScan)
  have retiredCorrect :
      retiredCommittedIndexInLog source appended.log.decode = retired :=
    (NativeArrayRetirement.retired_index_scan_correct appended.log source
      retiredPosition).mp retiredScan
  let refreshed :=
    NativeArrayLeaderLogWrite.refreshRow old (.transaction transactionNat)
      retirement signature retired
  have refreshedModel :
      refreshed.toModel = refreshRetirementState source appended.toModel := by
    change
      (NativeArrayLeaderLogWrite.refreshRow old (.transaction transactionNat)
        retirement signature retired).toModel =
          refreshRetirementState source
            (NativeArrayLeaderLogWrite.appendRow old
              (.transaction transactionNat)).toModel
    rw [NativeArrayLeaderLogWrite.append_row_correct]
    exact
      NativeArrayLeaderLogWrite.refresh_row_correct old source
        (.transaction transactionNat) retirement signature retired retirementCorrect
        signatureCorrect retiredCorrect
  have outputToRefreshed : output.toModel = refreshed.toModel :=
    outputModel.trans refreshedModel.symm
  have refreshedRep : tailTerms.values.Rep assignment refreshed :=
    NodeRowTerms.Rep.of_model_eq assignment tailTerms.values output refreshed
      (by simpa [tailTerms] using outputRep) outputToRefreshed
  have nativeEnabled :
      NativeArrayClientRequest.enabled frame source transactionNat refreshed :=
    (client_request_guards_correct assignment before.toColumns frame columnsRep source
      transaction tailTerms.values.membershipState transactionNat refreshed
      sameTransaction
      (by simpa [tailTerms] using refreshedRep.membershipState)).mp
      (by simpa [tailTerms] using guardHolds)
  let completed := retirementCompletedNodes refreshed.log.decode refreshed.commit
  let retiredFrame := retirementWriteFrame frame source completed refreshed
  have sameLog : output.log.decode = refreshed.log.decode := by
    simpa only [NativeArrayCheckQuorum.Local.toModel] using
      congrArg NodeState.log outputToRefreshed
  have sameCommit : output.commit = refreshed.commit := by
    simpa only [NativeArrayCheckQuorum.Local.toModel] using
      congrArg NodeState.commitIndex outputToRefreshed
  have sameCompleted :
      retirementCompletedNodes output.log.decode output.commit = completed := by
    simp [completed, sameLog, sameCommit]
  let written := retirementWriteFrame frame source completed output
  have writtenRep : FrameColumnsRep assignment states.retired.toColumns written := by
    simpa [written, sameCompleted] using writtenColumns
  have retiredFrameRep :
      FrameColumnsRep assignment states.retired.toColumns retiredFrame := by
    refine { writtenRep with
      nodes := NodeColumnsRep.of_model_eq assignment states.retired.toColumns written.nodes
        retiredFrame.nodes writtenRep.nodes ?_ ?_ }
    · intro node
      by_cases same : node = source
      · subst node
        simp [written, retiredFrame, retirementWriteFrame]
      · simp [written, retiredFrame, retirementWriteFrame, same]
    · intro node
      by_cases same : node = source
      · subst node
        simpa [written, retiredFrame, retirementWriteFrame,
          NativeArrayCheckQuorum.get] using outputToRefreshed
      · simp [written, retiredFrame, retirementWriteFrame,
          NativeArrayCheckQuorum.get, same]
  have finalRep :=
    insert_submitted_frame transaction transactionNat states.retired after
      execution.submittedRun assignment holds retiredFrame retiredFrameRep sameTransaction
  let nextFrame :=
    NativeArrayClientRequest.request frame source transactionNat refreshed completed
  have step : NativeArrayClientRequest.Request frame source transactionNat nextFrame :=
    .submit retirement signature retired completed retirementCorrect signatureCorrect
      retiredCorrect rfl nativeEnabled
  refine ⟨nextFrame, step, ?_⟩
  simpa [nextFrame, retiredFrame, retirementWriteFrame,
    NativeArrayClientRequest.request] using finalRep

theorem client_request_model_sound {width : PNat} [Bootstrap (Fin width)]
    (source : Fin width) (transaction : Expr .int) (transactionNat : Nat)
    (before after : Encoding width)
    (run : (clientRequest source transaction).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (state : State (Fin width) Nat)
    (columnsRep : FrameColumnsRep assignment before.toColumns frame)
    (modelRep : frame.Rep state)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION)
    (sameTransaction :
      transaction.eval assignment Locals.empty = (transactionNat : Int)) :
    CCFRaft.Enabled state (.clientRequest source transactionNat) /\
      exists nextFrame : NativeArrayVote.Frame (Fin width) Nat,
        FrameColumnsRep assignment after.toColumns nextFrame /\
          nextFrame.Rep (CCFRaft.next state (.clientRequest source transactionNat)) := by
  obtain ⟨nextFrame, step, nextRep⟩ :=
    client_request_frame_sound source transaction transactionNat before after run
      assignment holds frame columnsRep sameBootstrap sameTransaction
  have correct :=
    NativeArrayClientRequest.Request.model_correct frame nextFrame state modelRep source
      transactionNat step
  exact ⟨correct.1, nextFrame, nextRep, correct.2⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
