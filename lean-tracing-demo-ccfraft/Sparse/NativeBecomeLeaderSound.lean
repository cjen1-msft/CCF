-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayBecomeLeaderTransition
import Sparse.NativeBecomeLeaderExecution
import Sparse.NativeBecomeLeaderGuardsEncoding
import Sparse.NativeBecomeLeaderRowEncoding
import Sparse.NativeNodeRowModelEncoding
import Sparse.NativeRetirementTailSound

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem become_leader_frame_sound {width : PNat} [Bootstrap (Fin width)]
    (source : Fin width) (before after : Encoding width)
    (run : (becomeLeader source).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (columnsRep : FrameColumnsRep assignment before.toColumns frame)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION) :
    exists nextFrame : NativeArrayVote.Frame (Fin width) Nat,
      NativeArrayBecomeLeader.BecomeLeader frame source nextFrame /\
        FrameColumnsRep assignment after.toColumns nextFrame := by
  obtain ⟨states, execution⟩ := become_leader_success source before after run
  let terms := becomeLeaderExecutionTerms before source
  let old := NativeArrayCheckQuorum.get frame.nodes source
  have currentAssertedHolds :=
    retirement_tail_prior_holds before.bootstrap source terms.prepared terms.old.commit
      terms.guards states.prefixStates.currentAsserted after execution.runs.tailRun
      assignment holds
  have currentFacts :=
    assertion_holds terms.currentConstraint states.prefixStates.currentFresh
      states.prefixStates.currentAsserted execution.runs.currentAssertionRun
      assignment currentAssertedHolds
  have latestAssertedHolds :=
    fresh_prior_holds states.prefixStates.latestAsserted states.prefixStates.currentFresh
      (before.next + 1) execution.runs.currentRun assignment currentFacts.1
  have latestFacts :=
    assertion_holds terms.latestConstraint states.prefixStates.latestFresh
      states.prefixStates.latestAsserted execution.runs.latestAssertionRun
      assignment latestAssertedHolds
  have oldRep :=
    node_row_snapshot_rep assignment before.toColumns frame.nodes columnsRep.nodes source
  obtain ⟨latestNat, sameLatest, latestMaximum⟩ :=
    bounded_signature_term_sound assignment Locals.empty
      terms.old.logLength terms.old.logEntries terms.old.logLength terms.latest
      old.log old.log.length
      (by simpa [terms, old] using oldRep.logLength)
      (by simpa [terms, old] using oldRep.logLength)
      (by
        intro position live
        simpa [terms, old] using oldRep.logEntries position live)
      (by simpa [terms] using latestFacts.2)
  have latestMaximumFull :
      maxCommittableIndex old.log.decode = latestNat := by
    rw [maxCommittableIndexUpTo] at latestMaximum
    have full : old.log.decode.take old.log.length = old.log.decode := by
      rw [<- old.log.decode_length, List.take_length]
    rw [full] at latestMaximum
    exact latestMaximum
  have latestCorrect : NativeArrayVote.SignatureIndex old.log latestNat :=
    (NativeArrayVote.signature_index_correct old.log latestNat).mpr latestMaximumFull
  obtain ⟨currentNat, sameCurrent, currentModel⟩ :=
    current_configuration_index_term_sound assignment Locals.empty
      terms.old.logLength terms.old.logEntries terms.old.commit terms.current
      old.log old.commit
      (by simpa [terms, old] using oldRep.logLength)
      (by simpa [terms, old] using oldRep.commit)
      (by
        intro position live
        simpa [terms, old] using oldRep.logEntries position live)
      (by simpa [terms] using currentFacts.2)
  have currentCorrect :
      NativeArrayCheckQuorum.CurrentIndex old.log old.commit currentNat :=
    (NativeArrayCheckQuorum.current_index_correct old.log old.commit currentNat).mpr
      currentModel
  let prepared := NativeArrayBecomeLeader.prepareRow old latestNat
  have preparedRep : terms.prepared.Rep assignment prepared :=
    become_leader_row_terms_rep assignment terms.old old terms.latest latestNat
      (by simpa [terms, old] using oldRep) sameLatest
  have tailColumnsRep :
      FrameColumnsRep assignment states.prefixStates.currentAsserted.toColumns frame := by
    rw [execution.currentAssertedColumns]
    exact columnsRep
  obtain ⟨output, outputRep, outputModelRaw, guardHolds, writtenColumns⟩ :=
    retirement_tail_sound before.bootstrap source terms.prepared terms.old.commit
      terms.guards states.prefixStates.currentAsserted after execution.runs.tailRun
      assignment holds frame tailColumnsRep prepared preparedRep old.commit
      (by
        simpa [terms, old, prepared, NativeArrayBecomeLeader.prepareRow] using
          oldRep.commit)
      sameBootstrap
  have outputModel :
      output.toModel =
        refreshRetirementState source prepared.toModel := by
    simpa [prepared, NativeArrayBecomeLeader.prepareRow,
      NativeArrayCheckQuorum.Local.toModel] using outputModelRaw
  let tailTerms :=
    retirementTailTerms states.prefixStates.currentAsserted terms.prepared terms.old.commit
  have writerHolds :=
    retirement_writes_prior_holds source tailTerms.values tailTerms.completed
      states.tailStates.writerBefore after execution.tailExecution.runs.writeRun
      assignment holds
  have constraints :=
    retirement_tail_constraints before.bootstrap source terms.prepared terms.old.commit
      terms.guards states.prefixStates.currentAsserted after states.tailStates
      execution.tailExecution assignment writerHolds
  obtain ⟨_, retirement, signaturePosition, retiredPosition, _, _, _, _,
      _, retirementCorrect, signatureScan, retiredScan⟩ :=
    retirement_refresh_constraints_sound assignment Locals.empty before.bootstrap
      terms.prepared.logLength terms.prepared.logEntries source tailTerms.first
      tailTerms.retirement tailTerms.signature tailTerms.retired prepared.log
      (by simpa [tailTerms] using preparedRep.logLength) sameBootstrap
      (by
        intro position live
        simpa [tailTerms] using preparedRep.logEntries position live)
      (by simpa [tailTerms] using constraints.refresh)
  let signature := signaturePosition.map (1 + ·)
  let retired := retiredPosition.map (1 + ·)
  have signatureCorrect :
      retirement.bind
          (retirementCommittableIndexInLog prepared.log.decode) =
        signature := by
    cases retirement with
    | none =>
      simp only [RetirementSignatureScan] at signatureScan
      simp [signature, signatureScan]
    | some retirementIndex =>
      exact
        (NativeArrayRetirement.signature_scan_correct prepared.log retirementIndex
          signaturePosition).mp (by
            simpa only [RetirementSignatureScan] using signatureScan)
  have retiredCorrect :
      retiredCommittedIndexInLog source prepared.log.decode = retired :=
    (NativeArrayRetirement.retired_index_scan_correct prepared.log source
      retiredPosition).mp retiredScan
  let refreshed :=
    NativeArrayBecomeLeader.refreshRow old latestNat retirement signature retired
  have refreshedModel :
      refreshed.toModel = refreshRetirementState source prepared.toModel := by
    change
      (NativeArrayBecomeLeader.refreshRow old latestNat retirement signature retired).toModel =
        refreshRetirementState source
          (NativeArrayBecomeLeader.prepareRow old latestNat).toModel
    rw [NativeArrayBecomeLeader.prepare_row_correct]
    exact
      NativeArrayBecomeLeader.refresh_row_correct old source latestNat retirement
        signature retired retirementCorrect signatureCorrect retiredCorrect
  have outputToRefreshed : output.toModel = refreshed.toModel :=
    outputModel.trans refreshedModel.symm
  have refreshedRep : tailTerms.values.Rep assignment refreshed :=
    NodeRowTerms.Rep.of_model_eq assignment tailTerms.values output refreshed
      (by simpa [tailTerms] using outputRep) outputToRefreshed
  have encodedBootstrap :
      before.bootstrap = encodeBits INITIAL_CONFIGURATION := by
    rw [<- sameBootstrap, encode_decode_bits]
  have nativeEnabled :
      NativeArrayBecomeLeader.enabled frame source currentNat refreshed :=
    (become_leader_guards_correct assignment before.bootstrap before.toColumns frame
      columnsRep source terms.current tailTerms.values.membershipState currentNat
      refreshed encodedBootstrap sameCurrent
      (by simpa [tailTerms] using refreshedRep.membershipState)).mp
      (by simpa [terms, tailTerms] using guardHolds)
  let completed := retirementCompletedNodes refreshed.log.decode refreshed.commit
  let nextFrame :=
    NativeArrayBecomeLeader.becomeLeader frame source refreshed completed
  have step : NativeArrayBecomeLeader.BecomeLeader frame source nextFrame := by
    exact .promote latestNat currentNat retirement signature retired completed
      latestCorrect currentCorrect retirementCorrect signatureCorrect retiredCorrect
      rfl nativeEnabled
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
  have writtenRep : FrameColumnsRep assignment after.toColumns written := by
    simpa [written, sameCompleted] using writtenColumns
  have nextRep : FrameColumnsRep assignment after.toColumns nextFrame := by
    refine { writtenRep with
      nodes := NodeColumnsRep.of_model_eq assignment after.toColumns written.nodes
        nextFrame.nodes writtenRep.nodes ?_ ?_ }
    · intro node
      by_cases same : node = source
      · subst node
        simp [written, nextFrame, retirementWriteFrame,
          NativeArrayBecomeLeader.becomeLeader]
      · simp [written, nextFrame, retirementWriteFrame,
          NativeArrayBecomeLeader.becomeLeader, same]
    · intro node
      by_cases same : node = source
      · subst node
        simpa [written, nextFrame, retirementWriteFrame,
          NativeArrayBecomeLeader.becomeLeader, NativeArrayCheckQuorum.get] using
            outputToRefreshed
      · simp [written, nextFrame, retirementWriteFrame,
          NativeArrayBecomeLeader.becomeLeader, NativeArrayCheckQuorum.get, same]
  exact ⟨nextFrame, step, nextRep⟩

theorem become_leader_model_sound {width : PNat} [Bootstrap (Fin width)]
    (source : Fin width) (before after : Encoding width)
    (run : (becomeLeader source).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (state : State (Fin width) Nat)
    (columnsRep : FrameColumnsRep assignment before.toColumns frame)
    (modelRep : frame.Rep state)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION) :
    CCFRaft.Enabled state (.becomeLeader source) /\
      exists nextFrame : NativeArrayVote.Frame (Fin width) Nat,
        FrameColumnsRep assignment after.toColumns nextFrame /\
          nextFrame.Rep (CCFRaft.next state (.becomeLeader source)) := by
  obtain ⟨nextFrame, step, nextRep⟩ :=
    become_leader_frame_sound source before after run assignment holds frame
      columnsRep sameBootstrap
  have correct :=
    NativeArrayBecomeLeader.BecomeLeader.model_correct frame nextFrame state
      modelRep source step
  exact ⟨correct.1, nextFrame, nextRep, correct.2⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
