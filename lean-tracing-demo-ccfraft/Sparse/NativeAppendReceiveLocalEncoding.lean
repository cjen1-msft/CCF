-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendReceiveCandidateEncoding
import Sparse.NativeAppendReceiveFinalRowEncoding
import Sparse.NativeAppendReceiveHandlerEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt NativeArrayCheckQuorum NativeArrayLogWrite NativeArrayVote

theorem append_receive_response_term_endpoints {width : PNat}
    (assignment : Assignment) (columns : Columns)
    (source destination : Fin width) (packet : Expr (packetTy width))
    (best : Expr .int) (response : AppendEntriesResponse (Fin width))
    (sameResponse :
      (appendReceiveResponseTerm columns source destination packet best).eval
          assignment Locals.empty =
        packetValue (.appendEntriesResponse response)) :
    response.source = destination /\ response.destination = source := by
  have sameHeader := congrArg (fun value => value.1.2) sameResponse
  have sameSourceValue : (destination.val : Int) = response.source.val := by
    simpa [appendReceiveResponseTerm, appendResponseTerm, Term.eval, packetValue,
      packetHeaderValue, Message.source, Message.destination] using
        congrArg Prod.fst sameHeader
  have sameDestinationValue : (source.val : Int) = response.destination.val := by
    simpa [appendReceiveResponseTerm, appendResponseTerm, Term.eval, packetValue,
      packetHeaderValue, Message.source, Message.destination] using
        congrArg Prod.snd sameHeader
  exact ⟨Fin.ext (Int.ofNat_inj.mp sameSourceValue.symm),
    Fin.ext (Int.ofNat_inj.mp sameDestinationValue.symm)⟩

theorem append_receive_local_correct {width : PNat}
    [Bootstrap (Fin width)]
    (assignment : Assignment) (columns : Columns)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays)
    (source destination : Fin width) (packet : Expr (packetTy width))
    (request : AppendEntriesRequest (Fin width) Nat)
    (samePacket :
      packet.eval assignment Locals.empty =
        packetValue (.appendEntriesRequest request))
    (sameSource : request.source = source)
    (sameDestination : request.destination = destination)
    (bootstrap : BitVec width)
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (grows : Expr .bool)
    (spliced logEntries : Expr (.array .int (entryTy width)))
    (logLength commitSignature commit : Expr .int)
    (first retirement refreshSignature retired best : Expr .int)
    (sameGrows :
      grows.eval assignment Locals.empty =
        (Term.and
          (appendReceiveTerms columns destination packet).acceptable
          (Term.not (appendReceiveTerms columns destination packet).alreadyDone)).eval
            assignment Locals.empty)
    (spliceAccepted :
      (implies grows
        (let requestPayload := appendRequestPayloadTerm packet
         let entries := requestPayload.snd.snd.snd
         let old := nodeRowSnapshot columns destination
         logSpliceTerm width old.logLength old.logEntries entries.fst entries.snd
           requestPayload.fst spliced)).eval assignment Locals.empty = true)
    (sameLogLength :
      logLength.eval assignment Locals.empty =
        (Term.ite grows
          (let requestPayload := appendRequestPayloadTerm packet
           let entries := requestPayload.snd.snd.snd
           let old := nodeRowSnapshot columns destination
           logSpliceLength old.logLength entries.fst requestPayload.fst)
          (nodeRowSnapshot columns destination).logLength).eval
            assignment Locals.empty)
    (sameLogEntries :
      logEntries.eval assignment Locals.empty =
        (Term.ite grows spliced
          (nodeRowSnapshot columns destination).logEntries).eval
            assignment Locals.empty)
    (signatureAccepted :
      (implies
        (appendReceiveTerms columns destination packet).acceptable
        (let requestPayload := appendRequestPayloadTerm packet
         let entries := requestPayload.snd.snd.snd
         boundedSignatureTerm width logLength logEntries
           (logRangeMinTerm requestPayload.snd.snd.fst
             (.add requestPayload.fst entries.fst))
           commitSignature)).eval assignment Locals.empty = true)
    (sameCommit :
      commit.eval assignment Locals.empty =
        (Term.ite
          (appendReceiveTerms columns destination packet).acceptable
          (intMaxTerm (nodeRowSnapshot columns destination).commit commitSignature)
          (nodeRowSnapshot columns destination).commit).eval
            assignment Locals.empty)
    (refreshAccepted :
      (implies
        (Term.not (appendReceiveTerms columns destination packet).stepDown)
        (let candidate := appendReceiveCandidateRowTerms columns destination packet
           grows logLength logEntries commit
         retirementRefreshConstraints width bootstrap candidate.logLength
           candidate.logEntries destination first retirement refreshSignature
           retired)).eval assignment Locals.empty = true)
    (nackAccepted :
      (implies
        (Term.and
          (appendReceiveTerms columns destination packet).rejects
          (appendReceiveNackHint columns destination packet))
        (let requestPayload := appendRequestPayloadTerm packet
         let old := nodeRowSnapshot columns destination
         nackMatchTerm width old.logLength old.logEntries requestPayload.fst
           requestPayload.snd.fst best)).eval assignment Locals.empty = true)
    (localEnabled :
      (Term.or
        (appendReceiveTerms columns destination packet).stepDown
        (appendReceiveTerms columns destination packet).handles).eval
          assignment Locals.empty = true) :
    let branches := appendReceiveTerms columns destination packet
    let old := NativeArrayCheckQuorum.get arrays destination
    let candidateTerms := appendReceiveCandidateRowTerms columns destination packet
      grows logLength logEntries commit
    let outputTerms := appendReceiveFinalRowTerms candidateTerms branches.stepDown
      retirement refreshSignature retired
    let step := branches.stepDown.eval assignment Locals.empty
    exists candidate output : NativeArrayCheckQuorum.Local (Fin width) Nat,
      exists response : AppendEntriesResponse (Fin width),
        candidateTerms.Rep assignment candidate /\
        outputTerms.Rep assignment output /\
        (appendReceiveResponseTerm columns source destination packet best).eval
            assignment Locals.empty =
          packetValue (.appendEntriesResponse response) /\
        response.source = destination /\
        response.destination = source /\
        (step = true ->
          request.term = old.currentTerm /\
          (old.role = .candidate \/ old.role = .preVoteCandidate) /\
          output = { old with role := .follower, isNewFollower := true }) /\
        (step = false ->
          handleAppendEntriesRequest? old.toModel request =
            some (candidate.toModel, response) /\
          output.toModel = refreshRetirementState destination candidate.toModel) /\
        output.log = candidate.log /\
        output.commit = candidate.commit := by
  let branches := appendReceiveTerms columns destination packet
  let payload := NativeArrayCheckQuorum.Log.ofList request.entries
  let old := NativeArrayCheckQuorum.get arrays destination
  let candidateTerms := appendReceiveCandidateRowTerms columns destination packet
    grows logLength logEntries commit
  let outputTerms := appendReceiveFinalRowTerms candidateTerms branches.stepDown
    retirement refreshSignature retired
  let step := branches.stepDown.eval assignment Locals.empty
  obtain ⟨candidateSignature, acceptableCorrect, doneCorrect, conflictCorrect,
      _, latest, candidateRep⟩ :=
    append_receive_candidate_row_terms_rep assignment columns arrays rep destination
      packet request samePacket grows spliced logEntries logLength commitSignature
      commit sameGrows spliceAccepted sameLogLength sameLogEntries signatureAccepted
      sameCommit
  let acceptable := branches.acceptable.eval assignment Locals.empty
  let done := branches.alreadyDone.eval assignment Locals.empty
  let conflict := branches.conflict.eval assignment Locals.empty
  let candidate := NativeArrayAppendCandidate.candidateRow old request payload
    candidateSignature acceptable done conflict
  change candidateTerms.Rep assignment candidate at candidateRep
  obtain ⟨output, outputRep, stepOutput, consumeOutput, sameLog, sameCommitValue⟩ :=
    append_receive_final_row_terms_correct assignment bootstrap candidateTerms candidate
      candidateRep destination branches.stepDown step first retirement refreshSignature
      retired rfl sameBootstrap
      (by simpa [branches, candidateTerms] using refreshAccepted)
  change outputTerms.Rep assignment output at outputRep
  have stepCorrect :
      step = true ->
        request.term = old.currentTerm /\
          (old.role = .candidate \/ old.role = .preVoteCandidate) := by
    intro stepTrue
    exact (append_receive_step_down_correct assignment columns arrays rep destination
      packet request samePacket).mp stepTrue
  have candidateOfStep :
      step = true -> candidate = old := by
    intro stepTrue
    exact NativeArrayAppendCandidate.candidate_row_of_step_down old request payload
      candidateSignature acceptable done conflict acceptableCorrect
      (stepCorrect stepTrue)
  by_cases stepTrue : step = true
  · have semanticStep := stepCorrect stepTrue
    have candidateOld := candidateOfStep stepTrue
    have rejectedFalse : branches.rejects.eval assignment Locals.empty = false := by
      apply Bool.eq_false_iff.mpr
      intro rejected
      have semanticRejected :=
        (append_receive_rejects_correct assignment columns arrays rep destination
          packet request samePacket).mp rejected
      change request.term < old.currentTerm \/
        (request.term = old.currentTerm /\ old.role = .follower /\
          Not (NativeArrayAppendReceive.LogOk
            old.log request.prevLogIndex request.prevLogTerm)) at semanticRejected
      rcases semanticRejected with stale | ⟨_, follower, _⟩
      · omega
      · rcases semanticStep.2 with candidateRole | candidateRole <;>
          rw [follower] at candidateRole <;> contradiction
    let response :=
      successResponse old.toModel request (request.prevLogIndex + request.entries.length)
    have responseCorrect :=
      append_receive_response_ack_model_correct assignment columns arrays rep source
        destination packet best request samePacket sameSource sameDestination rejectedFalse
    have endpoints : response.source = destination /\ response.destination = source := by
      simp [response, successResponse, sameSource, sameDestination]
    refine ⟨candidate, output, response, candidateRep, outputRep, responseCorrect,
      endpoints.1, endpoints.2, ?_, ?_, sameLog, sameCommitValue⟩
    · intro _
      refine ⟨semanticStep.1, semanticStep.2, ?_⟩
      rw [stepOutput stepTrue, candidateOld]
    · intro impossible
      change step = false at impossible
      exact False.elim (Bool.noConfusion (stepTrue.symm.trans impossible))
  · have stepFalse : step = false := Bool.eq_false_iff.mpr stepTrue
    have handlesTrue : branches.handles.eval assignment Locals.empty = true := by
      have enabled :
          step = true \/ branches.handles.eval assignment Locals.empty = true := by
        simpa [branches, step, Term.eval] using localEnabled
      exact enabled.resolve_left stepTrue
    obtain ⟨response, handled, responseCorrect⟩ :=
      append_receive_handler_correct assignment columns arrays rep source destination
        packet request samePacket sameSource sameDestination best candidateSignature
        handlesTrue latest nackAccepted
    have endpoints :=
      append_receive_response_term_endpoints assignment columns source destination
        packet best response responseCorrect
    refine ⟨candidate, output, response, candidateRep, outputRep, responseCorrect,
      endpoints.1, endpoints.2, ?_, ?_, sameLog, sameCommitValue⟩
    · intro impossible
      change step = true at impossible
      exact False.elim (stepTrue impossible)
    · intro _
      exact ⟨handled, consumeOutput stepFalse⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
