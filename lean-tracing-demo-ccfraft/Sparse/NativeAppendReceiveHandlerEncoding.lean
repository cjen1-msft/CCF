-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendReceiveResponseEncoding
import Sparse.NativeArrayAppendCandidate
import Sparse.NativeArrayAppendNetwork
import Sparse.NativeNodeRowWritesEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt NativeArrayAppendHandler NativeArrayAppendHandlerCases
  NativeArrayAppendReceive NativeArrayCheckQuorum NativeArrayLogWrite
  NativeArrayVote

theorem append_receive_handles_excludes_step_down {width : PNat}
    [Bootstrap (Fin width)]
    (assignment : Assignment) (columns : Columns)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays) (destination : Fin width)
    (packet : Expr (packetTy width))
    (request : AppendEntriesRequest (Fin width) Nat)
    (samePacket :
      packet.eval assignment Locals.empty =
        packetValue (.appendEntriesRequest request))
    (handles :
      (appendReceiveTerms columns destination packet).handles.eval
        assignment Locals.empty = true) :
    (appendReceiveTerms columns destination packet).stepDown.eval
        assignment Locals.empty = false := by
  let row := NativeArrayCheckQuorum.get arrays destination
  let payload := NativeArrayCheckQuorum.Log.ofList request.entries
  have semanticHandles : Handles row request payload :=
    (append_receive_handles_correct assignment columns arrays rep destination
      packet request payload samePacket
      (NativeArrayCheckQuorum.Log.decode_ofList request.entries).symm).mp handles
  have handled :=
    (NativeArrayAppendHandlerCases.handles_iff row request payload
      (NativeArrayCheckQuorum.Log.decode_ofList request.entries).symm).mp semanticHandles
  cases result : handleAppendEntriesRequest? row.toModel request with
  | none =>
      simp [result] at handled
  | some pair =>
      have noStepDown :=
        NativeArrayAppendNetwork.successful_handler_excludes_stepdown
          row request pair.1 pair.2 result
      apply Bool.eq_false_iff.mpr
      intro encodedStepDown
      have semanticStepDown :=
        (append_receive_step_down_correct assignment columns arrays rep destination
          packet request samePacket).mp encodedStepDown
      have stepped :=
        NativeArrayAppendReceive.return_to_follower_success row request
          semanticStepDown.1 semanticStepDown.2
      rw [stepped] at noStepDown
      contradiction

theorem append_receive_handler_correct {width : PNat}
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
    (best : Expr .int) (signature : Nat)
    (handles :
      (appendReceiveTerms columns destination packet).handles.eval
        assignment Locals.empty = true)
    (latest :
      (appendReceiveTerms columns destination packet).acceptable.eval
          assignment Locals.empty = true ->
        SignatureIndex
          (take
            (NativeArrayAppendCandidate.candidateLog
              (NativeArrayCheckQuorum.get arrays destination) request
              (NativeArrayCheckQuorum.Log.ofList request.entries)
              ((appendReceiveTerms columns destination packet).acceptable.eval
                assignment Locals.empty)
              ((appendReceiveTerms columns destination packet).alreadyDone.eval
                assignment Locals.empty))
            (min request.leaderCommit
              (request.prevLogIndex +
                (NativeArrayCheckQuorum.Log.ofList request.entries).length)))
          signature)
    (nackAccepted :
      (implies
        (.and
          (appendReceiveTerms columns destination packet).rejects
          (appendReceiveNackHint columns destination packet))
        (let requestPayload := appendRequestPayloadTerm packet
         let old := nodeRowSnapshot columns destination
         nackMatchTerm width old.logLength old.logEntries requestPayload.fst
           requestPayload.snd.fst best)).eval assignment Locals.empty = true) :
    let branches := appendReceiveTerms columns destination packet
    let payload := NativeArrayCheckQuorum.Log.ofList request.entries
    let row := NativeArrayCheckQuorum.get arrays destination
    let acceptable := branches.acceptable.eval assignment Locals.empty
    let done := branches.alreadyDone.eval assignment Locals.empty
    let conflict := branches.conflict.eval assignment Locals.empty
    exists response : AppendEntriesResponse (Fin width),
      handleAppendEntriesRequest? row.toModel request =
        some ((NativeArrayAppendCandidate.candidateRow row request payload signature
          acceptable done conflict).toModel, response) /\
      (appendReceiveResponseTerm columns source destination packet best).eval
          assignment Locals.empty =
        packetValue (.appendEntriesResponse response) := by
  let branches := appendReceiveTerms columns destination packet
  let requestPayload := appendRequestPayloadTerm packet
  let payload := NativeArrayCheckQuorum.Log.ofList request.entries
  let row := NativeArrayCheckQuorum.get arrays destination
  let old := nodeRowSnapshot columns destination
  let acceptable := branches.acceptable.eval assignment Locals.empty
  let done := branches.alreadyDone.eval assignment Locals.empty
  let conflict := branches.conflict.eval assignment Locals.empty
  have samePayload : request.entries = payload.decode :=
    (NativeArrayCheckQuorum.Log.decode_ofList request.entries).symm
  have acceptableCorrect :
      acceptable = true <-> Acceptable row request := by
    simpa [acceptable, branches, row] using
      append_receive_acceptable_correct assignment columns arrays rep destination
        packet request samePacket
  have doneCorrect :
      done = true <->
        NativeArrayLogRanges.AlreadyDone row.log payload request.prevLogIndex := by
    simpa [done, branches, row, payload] using
      append_receive_already_done_correct assignment columns arrays rep destination
        packet request payload samePacket samePayload
  have conflictCorrect :
      conflict = true <->
        NativeArrayLogRanges.HasTermConflict row.log payload request.prevLogIndex := by
    simpa [conflict, branches, row, payload] using
      append_receive_conflict_correct assignment columns arrays rep destination
        packet request payload samePacket samePayload
  have rejectsCorrect :
      branches.rejects.eval assignment Locals.empty = true <->
        request.term < row.currentTerm \/
          (request.term = row.currentTerm /\ row.role = .follower /\
            Not (LogOk row.log request.prevLogIndex request.prevLogTerm)) := by
    simpa [branches, row] using
      append_receive_rejects_correct assignment columns arrays rep destination
        packet request samePacket
  have semanticHandles : Handles row request payload := by
    simpa [branches, row, payload] using
      (append_receive_handles_correct assignment columns arrays rep destination
        packet request payload samePacket samePayload).mp handles
  have handlerResult :=
    NativeArrayAppendCandidate.candidate_handler_result row request payload signature
      acceptable done conflict samePayload acceptableCorrect doneCorrect conflictCorrect
      latest semanticHandles
  by_cases acceptableTrue : acceptable = true
  · have rejectedFalse : branches.rejects.eval assignment Locals.empty = false := by
      apply Bool.eq_false_iff.mpr
      intro rejected
      exact NativeArrayAppendCandidate.acceptable_not_native_rejected row request
        (acceptableCorrect.mp acceptableTrue) (rejectsCorrect.mp rejected)
    let response :=
      successResponse row.toModel request (request.prevLogIndex + payload.length)
    refine ⟨response, ?_, ?_⟩
    · change handleAppendEntriesRequest? row.toModel request =
        some ((NativeArrayAppendCandidate.candidateRow row request payload signature
          acceptable done conflict).toModel, response)
      simpa [response, acceptableTrue] using handlerResult
    · have encoded :=
        append_receive_response_ack_model_correct assignment columns arrays rep
          source destination packet best request samePacket sameSource sameDestination
          rejectedFalse
      simpa [response, payload, NativeArrayCheckQuorum.Log.ofList] using encoded
  · have acceptableFalse : acceptable = false :=
      Bool.eq_false_iff.mpr acceptableTrue
    have rejectedTrue : branches.rejects.eval assignment Locals.empty = true := by
      rcases semanticHandles with rejected | ⟨accepted, _⟩
      · exact rejectsCorrect.mpr rejected
      · exact False.elim (acceptableTrue (acceptableCorrect.mpr accepted))
    have bestMatch :
        (appendReceiveNackHint columns destination packet).eval
            assignment Locals.empty = true ->
          exists bestNat : Nat,
            best.eval assignment Locals.empty = (bestNat : Int) /\
            Sparse.LogMatchSummary.StorageSummary row.log.length
              request.prevLogIndex bestNat
              (fun position => (row.log.entries position).term <=
                request.prevLogTerm) := by
      intro hinted
      have scanHolds :
          (nackMatchTerm width old.logLength old.logEntries requestPayload.fst
            requestPayload.snd.fst best).eval assignment Locals.empty = true := by
        apply (implies_eval
          (.and branches.rejects (appendReceiveNackHint columns destination packet))
          (nackMatchTerm width old.logLength old.logEntries requestPayload.fst
            requestPayload.snd.fst best) assignment Locals.empty).mp
          (by simpa [branches, old, requestPayload] using nackAccepted)
        simp [Term.eval, rejectedTrue, hinted]
      have payloadValue :=
        append_request_payload_term_correct packet assignment Locals.empty request
          samePacket
      have samePrevious :
          requestPayload.fst.eval assignment Locals.empty =
            (request.prevLogIndex : Int) := by
        simpa [requestPayload, Term.eval] using congrArg Prod.fst payloadValue
      have samePreviousTerm :
          requestPayload.snd.fst.eval assignment Locals.empty =
            (request.prevLogTerm : Int) := by
        simpa [requestPayload, Term.eval] using
          congrArg (fun value => value.2.1) payloadValue
      have oldRep := node_row_snapshot_rep assignment columns arrays rep destination
      obtain ⟨bestNat, sameBest, selected⟩ :=
        nack_match_term_sound assignment Locals.empty old.logLength old.logEntries
          requestPayload.fst requestPayload.snd.fst best row.log
          request.prevLogIndex request.prevLogTerm oldRep.logLength samePrevious
          samePreviousTerm oldRep.logEntries scanHolds
      exact ⟨bestNat, sameBest,
        (NativeArrayAppendReceive.nack_match_correct row.log request.prevLogIndex
          request.prevLogTerm bestNat).mpr selected⟩
    let response := failureResponse row.toModel request
    refine ⟨response, ?_, ?_⟩
    · change handleAppendEntriesRequest? row.toModel request =
        some ((NativeArrayAppendCandidate.candidateRow row request payload signature
          acceptable done conflict).toModel, response)
      simpa [response, acceptableFalse] using handlerResult
    · exact append_receive_response_rejected_correct assignment columns arrays rep
        source destination packet best request samePacket sameSource sameDestination
        rejectedTrue bestMatch

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
