-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendReceiveResponse
import Sparse.NativeAppendReceiveTermsEncoding
import Sparse.NativeLogSummaryEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt NativeArrayCheckQuorum NativeArrayVote

theorem append_receive_nack_hint_correct {width : PNat}
    (assignment : Assignment) (columns : Columns)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays) (destination : Fin width)
    (packet : Expr (packetTy width))
    (request : AppendEntriesRequest (Fin width) Nat)
    (samePacket :
      packet.eval assignment Locals.empty = packetValue (.appendEntriesRequest request)) :
    (appendReceiveNackHint columns destination packet).eval
        assignment Locals.empty = true <->
      (NativeArrayCheckQuorum.get arrays destination).currentTerm <= request.term /\
        request.prevLogIndex ≠ 0 /\
        request.prevLogIndex <=
          (NativeArrayCheckQuorum.get arrays destination).log.length /\
        NativeArrayVote.termAt
          (NativeArrayCheckQuorum.get arrays destination).log
          (NativeArrayCheckQuorum.get arrays destination).log.length ≠ 0 := by
  have payloadValue :=
    append_request_payload_term_correct packet assignment Locals.empty request samePacket
  have lastTerm := log_term_at_correct assignment Locals.empty columns arrays rep
    destination (length columns destination.val)
    (NativeArrayCheckQuorum.get arrays destination).log.length (rep.length destination)
  simp [appendReceiveNackHint, all, List.foldr_cons, List.foldr_nil,
    Term.eval, Bool.and_eq_true,
    decide_eq_false_iff_not, decide_eq_true_eq, lt, samePacket, packetValue,
    packetHeaderValue, Message.term, rep.currentTerm, payloadValue, rep.length,
    lastTerm]

theorem append_receive_response_ordinary_nack_correct {width : PNat}
    (assignment : Assignment) (columns : Columns)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays)
    (source destination : Fin width) (packet : Expr (packetTy width))
    (best : Expr .int)
    (rejected :
      (appendReceiveTerms columns destination packet).rejects.eval
        assignment Locals.empty = true)
    (noHint :
      (appendReceiveNackHint columns destination packet).eval
        assignment Locals.empty = false) :
    (appendReceiveResponseTerm columns source destination packet best).eval
        assignment Locals.empty =
      packetValue (.appendEntriesResponse {
        term := (NativeArrayCheckQuorum.get arrays destination).currentTerm
        success := false
        lastLogIndex := (NativeArrayCheckQuorum.get arrays destination).log.length
        source := destination
        destination := source
      }) := by
  apply append_response_term_eval assignment Locals.empty destination source
  · simp [Term.eval, rejected, noHint, rep.currentTerm]
  · simp [Term.eval, rejected]
  · simp [Term.eval, rejected, noHint, rep.length]

theorem append_receive_response_ack_correct {width : PNat}
    (assignment : Assignment) (columns : Columns)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays)
    (source destination : Fin width) (packet : Expr (packetTy width))
    (best : Expr .int) (request : AppendEntriesRequest (Fin width) Nat)
    (samePacket :
      packet.eval assignment Locals.empty = packetValue (.appendEntriesRequest request))
    (accepted :
      (appendReceiveTerms columns destination packet).rejects.eval
        assignment Locals.empty = false) :
    (appendReceiveResponseTerm columns source destination packet best).eval
        assignment Locals.empty =
      packetValue (.appendEntriesResponse {
        term := (NativeArrayCheckQuorum.get arrays destination).currentTerm
        success := true
        lastLogIndex := request.prevLogIndex + request.entries.length
        source := destination
        destination := source
      }) := by
  have payloadValue :=
    append_request_payload_term_correct packet assignment Locals.empty request samePacket
  apply append_response_term_eval assignment Locals.empty destination source
  · simp [Term.eval, accepted, rep.currentTerm]
  · simp [Term.eval, accepted]
  · simp [Term.eval, accepted, payloadValue, logValue]

theorem append_receive_response_ack_model_correct {width : PNat}
    (assignment : Assignment) (columns : Columns)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays)
    (source destination : Fin width) (packet : Expr (packetTy width))
    (best : Expr .int) (request : AppendEntriesRequest (Fin width) Nat)
    (samePacket :
      packet.eval assignment Locals.empty = packetValue (.appendEntriesRequest request))
    (sameSource : request.source = source)
    (sameDestination : request.destination = destination)
    (accepted :
      (appendReceiveTerms columns destination packet).rejects.eval
        assignment Locals.empty = false) :
    (appendReceiveResponseTerm columns source destination packet best).eval
        assignment Locals.empty =
      packetValue (.appendEntriesResponse
        (successResponse (NativeArrayCheckQuorum.get arrays destination).toModel
          request (request.prevLogIndex + request.entries.length))) := by
  rw [append_receive_response_ack_correct assignment columns arrays rep source
    destination packet best request samePacket accepted]
  congr 2
  simp [successResponse, Local.toModel, sameSource, sameDestination]

theorem append_receive_response_hinted_nack_correct {width : PNat}
    [Bootstrap (Fin width)]
    (assignment : Assignment) (columns : Columns)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays)
    (source destination : Fin width) (packet : Expr (packetTy width))
    (best : Expr .int) (request : AppendEntriesRequest (Fin width) Nat)
    (samePacket :
      packet.eval assignment Locals.empty = packetValue (.appendEntriesRequest request))
    (sameSource : request.source = source)
    (sameDestination : request.destination = destination)
    (rejected :
      (appendReceiveTerms columns destination packet).rejects.eval
        assignment Locals.empty = true)
    (hinted :
      (appendReceiveNackHint columns destination packet).eval
        assignment Locals.empty = true)
    (bestNat : Nat) (sameBest : best.eval assignment Locals.empty = (bestNat : Int))
    (bestMatch : Sparse.LogMatchSummary.StorageSummary
      (NativeArrayCheckQuorum.get arrays destination).log.length
      request.prevLogIndex bestNat
      (fun position =>
        ((NativeArrayCheckQuorum.get arrays destination).log.entries position).term <=
          request.prevLogTerm)) :
    (appendReceiveResponseTerm columns source destination packet best).eval
        assignment Locals.empty =
      packetValue (.appendEntriesResponse
        (failureResponse
          (NativeArrayCheckQuorum.get arrays destination).toModel request)) := by
  let row := NativeArrayCheckQuorum.get arrays destination
  have hint := (append_receive_nack_hint_correct assignment columns arrays rep
    destination packet request samePacket).mp hinted
  have bestTerm := log_term_at_correct assignment Locals.empty columns arrays rep
    destination best bestNat sameBest
  have nack :
      NativeArrayAppendReceive.nackResponse row request bestNat = {
        term := if bestNat = 0 then TERM_ONE else NativeArrayVote.termAt row.log bestNat
        success := false
        lastLogIndex := bestNat
        source := destination
        destination := source
      } := by
    simp [NativeArrayAppendReceive.nackResponse, row,
      not_lt_of_ge hint.1, hint.2.1, not_lt_of_ge hint.2.2.1, hint.2.2.2,
      sameSource, sameDestination]
  dsimp only [row] at nack
  rw [<- NativeArrayAppendReceive.nack_response_correct row request bestNat bestMatch,
    nack]
  apply append_response_term_eval assignment Locals.empty destination source
  · simp [Term.eval, rejected, hinted, sameBest, bestTerm]
  · simp [Term.eval, rejected]
  · simp [Term.eval, rejected, hinted, sameBest]

private theorem failure_response_ordinary_of_not_hint {width : PNat}
    [Bootstrap (Fin width)]
    (row : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (request : AppendEntriesRequest (Fin width) Nat)
    (notHint : Not (
      row.currentTerm <= request.term /\
        request.prevLogIndex ≠ 0 /\
        request.prevLogIndex <= row.log.length /\
        NativeArrayVote.termAt row.log row.log.length ≠ 0)) :
    failureResponse row.toModel request = {
      term := row.currentTerm
      success := false
      lastLogIndex := row.log.length
      source := request.destination
      destination := request.source
    } := by
  simp only [failureResponse, Local.toModel]
  rw [NativeArrayCheckQuorum.Log.decode_length,
    <- NativeArrayVote.term_at_correct row.log row.log.length]
  by_cases stale : request.term < row.currentTerm
  · simp [stale]
  · by_cases zero : request.prevLogIndex = 0
    · simp [stale, zero]
    · by_cases beyond : row.log.length < request.prevLogIndex
      · simp [stale, zero, beyond]
      · have lastZero : NativeArrayVote.termAt row.log row.log.length = 0 := by
          by_contra nonzero
          apply notHint
          exact ⟨by omega, zero, by omega, nonzero⟩
        simp [stale, zero, beyond, lastZero]

theorem append_receive_response_rejected_correct {width : PNat}
    [Bootstrap (Fin width)]
    (assignment : Assignment) (columns : Columns)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays)
    (source destination : Fin width) (packet : Expr (packetTy width))
    (best : Expr .int) (request : AppendEntriesRequest (Fin width) Nat)
    (samePacket :
      packet.eval assignment Locals.empty = packetValue (.appendEntriesRequest request))
    (sameSource : request.source = source)
    (sameDestination : request.destination = destination)
    (rejected :
      (appendReceiveTerms columns destination packet).rejects.eval
        assignment Locals.empty = true)
    (bestMatch :
      (appendReceiveNackHint columns destination packet).eval
          assignment Locals.empty = true ->
        exists bestNat : Nat,
          best.eval assignment Locals.empty = (bestNat : Int) /\
          Sparse.LogMatchSummary.StorageSummary
            (NativeArrayCheckQuorum.get arrays destination).log.length
            request.prevLogIndex bestNat
            (fun position =>
              ((NativeArrayCheckQuorum.get arrays destination).log.entries position).term <=
                request.prevLogTerm)) :
    (appendReceiveResponseTerm columns source destination packet best).eval
        assignment Locals.empty =
      packetValue (.appendEntriesResponse
        (failureResponse
          (NativeArrayCheckQuorum.get arrays destination).toModel request)) := by
  by_cases hinted :
      (appendReceiveNackHint columns destination packet).eval
        assignment Locals.empty = true
  · obtain ⟨bestNat, sameBest, summary⟩ := bestMatch hinted
    exact append_receive_response_hinted_nack_correct assignment columns arrays rep
      source destination packet best request samePacket sameSource sameDestination
      rejected hinted bestNat sameBest summary
  · have noHint :
        (appendReceiveNackHint columns destination packet).eval
          assignment Locals.empty = false :=
      Bool.eq_false_iff.mpr hinted
    have response := append_receive_response_ordinary_nack_correct assignment columns
      arrays rep source destination packet best rejected noHint
    have semanticHint :=
      append_receive_nack_hint_correct assignment columns arrays rep destination
        packet request samePacket
    have notSemanticHint : Not (
        (NativeArrayCheckQuorum.get arrays destination).currentTerm <= request.term /\
          request.prevLogIndex ≠ 0 /\
          request.prevLogIndex <=
            (NativeArrayCheckQuorum.get arrays destination).log.length /\
          NativeArrayVote.termAt
            (NativeArrayCheckQuorum.get arrays destination).log
            (NativeArrayCheckQuorum.get arrays destination).log.length ≠ 0) := by
      intro holds
      have encoded := semanticHint.mpr holds
      rw [noHint] at encoded
      contradiction
    rw [response]
    congr 2
    rw [failure_response_ordinary_of_not_hint
      (NativeArrayCheckQuorum.get arrays destination) request notSemanticHint]
    simp [sameSource, sameDestination]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
