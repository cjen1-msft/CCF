-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeVoteReceiveGuard
import Sparse.NativeQueueHeadEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem vote_receive_guards_correct {width : PNat}
    (assignment : Assignment) (columns : Columns) (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment columns frame) (source destination : Fin width) :
    Holds (voteReceiveGuards columns source destination) assignment <->
      (frame.nodes destination).isSome = true /\
        exists request : RequestVoteRequest (Fin width),
          (frame.queues destination source).peek = some (.requestVoteRequest request) /\
          request.destination = destination /\
          request.term <= (NativeArrayCheckQuorum.get frame.nodes destination).currentTerm := by
  by_cases nonempty : 0 < (frame.queues destination source).length
  · let message := (frame.queues destination source).cells (frame.queues destination source).head
    have samePacket := queue_head_packet_term_correct assignment columns frame rep source destination nonempty
    have packetKind := is_vote_request_correct (queueHeadPacketTerm columns source destination)
      assignment Locals.empty message samePacket
    have lengthValue :
        (queueScalarTerm columns.queueLength (.integer destination.val) (.integer source.val) : Expr .int).eval
          assignment Locals.empty = ((frame.queues destination source).length : Int) := by
      rw [queue_scalar_correct]
      exact congrArg (fun value : Nat => (value : Int)) (rep.queue_length destination source)
    have reduced :
        Holds (voteReceiveGuards columns source destination) assignment <->
          (frame.nodes destination).isSome = true /\
            (exists request, message = .requestVoteRequest request) /\
            message.destination = destination /\
            message.term <= (NativeArrayCheckQuorum.get frame.nodes destination).currentTerm := by
      simp [Holds, voteReceiveGuards, lt, Term.eval, rep.nodes.allocated, rep.nodes.currentTerm,
        lengthValue, packetKind, samePacket, packetValue, packetHeaderValue, Nat.ne_of_gt nonempty,
        message, Fin.ext_iff]
    rw [reduced]
    constructor
    · rintro ⟨present, ⟨request, same⟩, recipient, term⟩
      refine ⟨present, request, ?_, ?_, ?_⟩
      · simpa only [NativeArrayQueue.Queue.peek, if_pos nonempty] using congrArg some same
      · simpa only [same, Message.destination] using recipient
      · simpa only [same, Message.term] using term
    · rintro ⟨present, request, selected, recipient, term⟩
      have same : message = .requestVoteRequest request := by
        simpa only [NativeArrayQueue.Queue.peek, if_pos nonempty, Option.some.injEq] using selected
      exact ⟨present, ⟨request, same⟩, by simpa only [same, Message.destination] using recipient,
        by simpa only [same, Message.term] using term⟩
  · have empty : (frame.queues destination source).length = 0 := by omega
    simp [Holds, voteReceiveGuards, lt, Term.eval, queue_scalar_correct, rep.queue_length,
      empty, NativeArrayQueue.Queue.peek]

theorem vote_receive_guards_model_correct {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (columns : Columns) (frame : NativeArrayVote.Frame (Fin width) Nat)
    (state : State (Fin width) Nat) (rep : FrameColumnsRep assignment columns frame)
    (model : frame.Rep state) (source destination : Fin width) :
    Holds (voteReceiveGuards columns source destination) assignment <->
      Enabled state (.receive source destination) /\
        exists request remaining, takeFirstFrom source (state.network destination) =
          some (.requestVoteRequest request, remaining) := by
  rw [vote_receive_guards_correct assignment columns frame rep source destination]
  constructor
  · rintro ⟨present, request, selected, recipient, term⟩
    obtain ⟨remaining, taken⟩ :=
      NativeArrayVoteReceive.selected_model_take frame state model source destination _ selected
    have requestSource : request.source = source :=
      (Sparse.Queue.take_some_spec source (state.network destination) _ remaining taken).1
    refine ⟨?_, request, remaining, taken⟩
    rw [<- requestSource]
    exact (NativeArrayVoteReceive.enabled_correct frame state model destination request remaining
      (by simpa only [requestSource] using taken)).mpr ⟨present, recipient, term⟩
  · rintro ⟨enabled, request, remaining, taken⟩
    have requestSource : request.source = source :=
      (Sparse.Queue.take_some_spec source (state.network destination) _ remaining taken).1
    obtain ⟨present, recipient, term⟩ :=
      (NativeArrayVoteReceive.enabled_correct frame state model destination request remaining
        (by simpa only [requestSource] using taken)).mp (by simpa only [requestSource] using enabled)
    refine ⟨present, request, ?_, recipient, term⟩
    rw [NativeArrayQueue.model_peek_correct frame.queues state.network model.queues source destination, taken]
    rfl

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
