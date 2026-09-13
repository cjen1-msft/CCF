-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeVoteResponse
import Sparse.NativeArrayVoteResponse
import Sparse.NativeQueueHeadEncoding
import Sparse.NativeNodeRowWritesEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem vote_response_granted_term_correct {context : List Ty} {width : PNat}
    (packet : Term context (packetTy width)) (assignment : Assignment)
    (locals : Locals context) (preVote : Bool)
    (response : RequestVoteResponse (Fin width))
    (samePacket :
      packet.eval assignment locals =
        packetValue (NativeArrayVoteResponse.packet preVote response)) :
    (voteResponseGrantedTerm packet).eval assignment locals =
      response.voteGranted := by
  cases preVote <;>
    simp [voteResponseGrantedTerm, Term.eval, samePacket,
      NativeArrayVoteResponse.packet, packetValue, packetPayloadValue, Locals.cons]

theorem vote_response_kind_term_correct {context : List Ty} {width : PNat}
    (packet : Term context (packetTy width)) (assignment : Assignment)
    (locals : Locals context) (preVote : Bool) (message : Message (Fin width) Nat)
    (samePacket : packet.eval assignment locals = packetValue message) :
    (packetPayloadPatternTerm
        (if preVote then .requestPreVoteResponse none
          else .requestVoteResponse none)
        (.snd packet)).eval assignment locals = true <->
      exists response : RequestVoteResponse (Fin width),
        message = NativeArrayVoteResponse.packet preVote response := by
  cases preVote <;> cases message <;>
    simp [packetPayloadPatternTerm, optionalPatternTerm, Term.eval, samePacket,
      packetValue, packetPayloadValue, NativeArrayVoteResponse.packet, Locals.cons]
  case true.requestPreVoteResponse response =>
    exact ⟨
      { term := response.term
        voteGranted := response.voteGranted
        source := response.source
        destination := response.destination },
      by cases response; rfl⟩

theorem vote_response_guards_correct {width : PNat}
    (assignment : Assignment) (columns : Columns)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment columns frame)
    (preVote : Bool) (source destination : Fin width) :
    Holds (voteResponseGuards columns preVote source destination) assignment <->
      exists response : RequestVoteResponse (Fin width),
        (frame.queues destination source).peek =
          some (NativeArrayVoteResponse.packet preVote response) /\
        NativeArrayVoteResponse.enabled frame preVote destination response := by
  by_cases nonempty : 0 < (frame.queues destination source).length
  · let message :=
      (frame.queues destination source).cells
        (frame.queues destination source).head
    have samePacket :=
      queue_head_packet_term_correct assignment columns frame rep source destination
        nonempty
    have packetKind :=
      vote_response_kind_term_correct
        (queueHeadPacketTerm columns source destination) assignment Locals.empty
        preVote message samePacket
    have sameSource : message.source = source :=
      rep.queue_head_source source destination nonempty
    have lengthValue :
        (queueScalarTerm columns.queueLength (.integer destination.val)
          (.integer source.val) : Expr .int).eval assignment Locals.empty =
            ((frame.queues destination source).length : Int) := by
      rw [queue_scalar_correct]
      exact congrArg (fun value : Nat => (value : Int))
        (rep.queue_length destination source)
    have rowRep :=
      node_row_snapshot_rep assignment columns frame.nodes rep.nodes destination
    have reduced :
        Holds (voteResponseGuards columns preVote source destination) assignment <->
          (frame.nodes destination).isSome = true /\
            (exists response : RequestVoteResponse (Fin width),
              message = NativeArrayVoteResponse.packet preVote response) /\
            message.destination = destination /\
            ((frame.nodes source).isSome = true ->
              message.term <=
                  (NativeArrayCheckQuorum.get frame.nodes destination).currentTerm \/
                (NativeArrayCheckQuorum.get frame.nodes destination).role ≠
                  (if preVote then .preVoteCandidate else .candidate)) := by
      simp [Holds, voteResponseGuards, lt, implies, Term.eval,
        rep.nodes.allocated, rowRep.currentTerm, rowRep.role, lengthValue,
        packetKind, samePacket, packetValue, packetHeaderValue,
        Nat.ne_of_gt nonempty, role_code_eq, Fin.ext_iff, message,
        Option.isSome_iff_ne_none]
      tauto
    rw [reduced]
    constructor
    · rintro ⟨present, ⟨response, same⟩, recipient, handler⟩
      have responseSource : response.source = source := by
        cases preVote <;>
          simpa [same, NativeArrayVoteResponse.packet] using sameSource
      refine ⟨response, ?_, ?_⟩
      · simpa only [NativeArrayQueue.Queue.peek, if_pos nonempty,
          Option.some.injEq] using congrArg some same
      · rw [NativeArrayVoteResponse.enabled]
        refine ⟨present, ?_, ?_⟩
        · cases preVote <;>
            simpa [same, NativeArrayVoteResponse.packet] using recipient
        · rw [same] at handler
          cases preVote <;>
            simpa only [NativeArrayVoteResponse.handlerEnabled, Bool.false_eq_true,
              Bool.true_eq, if_false, if_true, responseSource,
              NativeArrayVoteResponse.packet, Message.term] using handler
    · rintro ⟨response, selected, present, recipient, handler⟩
      have same :
          message = NativeArrayVoteResponse.packet preVote response := by
        simpa only [NativeArrayQueue.Queue.peek, if_pos nonempty,
          Option.some.injEq] using selected
      have responseSource : response.source = source := by
        cases preVote <;>
          simpa [same, NativeArrayVoteResponse.packet] using sameSource
      refine ⟨present, ⟨response, same⟩, ?_, ?_⟩
      · cases preVote <;>
          simpa [same, NativeArrayVoteResponse.packet] using recipient
      · rw [same]
        cases preVote <;>
          simpa only [NativeArrayVoteResponse.handlerEnabled, Bool.false_eq_true,
            Bool.true_eq, if_false, if_true, responseSource,
            NativeArrayVoteResponse.packet, Message.term] using handler
  · have empty : (frame.queues destination source).length = 0 := by omega
    constructor
    · intro guardHolds
      have positive :=
        guardHolds
          (lt (.integer 0)
            (queueScalarTerm columns.queueLength (.integer destination.val)
              (.integer source.val)))
          (by simp [voteResponseGuards])
      simp [lt, Term.eval, queue_scalar_correct, rep.queue_length, empty] at positive
    · rintro ⟨response, selected, _⟩
      simp [NativeArrayQueue.Queue.peek, empty] at selected

private theorem encode_bits_or_singleton {width : PNat}
    (nodes : Finset (Fin width)) (source : Fin width) :
    encodeBits nodes ||| encodeBits {source} = encodeBits (insert source nodes) := by
  apply BitVec.eq_of_getLsbD_eq
  intro index within
  let peer : Fin width := ⟨index, within⟩
  rw [BitVec.getLsbD_or]
  have indexEq : index = peer.val := rfl
  rw [indexEq]
  rw [encode_bits_bit, encode_bits_bit, encode_bits_bit]
  by_cases member : peer ∈ nodes <;> by_cases same : peer = source <;>
    simp [member, same]

theorem vote_response_row_terms_rep {width : PNat}
    (assignment : Assignment) (columns : Columns)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment columns frame)
    (preVote : Bool) (source destination : Fin width)
    (response : RequestVoteResponse (Fin width))
    (selected :
      (frame.queues destination source).peek =
        some (NativeArrayVoteResponse.packet preVote response)) :
    (voteResponseRowTerms columns preVote source destination).Rep assignment
      (if (frame.nodes response.source).isSome then
        NativeArrayVoteResponse.nextRow
          (NativeArrayCheckQuorum.get frame.nodes destination) preVote response
      else NativeArrayCheckQuorum.get frame.nodes destination) := by
  have nonempty : 0 < (frame.queues destination source).length := by
    by_contra notPositive
    have empty : (frame.queues destination source).length = 0 := by omega
    simp [NativeArrayQueue.Queue.peek, empty] at selected
  let old := NativeArrayCheckQuorum.get frame.nodes destination
  have samePacket :=
    queue_head_packet_term_correct assignment columns frame rep source destination
      nonempty
  have sameSource :
      (NativeArrayVoteResponse.packet (T := Nat) preVote response).source = source := by
    have headSource := rep.queue_head_source source destination nonempty
    have headValue :
        (frame.queues destination source).cells
            (frame.queues destination source).head =
          NativeArrayVoteResponse.packet preVote response := by
      simpa only [NativeArrayQueue.Queue.peek, if_pos nonempty,
        Option.some.injEq] using selected
    simpa only [headValue] using headSource
  have responseSource : response.source = source := by
    cases voteMode : preVote <;>
      simp only [NativeArrayVoteResponse.packet, voteMode, Bool.false_eq_true,
        if_false, if_true, Message.source] at sameSource
    all_goals exact sameSource
  have headValue :
      (frame.queues destination source).cells
          (frame.queues destination source).head =
        NativeArrayVoteResponse.packet preVote response := by
    simpa only [NativeArrayQueue.Queue.peek, if_pos nonempty,
      Option.some.injEq] using selected
  have selectedPacket :
      (queueHeadPacketTerm columns source destination).eval
          assignment Locals.empty =
        packetValue (NativeArrayVoteResponse.packet preVote response) :=
    samePacket.trans (congrArg packetValue headValue)
  have responseTerm :
      (Term.fst (Term.fst
        (queueHeadPacketTerm columns source destination))).eval
          assignment Locals.empty = (response.term : Int) := by
    have same := congrArg (fun value => value.1.1) selectedPacket
    cases preVote <;>
      simpa [packetValue, packetHeaderValue, NativeArrayVoteResponse.packet] using same
  have responseMessageTerm :
      (NativeArrayVoteResponse.packet (T := Nat) preVote response).term =
        response.term := by
    cases preVote <;> rfl
  have oldRep :
      (nodeRowSnapshot columns destination).Rep assignment old :=
    node_row_snapshot_rep assignment columns frame.nodes rep.nodes destination
  have sourceAllocated :
      (allocated columns source.val : Expr .bool).eval assignment Locals.empty =
        (frame.nodes response.source).isSome := by
    simpa only [responseSource] using rep.nodes.allocated source
  have grantedValue :
      (voteResponseGrantedTerm
        (queueHeadPacketTerm columns source destination)).eval
          assignment Locals.empty = response.voteGranted :=
    vote_response_granted_term_correct
      (queueHeadPacketTerm columns source destination) assignment Locals.empty
      preVote response selectedPacket
  by_cases sourcePresent : (frame.nodes response.source).isSome = true
  · by_cases grant :
        response.term = old.currentTerm /\
          old.role = (if preVote then .preVoteCandidate else .candidate) /\
          response.voteGranted = true
    · have sourcePresent' : (frame.nodes source).isSome = true := by
        simpa only [responseSource] using sourcePresent
      cases voteMode : preVote <;>
        simp only [voteMode, Bool.false_eq_true, if_false, if_true] at grant
      all_goals
        constructor <;>
        simp [voteResponseRowTerms, NativeArrayVoteResponse.nextRow,
          voteMode, NativeArrayVoteResponse.packet, old, oldRep.role, oldRep.newFollower,
          oldRep.logLength, oldRep.commit, oldRep.currentTerm,
          oldRep.retirementIndex, oldRep.retirementCommittableIndex,
          oldRep.retiredCommittedIndex, oldRep.votedFor, oldRep.votesGranted,
          oldRep.preVotesGranted, oldRep.membershipState, oldRep.sentIndex,
          oldRep.matchIndex, sourceAllocated, selectedPacket, grantedValue,
          sourcePresent', grant,
          encode_bits_or_singleton,
          responseSource, packetValue, packetHeaderValue, all, Term.eval,
          Message.term]
      all_goals try
        exact fun index live => oldRep.logEntries index live
    · have sourcePresent' : (frame.nodes source).isSome = true := by
        simpa only [responseSource] using sourcePresent
      cases voteMode : preVote <;>
        simp only [voteMode, Bool.false_eq_true, if_false, if_true] at grant
      all_goals
        constructor <;>
        simp [voteResponseRowTerms, NativeArrayVoteResponse.nextRow,
          voteMode, NativeArrayVoteResponse.packet, old, oldRep.role, oldRep.newFollower,
          oldRep.logLength, oldRep.commit, oldRep.currentTerm,
          oldRep.retirementIndex, oldRep.retirementCommittableIndex,
          oldRep.retiredCommittedIndex, oldRep.votedFor, oldRep.votesGranted,
          oldRep.preVotesGranted, oldRep.membershipState, oldRep.sentIndex,
          oldRep.matchIndex, sourceAllocated, selectedPacket, grantedValue,
          sourcePresent', grant, role_code_eq,
          responseSource, packetValue, packetHeaderValue, all, Term.eval,
          Message.term]
      all_goals try
        exact fun index live => oldRep.logEntries index live
  · have sourceAbsent : (frame.nodes source).isSome ≠ true := by
      simpa only [responseSource] using sourcePresent
    cases voteMode : preVote <;>
      all_goals
      constructor <;>
      simp [voteResponseRowTerms,
        voteMode, NativeArrayVoteResponse.packet, old, oldRep.role, oldRep.newFollower,
        oldRep.logLength, oldRep.commit, oldRep.currentTerm,
        oldRep.retirementIndex, oldRep.retirementCommittableIndex,
        oldRep.retiredCommittedIndex, oldRep.votedFor, oldRep.votesGranted,
        oldRep.preVotesGranted, oldRep.membershipState, oldRep.sentIndex,
        oldRep.matchIndex, sourceAllocated, selectedPacket, grantedValue,
        sourceAbsent, role_code_eq, responseSource, packetValue,
        packetHeaderValue, all, Term.eval, Message.term]
    all_goals try
      exact fun index live => oldRep.logEntries index live

private theorem queue_head_packet_term_bounded {width : PNat}
    (before : Encoding width) (source destination : Fin width)
    (valid : ReferencesValid before) :
    (queueHeadPacketTerm before.toColumns source destination :
      Expr (packetTy width)).symbols.all
      (fun symbol => symbol.2 < before.next) = true := by
  simp [queueHeadPacketTerm, queuePacketTerm, queuePacketDomain, packetDomain,
    packetHeaderDomain, optionalNodeDomain, packetPayloadDomain,
    appendPayloadDomain, naturalPairDomain, logDomain, logCellDomain, entryDomain,
    defaultQueuePacketTerm, packetHeaderTerm, queueCellsTerm, queueScalarTerm,
    defaultLogEntry, entryTerm, contentTerm, packetSource, implies, all,
    lt, Term.symbols, Term.weaken_symbols, valid.queueCells, valid.queueHead]

theorem vote_response_row_terms_bounded {width : PNat}
    (before : Encoding width) (preVote : Bool) (source destination : Fin width)
    (valid : ReferencesValid before) :
    (voteResponseRowTerms before.toColumns preVote source destination).Bounded
      before.next := by
  have oldBounded := node_row_snapshot_bounded before destination valid
  have packetBounded :=
    queue_head_packet_term_bounded before source destination valid
  have packetSymbols := List.all_eq_true.mp packetBounded
  cases voteMode : preVote
  · change ({ nodeRowSnapshot before.toColumns destination with
      votesGranted := _ }).Bounded before.next
    exact { oldBounded with
      votesGranted := by
        simp [voteResponseGrantedTerm, all, Term.symbols,
          oldBounded.currentTerm, oldBounded.role, oldBounded.votesGranted]
        constructor
        · intro sort id member
          simp [allocated, Term.symbols] at member
          rcases member with ⟨_, rfl⟩
          exact valid.allocated
        · intro sort id member
          simpa using packetSymbols (sort, id) member }
  · change ({ nodeRowSnapshot before.toColumns destination with
      preVotesGranted := _ }).Bounded before.next
    exact { oldBounded with
      preVotesGranted := by
        simp [voteResponseGrantedTerm, all, Term.symbols,
          oldBounded.currentTerm, oldBounded.role, oldBounded.preVotesGranted]
        constructor
        · intro sort id member
          simp [allocated, Term.symbols] at member
          rcases member with ⟨_, rfl⟩
          exact valid.allocated
        · intro sort id member
          simpa using packetSymbols (sort, id) member }

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
