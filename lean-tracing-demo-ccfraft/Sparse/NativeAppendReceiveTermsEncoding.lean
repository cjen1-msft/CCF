-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendReceiveTerms
import Sparse.NativeArrayAppendReceiveGuard
import Sparse.NativeQueueHeadEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem is_append_request_term_correct {context : List Ty} {width : PNat}
    (packet : Term context (packetTy width)) (assignment : Assignment)
    (locals : Locals context) (message : Message (Fin width) Nat)
    (samePacket : packet.eval assignment locals = packetValue message) :
    (isAppendRequestTerm packet).eval assignment locals = true <->
      exists request, message = .appendEntriesRequest request := by
  cases message <;>
    simp [isAppendRequestTerm, Term.eval, samePacket, packetValue,
      packetPayloadValue]

theorem append_request_payload_term_correct {context : List Ty} {width : PNat}
    (packet : Term context (packetTy width)) (assignment : Assignment)
    (locals : Locals context) (request : AppendEntriesRequest (Fin width) Nat)
    (samePacket :
      packet.eval assignment locals = packetValue (.appendEntriesRequest request)) :
    (appendRequestPayloadTerm packet).eval assignment locals =
      ((request.prevLogIndex : Int), (request.prevLogTerm : Int),
        (request.leaderCommit : Int), logValue request.entries) := by
  simp [appendRequestPayloadTerm, Term.eval, samePacket, packetValue,
    packetPayloadValue, Locals.cons]

theorem append_request_log_term_correct {context : List Ty} {width : PNat}
    (packet : Term context (packetTy width)) (assignment : Assignment)
    (locals : Locals context) (request : AppendEntriesRequest (Fin width) Nat)
    (payload : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (samePacket :
      packet.eval assignment locals = packetValue (.appendEntriesRequest request))
    (samePayload : request.entries = payload.decode) :
    let entries := (appendRequestPayloadTerm packet).snd.snd.snd
    entries.eval assignment locals = logValue request.entries /\
      entries.fst.eval assignment locals = (payload.length : Int) /\
      forall index, index < payload.length ->
        modelEntry (entries.snd.eval assignment locals (index : Int)) =
          payload.entries index := by
  intro entries
  have payloadValue :=
    append_request_payload_term_correct packet assignment locals request samePacket
  have sameLog :
      entries.eval assignment locals = logValue request.entries := by
    simpa [entries, Term.eval] using
      congrArg (fun value => value.2.2.2) payloadValue
  refine ⟨sameLog, ?_, ?_⟩
  · have sameLength := congrArg Prod.fst sameLog
    calc
      entries.fst.eval assignment locals = (request.entries.length : Int) := by
        simpa [Term.eval, logValue] using sameLength
      _ = (payload.decode.length : Int) := by rw [samePayload]
      _ = (payload.length : Int) := by
        simp [NativeArrayCheckQuorum.Log.decode]
  · intro index live
    have sameCells := congrArg Prod.snd sameLog
    calc
      modelEntry (entries.snd.eval assignment locals (index : Int)) =
          modelEntry ((logValue request.entries).2 (index : Int)) := by
            apply congrArg modelEntry
            exact congrFun sameCells (index : Int)
      _ = payload.entries index := by
        simp [logValue, samePayload, NativeArrayCheckQuorum.Log.decode, live]

private theorem append_receive_log_ok_correct {width : PNat}
    (assignment : Assignment) (columns : Columns)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays) (destination : Fin width)
    (previous previousTerm : Expr .int)
    (previousValue previousTermValue : Nat)
    (samePreviousValue : previous.eval assignment Locals.empty = (previousValue : Int))
    (samePreviousTermValue :
      previousTerm.eval assignment Locals.empty = (previousTermValue : Int)) :
    let row := NativeArrayCheckQuorum.get arrays destination
    let oldEntries : Expr (.array .int (entryTy width)) :=
      .select (.free (.array .int (.array .int (entryTy width))) columns.logEntries)
        (.integer destination.val)
    let logOk : Expr .bool := .or (.equal previous (.integer 0))
      (.and (.le previous (length columns destination.val))
        (.equal (.fst (normalizedEntryTerm
          (.select oldEntries (.sub previous (.integer 1))))) previousTerm))
    logOk.eval assignment Locals.empty = true <->
      NativeArrayAppendReceive.LogOk row.log previousValue previousTermValue := by
  intro row oldEntries logOk
  by_cases zero : previousValue = 0
  · simp [logOk, Term.eval, samePreviousValue, zero,
      NativeArrayAppendReceive.LogOk]
  · by_cases within : previousValue <= row.log.length
    · have live : previousValue - 1 < row.log.length := by omega
      have sameEntry :
          modelEntry (oldEntries.eval assignment Locals.empty
            ((previousValue : Int) - 1)) = row.log.entries (previousValue - 1) := by
        have represented := rep.entries destination (previousValue - 1) live
        have sameIndex : ((previousValue - 1 : Nat) : Int) =
            (previousValue : Int) - 1 := by omega
        simpa [oldEntries, entryAt, Term.eval, sameIndex, row] using represented
      have sameTerm :
          ((normalizedEntryTerm
            (.select oldEntries (.sub previous (.integer 1)))).fst.eval
              assignment Locals.empty) =
            ((row.log.entries (previousValue - 1)).term : Int) := by
        simp only [Term.eval, normalized_entry_term_correct, samePreviousValue]
        rw [sameEntry]
        rfl
      simp only [logOk, Term.eval, Bool.or_eq_true, decide_eq_true_eq,
        samePreviousValue, Int.ofNat_eq_zero, zero, false_or, Bool.and_eq_true,
        rep.length, Int.ofNat_le, samePreviousTermValue,
        NativeArrayAppendReceive.LogOk]
      change previousValue <= row.log.length /\
          ((normalizedEntryTerm
            (.select oldEntries (.sub previous (.integer 1)))).eval
              assignment Locals.empty).1 = (previousTermValue : Int) <->
        previousValue <= row.log.length /\
          NativeArrayVote.termAt row.log previousValue = previousTermValue
      change ((normalizedEntryTerm
        (.select oldEntries (.sub previous (.integer 1)))).eval
          assignment Locals.empty).1 =
        ((row.log.entries (previousValue - 1)).term : Int) at sameTerm
      rw [sameTerm]
      simp [within, Nat.pos_of_ne_zero zero, NativeArrayVote.termAt]
    · simp only [logOk, Term.eval, Bool.or_eq_true, decide_eq_true_eq,
        samePreviousValue, Int.ofNat_eq_zero, zero, false_or, Bool.and_eq_true,
        rep.length, Int.ofNat_le, samePreviousTermValue,
        NativeArrayAppendReceive.LogOk]
      change previousValue <= row.log.length /\ _ <->
        previousValue <= row.log.length /\ _
      simp [within]

theorem append_receive_step_down_correct {width : PNat}
    (assignment : Assignment) (columns : Columns)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays) (destination : Fin width)
    (packet : Expr (packetTy width))
    (request : AppendEntriesRequest (Fin width) Nat)
    (samePacket :
      packet.eval assignment Locals.empty = packetValue (.appendEntriesRequest request)) :
    (appendReceiveTerms columns destination packet).stepDown.eval
        assignment Locals.empty = true <->
      request.term = (NativeArrayCheckQuorum.get arrays destination).currentTerm /\
        ((NativeArrayCheckQuorum.get arrays destination).role = .candidate \/
          (NativeArrayCheckQuorum.get arrays destination).role = .preVoteCandidate) := by
  simp [appendReceiveTerms, Term.eval, samePacket, packetValue, packetHeaderValue,
    Message.term, rep.currentTerm, rep.role, role_code_eq]

theorem append_receive_rejects_correct {width : PNat}
    (assignment : Assignment) (columns : Columns)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays) (destination : Fin width)
    (packet : Expr (packetTy width))
    (request : AppendEntriesRequest (Fin width) Nat)
    (samePacket :
      packet.eval assignment Locals.empty = packetValue (.appendEntriesRequest request)) :
    (appendReceiveTerms columns destination packet).rejects.eval
        assignment Locals.empty = true <->
      request.term < (NativeArrayCheckQuorum.get arrays destination).currentTerm \/
        (request.term = (NativeArrayCheckQuorum.get arrays destination).currentTerm /\
          (NativeArrayCheckQuorum.get arrays destination).role = .follower /\
          Not (NativeArrayAppendReceive.LogOk
            (NativeArrayCheckQuorum.get arrays destination).log
            request.prevLogIndex request.prevLogTerm)) := by
  let payload := appendRequestPayloadTerm packet
  have payloadValue :=
    append_request_payload_term_correct packet assignment Locals.empty request samePacket
  have samePrevious : payload.fst.eval assignment Locals.empty =
      (request.prevLogIndex : Int) := by
    simpa [payload, Term.eval] using congrArg Prod.fst payloadValue
  have samePreviousTerm : payload.snd.fst.eval assignment Locals.empty =
      (request.prevLogTerm : Int) := by
    simpa [payload, Term.eval] using congrArg (fun value => value.2.1) payloadValue
  have logOk := append_receive_log_ok_correct assignment columns arrays rep destination
    payload.fst payload.snd.fst request.prevLogIndex request.prevLogTerm
    samePrevious samePreviousTerm
  dsimp only at logOk
  simp only [payload, Term.eval] at logOk
  simp only [appendReceiveTerms, Term.eval, Bool.or_eq_true, Bool.and_eq_true,
    Bool.not_eq_true', decide_eq_true_eq, decide_eq_false_iff_not, all,
    List.foldr_cons, List.foldr_nil, and_true, lt, samePacket, packetValue,
    packetHeaderValue, Message.term, rep.currentTerm, rep.role, role_code_eq]
  constructor
  · rintro (stale | ⟨sameTerm, follower, rejected⟩)
    · left
      exact Int.ofNat_lt.mp (lt_of_not_ge stale)
    · right
      refine ⟨Int.ofNat_inj.mp sameTerm, follower, ?_⟩
      intro accepted
      have held := logOk.mpr accepted
      rw [rejected] at held
      contradiction
  · rintro (stale | ⟨sameTerm, follower, rejected⟩)
    · left
      exact not_le_of_gt (Int.ofNat_lt.mpr stale)
    · right
      refine ⟨congrArg (fun value : Nat => (value : Int)) sameTerm, follower, ?_⟩
      apply Bool.eq_false_iff.mpr
      intro held
      exact rejected (logOk.mp held)

theorem append_receive_acceptable_correct {width : PNat}
    (assignment : Assignment) (columns : Columns)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays) (destination : Fin width)
    (packet : Expr (packetTy width))
    (request : AppendEntriesRequest (Fin width) Nat)
    (samePacket :
      packet.eval assignment Locals.empty = packetValue (.appendEntriesRequest request)) :
    (appendReceiveTerms columns destination packet).acceptable.eval
        assignment Locals.empty = true <->
      NativeArrayAppendHandler.Acceptable
        (NativeArrayCheckQuorum.get arrays destination) request := by
  let payload := appendRequestPayloadTerm packet
  have payloadValue :=
    append_request_payload_term_correct packet assignment Locals.empty request samePacket
  have samePrevious : payload.fst.eval assignment Locals.empty =
      (request.prevLogIndex : Int) := by
    simpa [payload, Term.eval] using congrArg Prod.fst payloadValue
  have samePreviousTerm : payload.snd.fst.eval assignment Locals.empty =
      (request.prevLogTerm : Int) := by
    simpa [payload, Term.eval] using congrArg (fun value => value.2.1) payloadValue
  have logOk := append_receive_log_ok_correct assignment columns arrays rep destination
    payload.fst payload.snd.fst request.prevLogIndex request.prevLogTerm
    samePrevious samePreviousTerm
  dsimp only at logOk
  simp only [payload, Term.eval] at logOk
  simp only [appendReceiveTerms, all, List.foldr_cons, List.foldr_nil, Term.eval,
    Bool.and_eq_true, decide_eq_true_eq, and_true, samePacket, packetValue,
    packetHeaderValue, Message.term, rep.currentTerm, rep.role, rep.commit,
    role_code_eq]
  simp only [NativeArrayAppendHandler.Acceptable]
  constructor
  · rintro ⟨sameTerm, follower, encodedLogOk, commitBound⟩
    refine ⟨Int.ofNat_inj.mp sameTerm, follower, logOk.mp encodedLogOk, ?_⟩
    apply Int.ofNat_le.mp
    exact commitBound.trans_eq samePrevious
  · rintro ⟨sameTerm, follower, semanticLogOk, commitBound⟩
    refine ⟨congrArg (fun value : Nat => (value : Int)) sameTerm, follower,
      logOk.mpr semanticLogOk, ?_⟩
    calc
      ((NativeArrayCheckQuorum.get arrays destination).commit : Int) <=
          (request.prevLogIndex : Int) := Int.ofNat_le.mpr commitBound
      _ = payload.fst.eval assignment Locals.empty := samePrevious.symm

theorem append_receive_already_done_correct {width : PNat}
    (assignment : Assignment) (columns : Columns)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays) (destination : Fin width)
    (packet : Expr (packetTy width))
    (request : AppendEntriesRequest (Fin width) Nat)
    (payload : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (samePacket :
      packet.eval assignment Locals.empty = packetValue (.appendEntriesRequest request))
    (samePayload : request.entries = payload.decode) :
    (appendReceiveTerms columns destination packet).alreadyDone.eval
        assignment Locals.empty = true <->
      NativeArrayLogRanges.AlreadyDone
        (NativeArrayCheckQuorum.get arrays destination).log payload
        request.prevLogIndex := by
  let requestPayload := appendRequestPayloadTerm packet
  let entries := requestPayload.snd.snd.snd
  obtain ⟨_, samePayloadLength, samePayloadEntries⟩ :=
    append_request_log_term_correct packet assignment Locals.empty request payload
      samePacket samePayload
  have payloadValue :=
    append_request_payload_term_correct packet assignment Locals.empty request samePacket
  have samePrevious : requestPayload.fst.eval assignment Locals.empty =
      (request.prevLogIndex : Int) := by
    simpa [requestPayload, Term.eval] using congrArg Prod.fst payloadValue
  have sameOldEntries : forall index,
      index < (NativeArrayCheckQuorum.get arrays destination).log.length ->
      modelEntry
          ((.select
            (.free (.array .int (.array .int (entryTy width))) columns.logEntries)
            (.integer destination.val) : Expr (.array .int (entryTy width))).eval
              assignment Locals.empty (index : Int)) =
        (NativeArrayCheckQuorum.get arrays destination).log.entries index := by
    intro index live
    simpa [entryAt, Term.eval] using rep.entries destination index live
  change (appendAlreadyDoneTerm width
    (length columns destination.val)
    (.select (.free (.array .int (.array .int (entryTy width))) columns.logEntries)
      (.integer destination.val))
    entries.fst entries.snd requestPayload.fst).eval assignment Locals.empty = true <->
      _
  exact append_already_done_term_correct assignment Locals.empty
    (length columns destination.val)
    (.select (.free (.array .int (.array .int (entryTy width))) columns.logEntries)
      (.integer destination.val))
    entries.fst entries.snd requestPayload.fst
    (NativeArrayCheckQuorum.get arrays destination).log payload request.prevLogIndex
    (rep.length destination) samePayloadLength samePrevious sameOldEntries
    samePayloadEntries

theorem append_receive_extends_log_correct {width : PNat}
    (assignment : Assignment) (columns : Columns)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays) (destination : Fin width)
    (packet : Expr (packetTy width))
    (request : AppendEntriesRequest (Fin width) Nat)
    (payload : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (samePacket :
      packet.eval assignment Locals.empty = packetValue (.appendEntriesRequest request))
    (samePayload : request.entries = payload.decode) :
    (appendReceiveTerms columns destination packet).extendsLog.eval
        assignment Locals.empty = true <->
      NativeArrayLogRanges.NoConflictExtension
        (NativeArrayCheckQuorum.get arrays destination).log payload
        request.prevLogIndex := by
  let requestPayload := appendRequestPayloadTerm packet
  let entries := requestPayload.snd.snd.snd
  obtain ⟨_, samePayloadLength, samePayloadEntries⟩ :=
    append_request_log_term_correct packet assignment Locals.empty request payload
      samePacket samePayload
  have payloadValue :=
    append_request_payload_term_correct packet assignment Locals.empty request samePacket
  have samePrevious : requestPayload.fst.eval assignment Locals.empty =
      (request.prevLogIndex : Int) := by
    simpa [requestPayload, Term.eval] using congrArg Prod.fst payloadValue
  have sameOldEntries : forall index,
      index < (NativeArrayCheckQuorum.get arrays destination).log.length ->
      modelEntry
          ((.select
            (.free (.array .int (.array .int (entryTy width))) columns.logEntries)
            (.integer destination.val) : Expr (.array .int (entryTy width))).eval
              assignment Locals.empty (index : Int)) =
        (NativeArrayCheckQuorum.get arrays destination).log.entries index := by
    intro index live
    simpa [entryAt, Term.eval] using rep.entries destination index live
  change (appendNoConflictExtensionTerm width
    (length columns destination.val)
    (.select (.free (.array .int (.array .int (entryTy width))) columns.logEntries)
      (.integer destination.val))
    entries.fst entries.snd requestPayload.fst).eval assignment Locals.empty = true <->
      _
  exact append_no_conflict_extension_term_correct assignment Locals.empty
    (length columns destination.val)
    (.select (.free (.array .int (.array .int (entryTy width))) columns.logEntries)
      (.integer destination.val))
    entries.fst entries.snd requestPayload.fst
    (NativeArrayCheckQuorum.get arrays destination).log payload request.prevLogIndex
    (rep.length destination) samePayloadLength samePrevious sameOldEntries
    samePayloadEntries

theorem append_receive_conflict_correct {width : PNat}
    (assignment : Assignment) (columns : Columns)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays) (destination : Fin width)
    (packet : Expr (packetTy width))
    (request : AppendEntriesRequest (Fin width) Nat)
    (payload : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (samePacket :
      packet.eval assignment Locals.empty = packetValue (.appendEntriesRequest request))
    (samePayload : request.entries = payload.decode) :
    (appendReceiveTerms columns destination packet).conflict.eval
        assignment Locals.empty = true <->
      NativeArrayLogRanges.HasTermConflict
        (NativeArrayCheckQuorum.get arrays destination).log payload
        request.prevLogIndex := by
  let requestPayload := appendRequestPayloadTerm packet
  let entries := requestPayload.snd.snd.snd
  obtain ⟨_, samePayloadLength, samePayloadEntries⟩ :=
    append_request_log_term_correct packet assignment Locals.empty request payload
      samePacket samePayload
  have payloadValue :=
    append_request_payload_term_correct packet assignment Locals.empty request samePacket
  have samePrevious : requestPayload.fst.eval assignment Locals.empty =
      (request.prevLogIndex : Int) := by
    simpa [requestPayload, Term.eval] using congrArg Prod.fst payloadValue
  have sameOldEntries : forall index,
      index < (NativeArrayCheckQuorum.get arrays destination).log.length ->
      modelEntry
          ((.select
            (.free (.array .int (.array .int (entryTy width))) columns.logEntries)
            (.integer destination.val) : Expr (.array .int (entryTy width))).eval
              assignment Locals.empty (index : Int)) =
        (NativeArrayCheckQuorum.get arrays destination).log.entries index := by
    intro index live
    simpa [entryAt, Term.eval] using rep.entries destination index live
  change (appendTermConflictTerm width
    (length columns destination.val)
    (.select (.free (.array .int (.array .int (entryTy width))) columns.logEntries)
      (.integer destination.val))
    entries.fst entries.snd requestPayload.fst).eval assignment Locals.empty = true <->
      _
  exact append_term_conflict_term_correct assignment Locals.empty
    (length columns destination.val)
    (.select (.free (.array .int (.array .int (entryTy width))) columns.logEntries)
      (.integer destination.val))
    entries.fst entries.snd requestPayload.fst
    (NativeArrayCheckQuorum.get arrays destination).log payload request.prevLogIndex
    (rep.length destination) samePayloadLength samePrevious sameOldEntries
    samePayloadEntries

theorem append_receive_handles_correct {width : PNat}
    (assignment : Assignment) (columns : Columns)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays) (destination : Fin width)
    (packet : Expr (packetTy width))
    (request : AppendEntriesRequest (Fin width) Nat)
    (payload : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (samePacket :
      packet.eval assignment Locals.empty = packetValue (.appendEntriesRequest request))
    (samePayload : request.entries = payload.decode) :
    (appendReceiveTerms columns destination packet).handles.eval
        assignment Locals.empty = true <->
      NativeArrayAppendHandlerCases.Handles
        (NativeArrayCheckQuorum.get arrays destination) request payload := by
  let terms := appendReceiveTerms columns destination packet
  have shape :
      terms.handles.eval assignment Locals.empty = true <->
        terms.rejects.eval assignment Locals.empty = true \/
          (terms.acceptable.eval assignment Locals.empty = true /\
            (terms.alreadyDone.eval assignment Locals.empty = true \/
              terms.extendsLog.eval assignment Locals.empty = true \/
              (terms.conflict.eval assignment Locals.empty = true /\
                (read columns columns.newFollower destination.val (.boolean true)).eval
                  assignment Locals.empty = true))) := by
    simp [terms, appendReceiveTerms, Term.eval]
  rw [shape,
    append_receive_rejects_correct assignment columns arrays rep destination packet
      request samePacket,
    append_receive_acceptable_correct assignment columns arrays rep destination packet
      request samePacket,
    append_receive_already_done_correct assignment columns arrays rep destination packet
      request payload samePacket samePayload,
    append_receive_extends_log_correct assignment columns arrays rep destination packet
      request payload samePacket samePayload,
    append_receive_conflict_correct assignment columns arrays rep destination packet
      request payload samePacket samePayload,
    rep.newFollower destination]
  rfl

theorem append_receive_guards_correct {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (columns : Columns)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment columns frame)
    (source destination : Fin width) :
    Holds (appendReceiveGuards columns source destination) assignment <->
      (frame.nodes destination).isSome = true /\
        0 < (frame.queues destination source).length /\
        exists request : AppendEntriesRequest (Fin width) Nat,
          (frame.queues destination source).peek =
            some (.appendEntriesRequest request) /\
          request.destination = destination /\
          ((request.term =
                (NativeArrayCheckQuorum.get frame.nodes destination).currentTerm /\
              ((NativeArrayCheckQuorum.get frame.nodes destination).role = .candidate \/
                (NativeArrayCheckQuorum.get frame.nodes destination).role =
                  .preVoteCandidate)) \/
            NativeArrayAppendHandlerCases.Handles
              (NativeArrayCheckQuorum.get frame.nodes destination) request
              (NativeArrayCheckQuorum.Log.ofList request.entries)) := by
  by_cases nonempty : 0 < (frame.queues destination source).length
  · let message :=
      (frame.queues destination source).cells (frame.queues destination source).head
    let packet : Expr (packetTy width) :=
      queueHeadPacketTerm columns source destination
    have samePacket :
        packet.eval assignment Locals.empty = packetValue message :=
      queue_head_packet_term_correct assignment columns frame rep source destination nonempty
    have packetKind :=
      is_append_request_term_correct packet assignment Locals.empty message samePacket
    have lengthValue :
        (queueScalarTerm columns.queueLength (.integer destination.val)
          (.integer source.val) : Expr .int).eval assignment Locals.empty =
          ((frame.queues destination source).length : Int) := by
      rw [queue_scalar_correct]
      exact congrArg (fun value : Nat => (value : Int))
        (rep.queue_length destination source)
    have shape :
        Holds (appendReceiveGuards columns source destination) assignment <->
          (allocated columns destination.val : Expr .bool).eval
              assignment Locals.empty = true /\
            (.le (.integer 1)
              (queueScalarTerm columns.queueLength (.integer destination.val)
                (.integer source.val)) : Expr .bool).eval
                assignment Locals.empty = true /\
            (isAppendRequestTerm packet).eval assignment Locals.empty = true /\
            (.equal packet.fst.snd.snd (.integer destination.val) : Expr .bool).eval
                assignment Locals.empty = true /\
            (Term.or
              (appendReceiveTerms columns destination packet).stepDown
              (appendReceiveTerms columns destination packet).handles).eval
                assignment Locals.empty = true := by
      simp [Holds, appendReceiveGuards, packet]
    rw [shape]
    constructor
    · rintro ⟨present, positive, kind, recipient, action⟩
      obtain ⟨request, sameMessage⟩ := packetKind.mp kind
      have sameRequestPacket :
          packet.eval assignment Locals.empty =
            packetValue (.appendEntriesRequest request) := by
        simpa only [sameMessage] using samePacket
      have selected :
          (frame.queues destination source).peek =
            some (.appendEntriesRequest request) := by
        simp [NativeArrayQueue.Queue.peek, nonempty, message, sameMessage]
      have recipientModel : request.destination = destination := by
        have recipientValue : (request.destination.val : Int) = destination.val := by
          simpa [Term.eval, sameRequestPacket, packetValue, packetHeaderValue,
            Message.destination] using recipient
        exact Fin.ext (Int.ofNat_inj.mp recipientValue)
      have actionCases :
          (appendReceiveTerms columns destination packet).stepDown.eval
                assignment Locals.empty = true \/
            (appendReceiveTerms columns destination packet).handles.eval
                assignment Locals.empty = true := by
        simpa [Term.eval] using action
      have stepDown :=
        append_receive_step_down_correct assignment columns frame.nodes rep.nodes
          destination packet request sameRequestPacket
      have handles :=
        append_receive_handles_correct assignment columns frame.nodes rep.nodes
          destination packet request (NativeArrayCheckQuorum.Log.ofList request.entries)
          sameRequestPacket (by simp)
      refine ⟨rep.nodes.allocated destination |>.symm.trans present,
        nonempty, request, selected, recipientModel, ?_⟩
      exact actionCases.imp stepDown.mp handles.mp
    · rintro ⟨present, _, request, selected, recipient, action⟩
      have sameMessage : message = .appendEntriesRequest request := by
        simpa [NativeArrayQueue.Queue.peek, nonempty, message] using selected
      have sameRequestPacket :
          packet.eval assignment Locals.empty =
            packetValue (.appendEntriesRequest request) := by
        simpa only [sameMessage] using samePacket
      have actionCases :
          (appendReceiveTerms columns destination packet).stepDown.eval
                assignment Locals.empty = true \/
            (appendReceiveTerms columns destination packet).handles.eval
                assignment Locals.empty = true := by
        have stepDown :=
          append_receive_step_down_correct assignment columns frame.nodes rep.nodes
            destination packet request sameRequestPacket
        have handles :=
          append_receive_handles_correct assignment columns frame.nodes rep.nodes
            destination packet request (NativeArrayCheckQuorum.Log.ofList request.entries)
            sameRequestPacket (by simp)
        exact action.imp stepDown.mpr handles.mpr
      refine ⟨rep.nodes.allocated destination |>.trans present, ?_, packetKind.mpr
        ⟨request, sameMessage⟩, ?_, ?_⟩
      · simpa [Term.eval, lengthValue] using nonempty
      · simp [Term.eval, sameRequestPacket, packetValue, packetHeaderValue,
          Message.destination, recipient]
      · simpa [Term.eval] using actionCases
  · have empty : (frame.queues destination source).length = 0 := by omega
    simp [Holds, appendReceiveGuards, Term.eval, queue_scalar_correct,
      rep.queue_length, empty]

theorem append_receive_guards_model_correct {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (columns : Columns)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (state : State (Fin width) Nat)
    (rep : FrameColumnsRep assignment columns frame) (model : frame.Rep state)
    (source destination : Fin width) :
    Holds (appendReceiveGuards columns source destination) assignment <->
      (frame.nodes destination).isSome = true /\
        0 < (frame.queues destination source).length /\
        exists request : AppendEntriesRequest (Fin width) Nat,
          (frame.queues destination source).peek =
            some (.appendEntriesRequest request) /\
          request.destination = destination /\
          CCFRaft.Enabled state (.receive source destination) := by
  rw [append_receive_guards_correct assignment columns frame rep source destination]
  constructor
  · rintro ⟨present, nonempty, request, selected, recipient, action⟩
    have enabled :=
      (NativeArrayAppendReceiveGuard.enabled_correct frame state model source destination
        request (NativeArrayCheckQuorum.Log.ofList request.entries) selected (by simp)).mpr
        ⟨present, recipient, action⟩
    exact ⟨present, nonempty, request, selected, recipient, enabled⟩
  · rintro ⟨present, nonempty, request, selected, recipient, enabled⟩
    have action :=
      (NativeArrayAppendReceiveGuard.enabled_correct frame state model source destination
        request (NativeArrayCheckQuorum.Log.ofList request.entries) selected (by simp)).mp
        enabled |>.2.2
    exact ⟨present, nonempty, request, selected, recipient, action⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
