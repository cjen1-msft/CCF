-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendResponse
import Sparse.NativeArrayAppendResponse
import Sparse.NativeQueueHeadEncoding
import Sparse.NativeNodeRowWritesEncoding
import Sparse.NativeLogSummaryEncoding
import Sparse.NativePacketPatternEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem append_response_payload_term_correct {context : List Ty} {width : PNat}
    (packet : Term context (packetTy width)) (assignment : Assignment)
    (locals : Locals context) (response : AppendEntriesResponse (Fin width))
    (samePacket :
      packet.eval assignment locals =
        packetValue (.appendEntriesResponse response)) :
    (appendResponsePayloadTerm packet).eval assignment locals =
      (response.success, (response.lastLogIndex : Int)) := by
  simp [appendResponsePayloadTerm, Term.eval, samePacket, packetValue,
    packetPayloadValue, Locals.cons]

theorem append_response_kind_term_correct {context : List Ty} {width : PNat}
    (packet : Term context (packetTy width)) (assignment : Assignment)
    (locals : Locals context) (message : Message (Fin width) Nat)
    (samePacket : packet.eval assignment locals = packetValue message) :
    (packetPayloadPatternTerm (.appendEntriesResponse none none)
      (.snd packet)).eval assignment locals = true <->
      exists response : AppendEntriesResponse (Fin width),
        message = .appendEntriesResponse response := by
  rw [packet_payload_pattern_term_correct
    (.appendEntriesResponse none none) (.snd packet) assignment locals message]
  · cases message <;>
      simp [NativePacketPattern.Payload.matches,
        NativePacketPattern.matchesOptional]
  · simpa [Term.eval] using congrArg Prod.snd samePacket

theorem append_response_guards_correct {width : PNat}
    (assignment : Assignment) (columns : Columns)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment columns frame)
    (source destination : Fin width) :
    Holds (appendResponseGuards columns source destination) assignment <->
      exists response : AppendEntriesResponse (Fin width),
        (frame.queues destination source).peek =
          some (.appendEntriesResponse response) /\
        NativeArrayAppendResponse.enabled frame destination response := by
  by_cases nonempty : 0 < (frame.queues destination source).length
  · let message : Message (Fin width) Nat :=
      (frame.queues destination source).cells
        (frame.queues destination source).head
    let packet : Expr (packetTy width) :=
      queueHeadPacketTerm columns source destination
    let payload := appendResponsePayloadTerm packet
    let row := nodeRowSnapshot columns destination
    have samePacket :=
      queue_head_packet_term_correct assignment columns frame rep source destination
        nonempty
    have packetKind :=
      append_response_kind_term_correct
        (queueHeadPacketTerm columns source destination) assignment Locals.empty
        message samePacket
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
    have shape :
        Holds (appendResponseGuards columns source destination) assignment <->
          (allocated columns destination.val : Expr .bool).eval
              assignment Locals.empty = true /\
            (lt (.integer 0)
              (queueScalarTerm columns.queueLength (.integer destination.val)
                (.integer source.val)) : Expr .bool).eval
                assignment Locals.empty = true /\
            (packetPayloadPatternTerm (.appendEntriesResponse none none)
              packet.snd).eval assignment Locals.empty = true /\
            (.equal packet.fst.snd.snd
              (.integer destination.val) : Expr .bool).eval
                assignment Locals.empty = true /\
            (implies (allocated columns source.val)
              (.or (.not payload.fst)
                (.or (.le packet.fst.fst row.currentTerm)
                  (.not (.equal row.role
                    (.integer (roleCode .leader))))))).eval
                assignment Locals.empty = true := by
      simp [Holds, appendResponseGuards, packet, payload, row]
    rw [shape]
    constructor
    · rintro ⟨presentTerm, _, kindTerm, recipientTerm, handlerTerm⟩
      obtain ⟨response, same⟩ := packetKind.mp kindTerm
      have responseSource : response.source = source := by
        simpa [same] using sameSource
      have selectedPacket :
          packet.eval assignment Locals.empty =
            packetValue (.appendEntriesResponse response) := by
        change packet.eval assignment Locals.empty = packetValue message at samePacket
        rw [same] at samePacket
        exact samePacket
      have payloadValue :=
        append_response_payload_term_correct packet assignment Locals.empty
          response selectedPacket
      have successValue :
          ((appendResponsePayloadTerm packet).eval
              assignment Locals.empty).1 = response.success :=
        congrArg Prod.fst payloadValue
      have termValue :
          ((packet.eval assignment Locals.empty).1).1 =
            (response.term : Int) := by
        simpa [packetValue, packetHeaderValue] using
          congrArg (fun value => value.1.1) selectedPacket
      have handlerCorrect :
          (payload.fst.not.or
            ((packet.fst.fst.le row.currentTerm).or
              (Term.equal row.role
                (.integer (roleCode .leader))).not)).eval
                assignment Locals.empty = true <->
            NativeArrayAppendResponse.handlerEnabled
              (NativeArrayCheckQuorum.get frame.nodes destination) response := by
        simp [NativeArrayAppendResponse.handlerEnabled, payload, row, Term.eval,
          successValue, termValue,
          rowRep.currentTerm, rowRep.role, role_code_eq,
          decide_eq_true_eq, decide_eq_false_iff_not]
      have present : (frame.nodes destination).isSome = true := by
        simpa [rep.nodes.allocated] using presentTerm
      have recipient : response.destination = destination := by
        simpa [packet, Term.eval, selectedPacket, packetValue,
          packetHeaderValue, Fin.ext_iff] using recipientTerm
      refine ⟨response, ?_, ?_⟩
      · simpa only [NativeArrayQueue.Queue.peek, if_pos nonempty,
          Option.some.injEq] using congrArg some same
      · rw [NativeArrayAppendResponse.enabled]
        refine ⟨present, ?_, ?_⟩
        · exact recipient
        · intro sourcePresent
          have sourcePresent' : (frame.nodes source).isSome = true := by
            simpa [responseSource] using sourcePresent
          have sourcePresentTerm :
              (allocated columns source.val : Expr .bool).eval
                  assignment Locals.empty = true := by
            simpa [rep.nodes.allocated] using sourcePresent'
          have handlerValue :=
            (implies_eval (allocated columns source.val)
              (.or (.not payload.fst)
                (.or (.le packet.fst.fst row.currentTerm)
                  (.not (.equal row.role
                    (.integer (roleCode .leader))))))
              assignment Locals.empty).mp handlerTerm sourcePresentTerm
          exact handlerCorrect.mp handlerValue
    · rintro ⟨response, selected, present, recipient, handler⟩
      have same : message = .appendEntriesResponse response := by
        simpa only [NativeArrayQueue.Queue.peek, if_pos nonempty,
          Option.some.injEq] using selected
      have responseSource : response.source = source := by
        simpa [same] using sameSource
      have selectedPacket :
          packet.eval assignment Locals.empty =
            packetValue (.appendEntriesResponse response) := by
        change packet.eval assignment Locals.empty = packetValue message at samePacket
        rw [same] at samePacket
        exact samePacket
      have payloadValue :=
        append_response_payload_term_correct packet assignment Locals.empty
          response selectedPacket
      have successValue :
          ((appendResponsePayloadTerm packet).eval
              assignment Locals.empty).1 = response.success :=
        congrArg Prod.fst payloadValue
      have termValue :
          ((packet.eval assignment Locals.empty).1).1 =
            (response.term : Int) := by
        simpa [packetValue, packetHeaderValue] using
          congrArg (fun value => value.1.1) selectedPacket
      have handlerCorrect :
          (payload.fst.not.or
            ((packet.fst.fst.le row.currentTerm).or
              (Term.equal row.role
                (.integer (roleCode .leader))).not)).eval
                assignment Locals.empty = true <->
            NativeArrayAppendResponse.handlerEnabled
              (NativeArrayCheckQuorum.get frame.nodes destination) response := by
        simp [NativeArrayAppendResponse.handlerEnabled, payload, row, Term.eval,
          successValue, termValue,
          rowRep.currentTerm, rowRep.role, role_code_eq,
          decide_eq_true_eq, decide_eq_false_iff_not]
      refine ⟨?_, ?_, packetKind.mpr ⟨response, same⟩, ?_, ?_⟩
      · simpa [rep.nodes.allocated] using present
      · simp [lt, Term.eval, lengthValue]
        omega
      · simp [packet, Term.eval, selectedPacket, packetValue,
          packetHeaderValue, recipient]
      · apply (implies_eval (allocated columns source.val)
          (.or (.not payload.fst)
            (.or (.le packet.fst.fst row.currentTerm)
              (.not (.equal row.role (.integer (roleCode .leader))))))
          assignment Locals.empty).mpr
        intro sourcePresentTerm
        have sourcePresent : (frame.nodes source).isSome = true := by
          simpa [rep.nodes.allocated] using sourcePresentTerm
        have responsePresent : (frame.nodes response.source).isSome = true := by
          simpa [responseSource] using sourcePresent
        have handlerValue := handler responsePresent
        exact handlerCorrect.mpr handlerValue
  · have empty : (frame.queues destination source).length = 0 := by omega
    constructor
    · intro guardHolds
      have positive :=
        guardHolds
          (lt (.integer 0)
            (queueScalarTerm columns.queueLength (.integer destination.val)
              (.integer source.val)))
          (by simp [appendResponseGuards])
      simp [lt, Term.eval, queue_scalar_correct, rep.queue_length, empty] at positive
    · rintro ⟨response, selected, _⟩
      simp [NativeArrayQueue.Queue.peek, empty] at selected

theorem append_response_scan_constraint_correct {width : PNat}
    [Bootstrap (Fin width)] (assignment : Assignment)
    (old : NodeRowTerms width)
    (nativeRow : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (oldRep : old.Rep assignment nativeRow)
    (packet : Expr (packetTy width))
    (response : AppendEntriesResponse (Fin width))
    (samePacket :
      packet.eval assignment Locals.empty =
        packetValue (.appendEntriesResponse response))
    (possible : Expr .int) (best : Nat)
    (samePossible :
      possible.eval assignment Locals.empty = (best : Int)) :
    (nackMatchTerm width old.logLength old.logEntries
      (appendResponsePayloadTerm packet).snd packet.fst.fst
      possible).eval assignment Locals.empty = true <->
        findHighestPossibleMatch nativeRow.log.decode response.lastLogIndex
          response.term = best := by
  have payloadValue :=
    append_response_payload_term_correct packet assignment Locals.empty response
      samePacket
  have samePrevious :
      (appendResponsePayloadTerm packet).snd.eval assignment Locals.empty =
        (response.lastLogIndex : Int) := by
    simpa [Term.eval] using congrArg Prod.snd payloadValue
  have sameThreshold :
      packet.fst.fst.eval assignment Locals.empty =
        (response.term : Int) := by
    have headerValue := congrArg (fun value => value.1.1) samePacket
    simpa [packetValue, packetHeaderValue, Term.eval] using headerValue
  exact nack_match_term_correct assignment Locals.empty old.logLength
    old.logEntries (appendResponsePayloadTerm packet).snd packet.fst.fst
    possible nativeRow.log response.lastLogIndex response.term best
    oldRep.logLength samePrevious sameThreshold samePossible oldRep.logEntries

theorem append_response_scan_constraint_sound {width : PNat}
    [Bootstrap (Fin width)] (assignment : Assignment)
    (old : NodeRowTerms width)
    (nativeRow : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (oldRep : old.Rep assignment nativeRow)
    (packet : Expr (packetTy width))
    (response : AppendEntriesResponse (Fin width))
    (samePacket :
      packet.eval assignment Locals.empty =
        packetValue (.appendEntriesResponse response))
    (possible : Expr .int)
    (accepted :
      (nackMatchTerm width old.logLength old.logEntries
        (appendResponsePayloadTerm packet).snd packet.fst.fst
        possible).eval assignment Locals.empty = true) :
    exists best : Nat,
      possible.eval assignment Locals.empty = (best : Int) /\
        findHighestPossibleMatch nativeRow.log.decode response.lastLogIndex
          response.term = best := by
  have payloadValue :=
    append_response_payload_term_correct packet assignment Locals.empty response
      samePacket
  have samePrevious :
      (appendResponsePayloadTerm packet).snd.eval assignment Locals.empty =
        (response.lastLogIndex : Int) := by
    simpa [Term.eval] using congrArg Prod.snd payloadValue
  have sameThreshold :
      packet.fst.fst.eval assignment Locals.empty =
        (response.term : Int) := by
    have headerValue := congrArg (fun value => value.1.1) samePacket
    simpa [packetValue, packetHeaderValue, Term.eval] using headerValue
  exact nack_match_term_sound assignment Locals.empty old.logLength old.logEntries
    (appendResponsePayloadTerm packet).snd packet.fst.fst possible
    nativeRow.log response.lastLogIndex response.term oldRep.logLength
    samePrevious sameThreshold oldRep.logEntries accepted

theorem append_response_scan_constraint_complete {width : PNat}
    [Bootstrap (Fin width)] (assignment : Assignment)
    (old : NodeRowTerms width)
    (nativeRow : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (oldRep : old.Rep assignment nativeRow)
    (packet : Expr (packetTy width))
    (response : AppendEntriesResponse (Fin width))
    (samePacket :
      packet.eval assignment Locals.empty =
        packetValue (.appendEntriesResponse response))
    (possible : Expr .int)
    (samePossible :
      possible.eval assignment Locals.empty =
        (findHighestPossibleMatch nativeRow.log.decode response.lastLogIndex
          response.term : Int)) :
    (nackMatchTerm width old.logLength old.logEntries
      (appendResponsePayloadTerm packet).snd packet.fst.fst
      possible).eval assignment Locals.empty = true := by
  exact
    (append_response_scan_constraint_correct assignment old nativeRow oldRep packet
      response samePacket possible
      (findHighestPossibleMatch nativeRow.log.decode response.lastLogIndex
        response.term) samePossible).mpr rfl

theorem append_response_row_terms_rep {width : PNat}
    (assignment : Assignment) (columns : Columns)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment columns frame)
    (source destination : Fin width)
    (response : AppendEntriesResponse (Fin width))
    (selected :
      (frame.queues destination source).peek =
        some (.appendEntriesResponse response))
    (possible : Expr .int)
    (possibleValue :
      possible.eval assignment Locals.empty =
        (findHighestPossibleMatch
          (NativeArrayCheckQuorum.get frame.nodes destination).log.decode
          response.lastLogIndex response.term : Int)) :
    (appendResponseRowTerms columns source destination possible).Rep assignment
      (if (frame.nodes response.source).isSome then
        NativeArrayAppendResponse.nextRow
          (NativeArrayCheckQuorum.get frame.nodes destination) response
      else NativeArrayCheckQuorum.get frame.nodes destination) := by
  have nonempty : 0 < (frame.queues destination source).length := by
    by_contra notPositive
    have empty : (frame.queues destination source).length = 0 := by omega
    simp [NativeArrayQueue.Queue.peek, empty] at selected
  let old := NativeArrayCheckQuorum.get frame.nodes destination
  let packet : Expr (packetTy width) :=
    queueHeadPacketTerm columns source destination
  let payload := appendResponsePayloadTerm packet
  have samePacket :=
    queue_head_packet_term_correct assignment columns frame rep source destination
      nonempty
  have headValue :
      (frame.queues destination source).cells
          (frame.queues destination source).head =
        .appendEntriesResponse response := by
    simpa only [NativeArrayQueue.Queue.peek, if_pos nonempty,
      Option.some.injEq] using selected
  have selectedPacket :
      packet.eval assignment Locals.empty =
        packetValue (.appendEntriesResponse response) := by
    change packet.eval assignment Locals.empty =
      packetValue
        ((frame.queues destination source).cells
          (frame.queues destination source).head) at samePacket
    rw [headValue] at samePacket
    exact samePacket
  have sameSource :
      (Message.appendEntriesResponse response : Message (Fin width) Nat).source =
        source := by
    have headSource := rep.queue_head_source source destination nonempty
    simpa only [headValue] using headSource
  have responseSource : response.source = source := by
    simpa using sameSource
  have payloadValue :=
    append_response_payload_term_correct packet assignment Locals.empty response
      selectedPacket
  have successValue :
      ((appendResponsePayloadTerm packet).eval assignment Locals.empty).1 =
        response.success :=
    congrArg Prod.fst payloadValue
  have lastIndexValue :
      ((appendResponsePayloadTerm packet).eval assignment Locals.empty).2 =
        (response.lastLogIndex : Int) :=
    congrArg Prod.snd payloadValue
  have termValue :
      ((packet.eval assignment Locals.empty).1).1 =
        (response.term : Int) := by
    simpa [packetValue, packetHeaderValue] using
      congrArg (fun value => value.1.1) selectedPacket
  have oldRep :
      (nodeRowSnapshot columns destination).Rep assignment old :=
    node_row_snapshot_rep assignment columns frame.nodes rep.nodes destination
  have sourceAllocated :
      (allocated columns source.val : Expr .bool).eval assignment Locals.empty =
        (frame.nodes source).isSome :=
    rep.nodes.allocated source
  rw [responseSource]
  by_cases sourcePresent : (frame.nodes source).isSome = true
  · cases success : response.success
    · simp only [sourcePresent, if_true]
      rw [show NativeArrayAppendResponse.nextRow old response =
          { old with
            sentIndex := Function.update old.sentIndex response.source
              (max
                (min
                  (findHighestPossibleMatch old.log.decode
                    response.lastLogIndex response.term)
                  (old.sentIndex response.source))
                  (old.matchIndex response.source)) } by
        simp [NativeArrayAppendResponse.nextRow, success]]
      exact { oldRep with
        sentIndex := by
          intro peer
          by_cases samePeer : peer = source
          · subst peer
            rw [responseSource]
            simp [appendResponseRowTerms, packet, all, Term.eval,
              sourceAllocated, sourcePresent, successValue, success,
              possibleValue, oldRep.sentIndex, oldRep.matchIndex,
              log_range_min_term_eval, int_max_term_eval, old]
          · have different : (peer.val : Int) ≠ source.val := by
              intro sameValue
              apply samePeer
              apply Fin.ext
              exact Int.ofNat_inj.mp sameValue
            simp [appendResponseRowTerms, packet, all, Term.eval,
              sourceAllocated, sourcePresent, successValue, success,
              possibleValue, oldRep.sentIndex, oldRep.matchIndex,
              log_range_min_term_eval, int_max_term_eval, old, samePeer,
              different, responseSource]
        matchIndex := by
          intro peer
          simp [appendResponseRowTerms, packet, all, Term.eval,
            sourceAllocated, sourcePresent, successValue, success,
            oldRep.matchIndex] }
    · by_cases acknowledges :
        response.term = old.currentTerm /\ old.role = .leader
      · simp only [sourcePresent, if_true]
        rw [show NativeArrayAppendResponse.nextRow old response =
            { old with
                matchIndex := Function.update old.matchIndex response.source
                  (max (old.matchIndex response.source) response.lastLogIndex) } by
            simp [NativeArrayAppendResponse.nextRow, success, acknowledges]]
        exact { oldRep with
          sentIndex := by
            intro peer
            simp [appendResponseRowTerms, packet, all, Term.eval,
              sourceAllocated, sourcePresent, successValue, success,
              oldRep.sentIndex]
          matchIndex := by
            intro peer
            by_cases samePeer : peer = source
            · subst peer
              rw [responseSource]
              simp [appendResponseRowTerms, packet, all, Term.eval,
                sourceAllocated, sourcePresent, successValue, success,
                termValue, lastIndexValue, oldRep.currentTerm, oldRep.role,
                oldRep.matchIndex, acknowledges,
                int_max_term_eval, old]
            · have different : (peer.val : Int) ≠ source.val := by
                intro sameValue
                apply samePeer
                apply Fin.ext
                exact Int.ofNat_inj.mp sameValue
              simp [appendResponseRowTerms, packet, all, Term.eval,
                sourceAllocated, sourcePresent, successValue, success,
                termValue, lastIndexValue, oldRep.currentTerm, oldRep.role,
                oldRep.matchIndex, acknowledges,
                int_max_term_eval, old, samePeer, different, responseSource] }
      · simp only [sourcePresent, if_true]
        rw [show NativeArrayAppendResponse.nextRow old response = old by
          simp [NativeArrayAppendResponse.nextRow, success, acknowledges]]
        exact { oldRep with
          sentIndex := by
            intro peer
            simp [appendResponseRowTerms, packet, all, Term.eval,
              sourceAllocated, sourcePresent, successValue, success,
              oldRep.sentIndex]
          matchIndex := by
            intro peer
            simp [appendResponseRowTerms, packet, all, Term.eval,
              sourceAllocated, sourcePresent, successValue, success,
              termValue, oldRep.currentTerm, oldRep.role, oldRep.matchIndex,
              acknowledges, role_code_eq] }
  · simp only [sourcePresent]
    exact { oldRep with
      sentIndex := by
        intro peer
        simp [appendResponseRowTerms, all, Term.eval,
          sourceAllocated, sourcePresent, oldRep.sentIndex, old]
      matchIndex := by
        intro peer
        simp [appendResponseRowTerms, all, Term.eval,
          sourceAllocated, sourcePresent, oldRep.matchIndex, old] }

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

theorem append_response_row_terms_bounded {width : PNat}
    (before : Encoding width) (source destination : Fin width)
    (possible : Expr .int) (valid : ReferencesValid before)
    (possibleBounded :
      possible.symbols.all (fun symbol => symbol.2 < before.next) = true) :
    (appendResponseRowTerms before.toColumns source destination possible).Bounded
      before.next := by
  have oldBounded := node_row_snapshot_bounded before destination valid
  have packetBounded :=
    queue_head_packet_term_bounded before source destination valid
  change ({ nodeRowSnapshot before.toColumns destination with
    sentIndex := _
    matchIndex := _ }).Bounded before.next
  exact { oldBounded with
    sentIndex := by
      simp [appendResponsePayloadTerm, intMaxTerm,
        logRangeMinTerm, Term.symbols, oldBounded.sentIndex,
        oldBounded.matchIndex, possibleBounded, packetBounded]
      intro sort id member
      simp [allocated, Term.symbols] at member
      rcases member with ⟨_, rfl⟩
      exact valid.allocated
    matchIndex := by
      simp [appendResponsePayloadTerm, all, intMaxTerm,
        Term.symbols, oldBounded.currentTerm, oldBounded.role,
        oldBounded.matchIndex, packetBounded]
      intro sort id member
      simp [allocated, Term.symbols] at member
      rcases member with ⟨_, rfl⟩
      exact valid.allocated }

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
