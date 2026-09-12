-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeLogValue
import Sparse.NativePacketHeader

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def appendPayloadTy (width : PNat) : Ty :=
  .pair .int (.pair .int (.pair .int (logTy width)))

def packetPayloadTy (width : PNat) : Ty :=
  .sum (appendPayloadTy width)
    (.sum (.pair .bool .int)
      (.sum (.pair .int .int)
        (.sum .bool (.sum (.pair .int .int) (.sum .bool .unit)))))

def packetTy (width : PNat) : Ty := .pair packetHeaderTy (packetPayloadTy width)

def packetPayloadValue {width : PNat} :
    Message (Fin width) Nat -> (packetPayloadTy width).denote
  | .appendEntriesRequest request =>
    .inl (request.prevLogIndex, request.prevLogTerm, request.leaderCommit, logValue request.entries)
  | .appendEntriesResponse response => .inr (.inl (response.success, response.lastLogIndex))
  | .requestVoteRequest request => .inr (.inr (.inl (request.lastCommittableTerm, request.lastCommittableIndex)))
  | .requestVoteResponse response => .inr (.inr (.inr (.inl response.voteGranted)))
  | .requestPreVote request =>
    .inr (.inr (.inr (.inr (.inl (request.lastCommittableTerm, request.lastCommittableIndex)))))
  | .requestPreVoteResponse response => .inr (.inr (.inr (.inr (.inr (.inl response.voteGranted)))))
  | .proposeVoteRequest _ => .inr (.inr (.inr (.inr (.inr (.inr ())))))

def PacketPayloadValid {width : PNat} : (packetPayloadTy width).denote -> Prop
  | .inl payload => 0 <= payload.1 /\ 0 <= payload.2.1 /\ 0 <= payload.2.2.1 /\ LogValueValid payload.2.2.2
  | .inr (.inl payload) => 0 <= payload.2
  | .inr (.inr (.inl payload)) => 0 <= payload.1 /\ 0 <= payload.2
  | .inr (.inr (.inr (.inr (.inl payload)))) => 0 <= payload.1 /\ 0 <= payload.2
  | _ => True

def packetFromPayload {width : PNat} (header : Nat × Fin width × Fin width) :
    (packetPayloadTy width).denote -> Message (Fin width) Nat :=
  let (term, source, destination) := header
  fun
  | .inl payload => .appendEntriesRequest
    { term, source, destination
      prevLogIndex := payload.1.toNat
      prevLogTerm := payload.2.1.toNat
      leaderCommit := payload.2.2.1.toNat
      entries := modelLog payload.2.2.2 }
  | .inr (.inl payload) => .appendEntriesResponse
    { term, source, destination, success := payload.1, lastLogIndex := payload.2.toNat }
  | .inr (.inr (.inl payload)) => .requestVoteRequest
    { term, source, destination
      lastCommittableTerm := payload.1.toNat
      lastCommittableIndex := payload.2.toNat }
  | .inr (.inr (.inr (.inl granted))) => .requestVoteResponse
    { term, source, destination, voteGranted := granted }
  | .inr (.inr (.inr (.inr (.inl payload)))) => .requestPreVote
    { term, source, destination
      lastCommittableTerm := payload.1.toNat
      lastCommittableIndex := payload.2.toNat }
  | .inr (.inr (.inr (.inr (.inr (.inl granted))))) => .requestPreVoteResponse
    { term, source, destination, voteGranted := granted }
  | .inr (.inr (.inr (.inr (.inr (.inr _))))) => .proposeVoteRequest
    { term, source, destination }

def packetValue {width : PNat} (message : Message (Fin width) Nat) : (packetTy width).denote :=
  (packetHeaderValue (message.term, message.source, message.destination), packetPayloadValue message)

structure PacketValueValid {width : PNat} (value : (packetTy width).denote) : Prop where
  header : PacketHeaderValid width value.1
  payload : PacketPayloadValid value.2

def modelPacket {width : PNat} (value : (packetTy width).denote) (valid : PacketValueValid value) :
    Message (Fin width) Nat :=
  packetFromPayload (modelPacketHeader value.1 valid.header) value.2

@[simp] theorem packet_payload_value_valid {width : PNat} (message : Message (Fin width) Nat) :
    PacketPayloadValid (packetPayloadValue message) := by
  cases message <;> simp [PacketPayloadValid, packetPayloadValue]

@[simp] theorem packet_value_valid {width : PNat} (message : Message (Fin width) Nat) :
    PacketValueValid (packetValue message) :=
  ⟨packet_header_value_valid _, packet_payload_value_valid message⟩

theorem packet_from_payload_header {width : PNat} (header : Nat × Fin width × Fin width)
    (payload : (packetPayloadTy width).denote) :
    ((packetFromPayload header payload).term, (packetFromPayload header payload).source,
      (packetFromPayload header payload).destination) = header := by
  rcases header with ⟨term, source, destination⟩
  rcases payload with append | response | vote | granted | preVote | preGranted | proposal <;> rfl

@[simp] theorem packet_from_payload_value {width : PNat} (message : Message (Fin width) Nat) :
    packetFromPayload (message.term, message.source, message.destination) (packetPayloadValue message) = message := by
  cases message <;>
    simp [packetFromPayload, packetPayloadValue, Message.term, Message.source, Message.destination]

theorem packet_payload_value_decode {width : PNat} (header : Nat × Fin width × Fin width)
    (payload : (packetPayloadTy width).denote) (valid : PacketPayloadValid payload) :
    packetPayloadValue (packetFromPayload header payload) = payload := by
  rcases payload with append | response | vote | granted | preVote | preGranted | proposal
  · rcases append with ⟨previous, previousTerm, commit, entries⟩
    rcases valid with ⟨previousValid, termValid, commitValid, entriesValid⟩
    simp [packetPayloadValue, packetFromPayload, Int.toNat_of_nonneg previousValid,
      Int.toNat_of_nonneg termValid, Int.toNat_of_nonneg commitValid, log_value_model entries entriesValid]
  · simp [packetPayloadValue, packetFromPayload, Int.toNat_of_nonneg valid]
  · simp [packetPayloadValue, packetFromPayload, Int.toNat_of_nonneg valid.1, Int.toNat_of_nonneg valid.2]
  · rfl
  · simp [packetPayloadValue, packetFromPayload, Int.toNat_of_nonneg valid.1, Int.toNat_of_nonneg valid.2]
  · rfl
  · cases proposal
    rfl

@[simp] theorem model_packet_value {width : PNat} (message : Message (Fin width) Nat)
    (valid : PacketValueValid (packetValue message)) :
    modelPacket (packetValue message) valid = message := by
  simp [modelPacket, packetValue]

theorem packet_value_model {width : PNat} (value : (packetTy width).denote)
    (valid : PacketValueValid value) : packetValue (modelPacket value valid) = value := by
  apply Prod.ext
  · simpa only [packetValue, modelPacket, packet_from_payload_header] using
      packet_header_value_model value.1 valid.header
  · exact packet_payload_value_decode _ value.2 valid.payload

theorem model_packet_eq_iff {width : PNat} (value : (packetTy width).denote)
    (message : Message (Fin width) Nat) (valid : PacketValueValid value) :
    value = packetValue message <-> modelPacket value valid = message := by
  constructor
  · intro same
    subst value
    exact model_packet_value message valid
  · intro same
    rw [<- same, packet_value_model value valid]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
