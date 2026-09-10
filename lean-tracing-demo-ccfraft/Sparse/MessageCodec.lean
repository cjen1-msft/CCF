import Sparse.BijectiveIntegerLog

set_option autoImplicit false

namespace CCFRaft.Sparse.MessageCodec

open Sparse.BijectiveIntegerLog

abbrev Packet := Message Node Nat

structure RawAppendEntriesRequest where
  term : Int
  prevLogIndex : Int
  prevLogTerm : Int
  entries : List RawEntry
  leaderCommit : Int
  source : Node
  destination : Node
  deriving DecidableEq

structure RawAppendEntriesResponse where
  term : Int
  success : Bool
  lastLogIndex : Int
  source : Node
  destination : Node
  deriving DecidableEq

structure RawRequestVoteRequest where
  term : Int
  lastCommittableTerm : Int
  lastCommittableIndex : Int
  source : Node
  destination : Node
  deriving DecidableEq

structure RawRequestVoteResponse where
  term : Int
  voteGranted : Bool
  source : Node
  destination : Node
  deriving DecidableEq

structure RawRequestPreVote where
  term : Int
  lastCommittableTerm : Int
  lastCommittableIndex : Int
  source : Node
  destination : Node
  deriving DecidableEq

structure RawRequestPreVoteResponse where
  term : Int
  voteGranted : Bool
  source : Node
  destination : Node
  deriving DecidableEq

structure RawProposeVoteRequest where
  term : Int
  source : Node
  destination : Node
  deriving DecidableEq

inductive RawMessage where
  | appendEntriesRequest (request : RawAppendEntriesRequest)
  | appendEntriesResponse (response : RawAppendEntriesResponse)
  | requestVoteRequest (request : RawRequestVoteRequest)
  | requestVoteResponse (response : RawRequestVoteResponse)
  | requestPreVote (request : RawRequestPreVote)
  | requestPreVoteResponse (response : RawRequestPreVoteResponse)
  | proposeVoteRequest (request : RawProposeVoteRequest)
  deriving DecidableEq

def decodeEntries (entries : List RawEntry) : List (Entry Node Nat) :=
  entries.map decodeEntry

def encodeEntries (entries : List (Entry Node Nat)) : List RawEntry :=
  entries.map encodeEntry

@[simp] theorem decode_encode_entries (entries : List (Entry Node Nat)) :
    decodeEntries (encodeEntries entries) = entries := by
  induction entries with
  | nil => rfl
  | cons entry rest ih =>
    simpa [decodeEntries, encodeEntries] using congrArg (List.cons entry) ih

@[simp] theorem encode_decode_entries (entries : List RawEntry) :
    encodeEntries (decodeEntries entries) = entries := by
  induction entries with
  | nil => rfl
  | cons entry rest ih =>
    simpa [decodeEntries, encodeEntries] using congrArg (List.cons entry) ih

-- Positional constructors and exhaustive patterns expose schema changes.
def decodeAppendEntriesRequest :
    RawAppendEntriesRequest -> AppendEntriesRequest Node Nat
  | .mk term prevLogIndex prevLogTerm entries leaderCommit source destination =>
    .mk (decodeNat term) (decodeNat prevLogIndex) (decodeNat prevLogTerm)
      (decodeEntries entries) (decodeNat leaderCommit) source destination

def encodeAppendEntriesRequest :
    AppendEntriesRequest Node Nat -> RawAppendEntriesRequest
  | .mk term prevLogIndex prevLogTerm entries leaderCommit source destination =>
    .mk (encodeNat term) (encodeNat prevLogIndex) (encodeNat prevLogTerm)
      (encodeEntries entries) (encodeNat leaderCommit) source destination

def decodeAppendEntriesResponse :
    RawAppendEntriesResponse -> AppendEntriesResponse Node
  | .mk term success lastLogIndex source destination =>
    .mk (decodeNat term) success (decodeNat lastLogIndex) source destination

def encodeAppendEntriesResponse :
    AppendEntriesResponse Node -> RawAppendEntriesResponse
  | .mk term success lastLogIndex source destination =>
    .mk (encodeNat term) success (encodeNat lastLogIndex) source destination

def decodeRequestVoteRequest : RawRequestVoteRequest -> RequestVoteRequest Node
  | .mk term lastCommittableTerm lastCommittableIndex source destination =>
    .mk (decodeNat term) (decodeNat lastCommittableTerm)
      (decodeNat lastCommittableIndex) source destination

def encodeRequestVoteRequest : RequestVoteRequest Node -> RawRequestVoteRequest
  | .mk term lastCommittableTerm lastCommittableIndex source destination =>
    .mk (encodeNat term) (encodeNat lastCommittableTerm)
      (encodeNat lastCommittableIndex) source destination

def decodeRequestVoteResponse : RawRequestVoteResponse -> RequestVoteResponse Node
  | .mk term voteGranted source destination =>
    .mk (decodeNat term) voteGranted source destination

def encodeRequestVoteResponse : RequestVoteResponse Node -> RawRequestVoteResponse
  | .mk term voteGranted source destination =>
    .mk (encodeNat term) voteGranted source destination

def decodeRequestPreVote : RawRequestPreVote -> RequestPreVote Node
  | .mk term lastCommittableTerm lastCommittableIndex source destination =>
    .mk (decodeNat term) (decodeNat lastCommittableTerm)
      (decodeNat lastCommittableIndex) source destination

def encodeRequestPreVote : RequestPreVote Node -> RawRequestPreVote
  | .mk term lastCommittableTerm lastCommittableIndex source destination =>
    .mk (encodeNat term) (encodeNat lastCommittableTerm)
      (encodeNat lastCommittableIndex) source destination

def decodeRequestPreVoteResponse :
    RawRequestPreVoteResponse -> RequestPreVoteResponse Node
  | .mk term voteGranted source destination =>
    .mk (decodeNat term) voteGranted source destination

def encodeRequestPreVoteResponse :
    RequestPreVoteResponse Node -> RawRequestPreVoteResponse
  | .mk term voteGranted source destination =>
    .mk (encodeNat term) voteGranted source destination

def decodeProposeVoteRequest : RawProposeVoteRequest -> ProposeVoteRequest Node
  | .mk term source destination => .mk (decodeNat term) source destination

def encodeProposeVoteRequest : ProposeVoteRequest Node -> RawProposeVoteRequest
  | .mk term source destination => .mk (encodeNat term) source destination

def decodeMessage : RawMessage -> Packet
  | .appendEntriesRequest request =>
    .appendEntriesRequest (decodeAppendEntriesRequest request)
  | .appendEntriesResponse response =>
    .appendEntriesResponse (decodeAppendEntriesResponse response)
  | .requestVoteRequest request =>
    .requestVoteRequest (decodeRequestVoteRequest request)
  | .requestVoteResponse response =>
    .requestVoteResponse (decodeRequestVoteResponse response)
  | .requestPreVote request =>
    .requestPreVote (decodeRequestPreVote request)
  | .requestPreVoteResponse response =>
    .requestPreVoteResponse (decodeRequestPreVoteResponse response)
  | .proposeVoteRequest request =>
    .proposeVoteRequest (decodeProposeVoteRequest request)

def encodeMessage : Packet -> RawMessage
  | .appendEntriesRequest request =>
    .appendEntriesRequest (encodeAppendEntriesRequest request)
  | .appendEntriesResponse response =>
    .appendEntriesResponse (encodeAppendEntriesResponse response)
  | .requestVoteRequest request =>
    .requestVoteRequest (encodeRequestVoteRequest request)
  | .requestVoteResponse response =>
    .requestVoteResponse (encodeRequestVoteResponse response)
  | .requestPreVote request =>
    .requestPreVote (encodeRequestPreVote request)
  | .requestPreVoteResponse response =>
    .requestPreVoteResponse (encodeRequestPreVoteResponse response)
  | .proposeVoteRequest request =>
    .proposeVoteRequest (encodeProposeVoteRequest request)

@[simp] theorem decode_encode_message (message : Packet) :
    decodeMessage (encodeMessage message) = message := by
  cases message with
  | appendEntriesRequest request =>
    cases request
    simp [encodeMessage, decodeMessage,
      encodeAppendEntriesRequest, decodeAppendEntriesRequest]
  | appendEntriesResponse response =>
    cases response
    simp [encodeMessage, decodeMessage,
      encodeAppendEntriesResponse, decodeAppendEntriesResponse]
  | requestVoteRequest request =>
    cases request
    simp [encodeMessage, decodeMessage,
      encodeRequestVoteRequest, decodeRequestVoteRequest]
  | requestVoteResponse response =>
    cases response
    simp [encodeMessage, decodeMessage,
      encodeRequestVoteResponse, decodeRequestVoteResponse]
  | requestPreVote request =>
    cases request
    simp [encodeMessage, decodeMessage, encodeRequestPreVote, decodeRequestPreVote]
  | requestPreVoteResponse response =>
    cases response
    simp [encodeMessage, decodeMessage,
      encodeRequestPreVoteResponse, decodeRequestPreVoteResponse]
  | proposeVoteRequest request =>
    cases request
    simp [encodeMessage, decodeMessage,
      encodeProposeVoteRequest, decodeProposeVoteRequest]

@[simp] theorem encode_decode_message (message : RawMessage) :
    encodeMessage (decodeMessage message) = message := by
  cases message with
  | appendEntriesRequest request =>
    cases request
    simp [encodeMessage, decodeMessage,
      encodeAppendEntriesRequest, decodeAppendEntriesRequest]
  | appendEntriesResponse response =>
    cases response
    simp [encodeMessage, decodeMessage,
      encodeAppendEntriesResponse, decodeAppendEntriesResponse]
  | requestVoteRequest request =>
    cases request
    simp [encodeMessage, decodeMessage,
      encodeRequestVoteRequest, decodeRequestVoteRequest]
  | requestVoteResponse response =>
    cases response
    simp [encodeMessage, decodeMessage,
      encodeRequestVoteResponse, decodeRequestVoteResponse]
  | requestPreVote request =>
    cases request
    simp [encodeMessage, decodeMessage, encodeRequestPreVote, decodeRequestPreVote]
  | requestPreVoteResponse response =>
    cases response
    simp [encodeMessage, decodeMessage,
      encodeRequestPreVoteResponse, decodeRequestPreVoteResponse]
  | proposeVoteRequest request =>
    cases request
    simp [encodeMessage, decodeMessage,
      encodeProposeVoteRequest, decodeProposeVoteRequest]

def messageEquiv : Equiv RawMessage Packet where
  toFun := decodeMessage
  invFun := encodeMessage
  left_inv := encode_decode_message
  right_inv := decode_encode_message

theorem message_eq_iff (a b : RawMessage) :
    decodeMessage a = decodeMessage b <-> a = b :=
  messageEquiv.injective.eq_iff

theorem message_ne_iff (a b : RawMessage) :
    Not (decodeMessage a = decodeMessage b) <-> Not (a = b) :=
  not_congr (message_eq_iff a b)

theorem encoded_message_eq_iff (a b : Packet) :
    encodeMessage a = encodeMessage b <-> a = b :=
  messageEquiv.symm.injective.eq_iff

theorem encoded_message_ne_iff (a b : Packet) :
    Not (encodeMessage a = encodeMessage b) <-> Not (a = b) :=
  not_congr (encoded_message_eq_iff a b)

theorem message_literal_eq_iff (actual : RawMessage) (expected : Packet) :
    actual = encodeMessage expected <-> decodeMessage actual = expected := by
  rw [<- message_eq_iff, decode_encode_message]

theorem message_literal_ne_iff (actual : RawMessage) (expected : Packet) :
    Not (actual = encodeMessage expected) <-> Not (decodeMessage actual = expected) :=
  not_congr (message_literal_eq_iff actual expected)

def decodeMessages (messages : List RawMessage) : List Packet :=
  messages.map decodeMessage

def encodeMessages (messages : List Packet) : List RawMessage :=
  messages.map encodeMessage

@[simp] theorem decode_encode_messages (messages : List Packet) :
    decodeMessages (encodeMessages messages) = messages := by
  induction messages with
  | nil => rfl
  | cons message rest ih =>
    simpa [decodeMessages, encodeMessages] using congrArg (List.cons message) ih

@[simp] theorem encode_decode_messages (messages : List RawMessage) :
    encodeMessages (decodeMessages messages) = messages := by
  induction messages with
  | nil => rfl
  | cons message rest ih =>
    simpa [decodeMessages, encodeMessages] using congrArg (List.cons message) ih

def messagesEquiv : Equiv (List RawMessage) (List Packet) where
  toFun := decodeMessages
  invFun := encodeMessages
  left_inv := encode_decode_messages
  right_inv := decode_encode_messages

theorem messages_eq_iff (a b : List RawMessage) :
    decodeMessages a = decodeMessages b <-> a = b :=
  messagesEquiv.injective.eq_iff

theorem messages_ne_iff (a b : List RawMessage) :
    Not (decodeMessages a = decodeMessages b) <-> Not (a = b) :=
  not_congr (messages_eq_iff a b)

def RawMessage.source : RawMessage -> Node
  | .appendEntriesRequest request => request.source
  | .appendEntriesResponse response => response.source
  | .requestVoteRequest request => request.source
  | .requestVoteResponse response => response.source
  | .requestPreVote request => request.source
  | .requestPreVoteResponse response => response.source
  | .proposeVoteRequest request => request.source

def RawMessage.destination : RawMessage -> Node
  | .appendEntriesRequest request => request.destination
  | .appendEntriesResponse response => response.destination
  | .requestVoteRequest request => request.destination
  | .requestVoteResponse response => response.destination
  | .requestPreVote request => request.destination
  | .requestPreVoteResponse response => response.destination
  | .proposeVoteRequest request => request.destination

def RawMessage.term : RawMessage -> Int
  | .appendEntriesRequest request => request.term
  | .appendEntriesResponse response => response.term
  | .requestVoteRequest request => request.term
  | .requestVoteResponse response => response.term
  | .requestPreVote request => request.term
  | .requestPreVoteResponse response => response.term
  | .proposeVoteRequest request => request.term

@[simp] theorem decode_source (message : RawMessage) :
    (decodeMessage message).source = message.source := by
  cases message <;> rfl

@[simp] theorem decode_destination (message : RawMessage) :
    (decodeMessage message).destination = message.destination := by
  cases message <;> rfl

@[simp] theorem encode_source (message : Packet) :
    (encodeMessage message).source = message.source := by
  cases message <;> rfl

@[simp] theorem encode_destination (message : Packet) :
    (encodeMessage message).destination = message.destination := by
  cases message <;> rfl

@[simp] theorem decode_term (message : RawMessage) :
    (decodeMessage message).term = decodeNat message.term := by
  cases message <;> rfl

@[simp] theorem encode_term (message : Packet) :
    (encodeMessage message).term = encodeNat message.term := by
  cases message <;> rfl

theorem term_arithmetic (message : RawMessage) :
    ((decodeMessage message).term : Int) =
      (if 0 <= message.term then 2 * message.term else -2 * message.term - 1) := by
  rw [decode_term]
  exact decode_formula message.term

theorem term_order_iff (a b : RawMessage) :
    (decodeMessage a).term < (decodeMessage b).term <->
      smtDecode a.term < smtDecode b.term := by
  simp only [decode_term, decoded_order_iff]

theorem encoded_term_one (message : Packet) (one : message.term = 1) :
    (encodeMessage message).term = -1 := by
  rw [encode_term, one, literal_one]

end CCFRaft.Sparse.MessageCodec

-- Audit every declaration in this unit, including generated definitions.
run_cmd do
  let mut checked := 0
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.MessageCodec).isPrefixOf name then
      let axioms <- Lean.collectAxioms name
      for axiomName in axioms do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
      checked := checked + 1
  Lean.logInfo m!"Sparse message codec audit passed: {checked} declarations."
