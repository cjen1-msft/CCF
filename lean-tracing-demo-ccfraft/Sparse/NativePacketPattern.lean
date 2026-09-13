-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Model

set_option autoImplicit false

namespace CCFRaft.NativePacketPattern

def matchesOptional {α : Type} [DecidableEq α] (expected : Option α) (actual : α) : Bool :=
  expected.all fun value => decide (actual = value)

structure Header (Node : Type) where
  term : Option Nat := none
  source : Option Node := none
  destination : Option Node := none
  deriving DecidableEq

inductive Payload (Node TxId : Type) where
  | appendEntriesRequest
      (prevLogIndex prevLogTerm leaderCommit entriesLength : Option Nat)
      (entries : Option (List (Entry Node TxId)))
  | appendEntriesResponse (success : Option Bool) (lastLogIndex : Option Nat)
  | requestVoteRequest (lastCommittableTerm lastCommittableIndex : Option Nat)
  | requestVoteResponse (voteGranted : Option Bool)
  | requestPreVote (lastCommittableTerm lastCommittableIndex : Option Nat)
  | requestPreVoteResponse (voteGranted : Option Bool)
  | proposeVoteRequest
  deriving DecidableEq

structure Pattern (Node TxId : Type) where
  header : Header Node := {}
  payload : Payload Node TxId
  deriving DecidableEq

def Header.matches {Node TxId : Type} [DecidableEq Node]
    (expected : Header Node) (actual : Message Node TxId) : Bool :=
  matchesOptional expected.term actual.term &&
    matchesOptional expected.source actual.source &&
    matchesOptional expected.destination actual.destination

def Payload.matches {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId] :
    Payload Node TxId -> Message Node TxId -> Bool
  | .appendEntriesRequest previous previousTerm commit length entries,
      .appendEntriesRequest request =>
    matchesOptional previous request.prevLogIndex &&
      matchesOptional previousTerm request.prevLogTerm &&
      matchesOptional commit request.leaderCommit &&
      matchesOptional length request.entries.length &&
      matchesOptional entries request.entries
  | .appendEntriesResponse success lastIndex, .appendEntriesResponse response =>
    matchesOptional success response.success &&
      matchesOptional lastIndex response.lastLogIndex
  | .requestVoteRequest lastTerm lastIndex, .requestVoteRequest request =>
    matchesOptional lastTerm request.lastCommittableTerm &&
      matchesOptional lastIndex request.lastCommittableIndex
  | .requestVoteResponse granted, .requestVoteResponse response =>
    matchesOptional granted response.voteGranted
  | .requestPreVote lastTerm lastIndex, .requestPreVote request =>
    matchesOptional lastTerm request.lastCommittableTerm &&
      matchesOptional lastIndex request.lastCommittableIndex
  | .requestPreVoteResponse granted, .requestPreVoteResponse response =>
    matchesOptional granted response.voteGranted
  | .proposeVoteRequest, .proposeVoteRequest _ => true
  | _, _ => false

def Pattern.matches {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId]
    (expected : Pattern Node TxId) (actual : Message Node TxId) : Bool :=
  expected.header.matches actual && expected.payload.matches actual

end CCFRaft.NativePacketPattern

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativePacketPattern).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
