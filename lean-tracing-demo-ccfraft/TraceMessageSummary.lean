-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Model

set_option autoImplicit false

namespace CCFRaft.TraceMessageSummary

/-- The captured batch summary does not reveal its payload or previous term. -/
structure AppendEntriesSummary (Node : Type) where
  term : Nat
  prevLogIndex : Nat
  entriesLength : Nat
  leaderCommit : Nat
  source : Node
  destination : Node
  deriving DecidableEq, Repr

inductive Summary (Node : Type) where
  | appendEntriesRequest (request : AppendEntriesSummary Node)
  | appendEntriesResponse (response : AppendEntriesResponse Node)
  | requestVoteRequest (request : RequestVoteRequest Node)
  | requestVoteResponse (response : RequestVoteResponse Node)
  | requestPreVote (request : RequestPreVote Node)
  | requestPreVoteResponse (response : RequestPreVoteResponse Node)
  | proposeVoteRequest (request : ProposeVoteRequest Node)
  deriving DecidableEq, Repr

def ofMessage {Node TxId : Type} : Message Node TxId -> Summary Node
  | .appendEntriesRequest request =>
      .appendEntriesRequest
        { term := request.term
          prevLogIndex := request.prevLogIndex
          entriesLength := request.entries.length
          leaderCommit := request.leaderCommit
          source := request.source
          destination := request.destination }
  | .appendEntriesResponse response => .appendEntriesResponse response
  | .requestVoteRequest request => .requestVoteRequest request
  | .requestVoteResponse response => .requestVoteResponse response
  | .requestPreVote request => .requestPreVote request
  | .requestPreVoteResponse response => .requestPreVoteResponse response
  | .proposeVoteRequest request => .proposeVoteRequest request

def Summary.source {Node : Type} : Summary Node -> Node
  | .appendEntriesRequest request => request.source
  | .appendEntriesResponse response => response.source
  | .requestVoteRequest request => request.source
  | .requestVoteResponse response => response.source
  | .requestPreVote request => request.source
  | .requestPreVoteResponse response => response.source
  | .proposeVoteRequest request => request.source

def Summary.destination {Node : Type} : Summary Node -> Node
  | .appendEntriesRequest request => request.destination
  | .appendEntriesResponse response => response.destination
  | .requestVoteRequest request => request.destination
  | .requestVoteResponse response => response.destination
  | .requestPreVote request => request.destination
  | .requestPreVoteResponse response => response.destination
  | .proposeVoteRequest request => request.destination

def Summary.matchesFirst {Node TxId : Type} [DecidableEq Node]
    (summary : Summary Node) (state : State Node TxId) : Bool :=
  match takeFirstFrom summary.source (state.network summary.destination) with
  | none => false
  | some (message, _) => decide (ofMessage message = summary)

end CCFRaft.TraceMessageSummary
