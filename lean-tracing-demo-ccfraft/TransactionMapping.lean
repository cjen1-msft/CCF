-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Model

set_option autoImplicit false

/-!
# Transaction identifier mapping

Map transaction identifiers throughout a complete Raft state. Structural
protocol data is preserved, including unallocated node-store slots and queue
ordering. A non-injective map may merge submitted transaction identifiers.
-/

namespace CCFRaft.TransactionMapping

open CCFRaft

variable {Node TxId OtherTxId : Type}

/-- Map transaction payloads while preserving structural entry content. -/
def mapEntryContent
    (f : TxId -> OtherTxId) :
    EntryContent Node TxId -> EntryContent Node OtherTxId
  | .transaction txId => .transaction (f txId)
  | .signature => .signature
  | .reconfiguration nodes => .reconfiguration nodes
  | .retiredCommitted nodes => .retiredCommitted nodes

/-- Map one log entry's transaction payload. -/
def mapEntry
    (f : TxId -> OtherTxId)
    (entry : Entry Node TxId) :
    Entry Node OtherTxId :=
  { term := entry.term
    content := mapEntryContent f entry.content }

/-- Map transaction payloads carried by an AppendEntries message. -/
def mapMessage
    (f : TxId -> OtherTxId) :
    Message Node TxId -> Message Node OtherTxId
  | .appendEntriesRequest request =>
      .appendEntriesRequest
        { request with entries := request.entries.map (mapEntry f) }
  | .appendEntriesResponse response => .appendEntriesResponse response
  | .requestVoteRequest request => .requestVoteRequest request
  | .requestVoteResponse response => .requestVoteResponse response
  | .requestPreVote request => .requestPreVote request
  | .requestPreVoteResponse response => .requestPreVoteResponse response
  | .proposeVoteRequest request => .proposeVoteRequest request

/-- Map all transaction payloads in one node-local state. -/
def mapNodeState
    (f : TxId -> OtherTxId)
    (state : NodeState Node TxId) :
    NodeState Node OtherTxId :=
  { role := state.role
    currentTerm := state.currentTerm
    log := state.log.map (mapEntry f)
    commitIndex := state.commitIndex
    sentIndex := state.sentIndex
    matchIndex := state.matchIndex
    isNewFollower := state.isNewFollower
    votedFor := state.votedFor
    votesGranted := state.votesGranted
    preVotesGranted := state.preVotesGranted
    membershipState := state.membershipState
    retirementIndex := state.retirementIndex
    retirementCommittableIndex := state.retirementCommittableIndex
    retiredCommittedIndex := state.retiredCommittedIndex }

/-- The finite set of exactly the allocated keys in a node store. -/
def allocatedNodes
    (nodes : NodeStore Node TxId) :
    Finset Node :=
  ⟨nodes.entries.entries.keys, nodes.entries.nodupKeys.nodup_keys⟩

/-- Map every allocated node value without allocating missing keys. -/
def mapNodeStore
    [DecidableEq Node]
    (f : TxId -> OtherTxId)
    (nodes : NodeStore Node TxId) :
    NodeStore Node OtherTxId :=
  NodeStore.ofFinset (allocatedNodes nodes) fun node =>
    mapNodeState f (nodes node)

/-- Map transaction IDs throughout an arbitrary complete Raft state. -/
def mapState
    [DecidableEq Node]
    [DecidableEq OtherTxId]
    (f : TxId -> OtherTxId)
    (state : State Node TxId) :
    State Node OtherTxId :=
  { nodes := mapNodeStore f state.nodes
    network := fun node => (state.network node).map (mapMessage f)
    submittedTxIds := state.submittedTxIds.image f
    hasJoined := state.hasJoined
    preVoteStatus := state.preVoteStatus
    retirementCompleted := state.retirementCompleted }

/--
The structural portion of the real `clientRequest` guard. Transaction
freshness is intentionally separate so symbolic evaluators can encode it.
-/
def structuralClientRequestEnabled
    [DecidableEq Node]
    [DecidableEq TxId]
    [Bootstrap Node]
    (state : State Node TxId)
    (node : Node)
    (txId : TxId) :
    Prop :=
  let nodeState := state.nodes node
  let entry : Entry Node TxId :=
    { term := nodeState.currentTerm
      content := .transaction txId }
  state.allocated node /\
    nodeState.role = .leader /\
    Not (nodeState.membershipState = .retiredCommitted) /\
    Not (
      (refreshRetirementState node
        { nodeState with log := nodeState.log ++ [entry] }).membershipState =
          .retiredCommitted)

instance
    [DecidableEq Node]
    [DecidableEq TxId]
    [Bootstrap Node]
    (state : State Node TxId)
    (node : Node)
    (txId : TxId) :
    Decidable (structuralClientRequestEnabled state node txId) := by
  unfold structuralClientRequestEnabled
  infer_instance

end CCFRaft.TransactionMapping
