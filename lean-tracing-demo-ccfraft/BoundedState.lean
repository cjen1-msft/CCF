-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Model

set_option autoImplicit false

/-!
# Finite full-state representation

This module materializes every function-valued field of `State Node Nat` as a
fixed vector. A missing node slot is distinct from an allocated slot containing
`freshNodeState`.

Bounds apply only to allocated local-state payloads. Missing slots decode to
`freshNodeState` for ordinary `NodeStore` reads, but that synthetic value is not
checked as an allocated local state.
-/

namespace CCFRaft.BoundedState

/--
Exclusive limits for scalar domains and inclusive limits for list capacities.
-/
structure Bounds where
  transactionCount : Nat
  termCount : Nat
  indexCount : Nat
  logCapacity : Nat
  queueCapacity : Nat
  deriving DecidableEq, Repr

/-- A fixed table containing one value for every node in the model world. -/
abbrev NodeTable (α : Type) := Vector α NODE_COUNT

variable {α : Type}

/-- Materialize a node-indexed function in node identifier order. -/
def NodeTable.ofFunction (value : Node → α) : NodeTable α :=
  Vector.ofFn value

/-- Executable lookup in a fixed node table. -/
def NodeTable.get (values : NodeTable α) (node : Node) : α :=
  Vector.get values node

/-- Finite representation of every field in an allocated local state. -/
structure LocalStateData (TxId : Type := Nat) where
  role : Role
  currentTerm : Nat
  log : List (Entry Node TxId)
  commitIndex : Nat
  sentIndex : NodeTable Nat
  matchIndex : NodeTable Nat
  isNewFollower : Bool
  votedFor : Option Node
  votesGranted : Finset Node
  preVotesGranted : Finset Node
  membershipState : MembershipState
  retirementIndex : Option Nat
  retirementCommittableIndex : Option Nat
  retiredCommittedIndex : Option Nat
  deriving DecidableEq

/--
Lossless finite data for a full model state. `nodes` has exactly fifteen slots;
`none` means unallocated and `some fresh` remains explicitly allocated.
-/
structure Data (TxId : Type := Nat) where
  nodes : NodeTable (Option (LocalStateData TxId))
  network : NodeTable (List (Message Node TxId))
  submittedTxIds : Finset TxId
  hasJoined : Finset Node
  preVoteStatus : NodeTable PreVoteStatus
  retirementCompleted : NodeTable (Finset Node)
  deriving DecidableEq

/-- Materialize a local protocol state, including both per-peer index tables. -/
def encodeLocal {TxId : Type}
    (state : NodeState Node TxId) : LocalStateData TxId where
  role := state.role
  currentTerm := state.currentTerm
  log := state.log
  commitIndex := state.commitIndex
  sentIndex := .ofFunction state.sentIndex
  matchIndex := .ofFunction state.matchIndex
  isNewFollower := state.isNewFollower
  votedFor := state.votedFor
  votesGranted := state.votesGranted
  preVotesGranted := state.preVotesGranted
  membershipState := state.membershipState
  retirementIndex := state.retirementIndex
  retirementCommittableIndex := state.retirementCommittableIndex
  retiredCommittedIndex := state.retiredCommittedIndex

/-- Recover a local protocol state from its finite data. -/
def decodeLocal {TxId : Type}
    (data : LocalStateData TxId) : NodeState Node TxId where
  role := data.role
  currentTerm := data.currentTerm
  log := data.log
  commitIndex := data.commitIndex
  sentIndex := data.sentIndex.get
  matchIndex := data.matchIndex.get
  isNewFollower := data.isNewFollower
  votedFor := data.votedFor
  votesGranted := data.votesGranted
  preVotesGranted := data.preVotesGranted
  membershipState := data.membershipState
  retirementIndex := data.retirementIndex
  retirementCommittableIndex := data.retirementCommittableIndex
  retiredCommittedIndex := data.retiredCommittedIndex

/-- Materialize all allocated slots and all global function fields. -/
def encode {TxId : Type} (state : State Node TxId) : Data TxId where
  nodes :=
    .ofFunction fun node =>
      (state.node? node).map encodeLocal
  network := .ofFunction state.network
  submittedTxIds := state.submittedTxIds
  hasJoined := state.hasJoined
  preVoteStatus := .ofFunction state.preVoteStatus
  retirementCompleted := .ofFunction state.retirementCompleted

/-- Node identities represented by allocated slots. -/
def Data.allocatedNodes {TxId : Type} (data : Data TxId) : Finset Node :=
  Finset.univ.filter fun node => (data.nodes.get node).isSome

/-- Rebuild the finite node store represented by the optional node slots. -/
def Data.decodeNodes {TxId : Type} (data : Data TxId) : NodeStore Node TxId :=
  NodeStore.ofFinset data.allocatedNodes fun node =>
    (data.nodes.get node).map decodeLocal |>.getD freshNodeState

/-- Recover the exact model state represented by finite data. -/
def decode {TxId : Type} (data : Data TxId) : State Node TxId where
  nodes := data.decodeNodes
  network := data.network.get
  submittedTxIds := data.submittedTxIds
  hasJoined := data.hasJoined
  preVoteStatus := data.preVoteStatus.get
  retirementCompleted := data.retirementCompleted.get

/-- An optional index is either absent or inside the exclusive index domain. -/
def OptionalIndexWithin (bounds : Bounds) : Option Nat → Prop
  | none => True
  | some index => index < bounds.indexCount

/-- Every entry term and transaction payload lies in its exclusive domain. -/
def EntryWithin (bounds : Bounds) (entry : Entry Node Nat) : Prop :=
  entry.term < bounds.termCount ∧
    match entry.content with
    | .transaction txId => txId < bounds.transactionCount
    | .signature => True
    | .reconfiguration _ => True
    | .retiredCommitted _ => True

/-- All scalar and embedded-entry fields of a message lie within bounds. -/
def MessageWithin (bounds : Bounds) : Message Node Nat → Prop
  | .appendEntriesRequest request =>
      request.term < bounds.termCount ∧
        request.prevLogIndex < bounds.indexCount ∧
        request.prevLogTerm < bounds.termCount ∧
        request.entries.length ≤ bounds.logCapacity ∧
        request.entries.Forall (EntryWithin bounds) ∧
        request.leaderCommit < bounds.indexCount
  | .appendEntriesResponse response =>
      response.term < bounds.termCount ∧
        response.lastLogIndex < bounds.indexCount
  | .requestVoteRequest request =>
      request.term < bounds.termCount ∧
        request.lastCommittableTerm < bounds.termCount ∧
        request.lastCommittableIndex < bounds.indexCount
  | .requestVoteResponse response =>
      response.term < bounds.termCount
  | .requestPreVote request =>
      request.term < bounds.termCount ∧
        request.lastCommittableTerm < bounds.termCount ∧
        request.lastCommittableIndex < bounds.indexCount
  | .requestPreVoteResponse response =>
      response.term < bounds.termCount
  | .proposeVoteRequest request =>
      request.term < bounds.termCount

/-- Every bounded scalar and list in one allocated local state is valid. -/
def LocalWithin (bounds : Bounds) (state : NodeState Node Nat) : Prop :=
  state.currentTerm < bounds.termCount ∧
    state.log.length ≤ bounds.logCapacity ∧
    state.log.Forall (EntryWithin bounds) ∧
    state.commitIndex < bounds.indexCount ∧
    (∀ node, state.sentIndex node < bounds.indexCount) ∧
    (∀ node, state.matchIndex node < bounds.indexCount) ∧
    OptionalIndexWithin bounds state.retirementIndex ∧
    OptionalIndexWithin bounds state.retirementCommittableIndex ∧
    OptionalIndexWithin bounds state.retiredCommittedIndex

/-- Check all transaction IDs in a finite set without enumerating `Nat`. -/
def TransactionsWithin (bounds : Bounds) (txIds : Finset Nat) : Prop :=
  ∀ txId ∈ txIds.1, txId < bounds.transactionCount

/-- Bounds for one optional allocated-node slot. -/
def OptionalLocalWithin
    (bounds : Bounds)
    (state : Option (NodeState Node Nat)) : Prop :=
  match state with
  | none => True
  | some localState => LocalWithin bounds localState

/--
Reviewed full-model bounds. Only local states returned by `node?` are checked;
the synthetic `freshNodeState` returned for an absent node is intentionally not.
-/
def WithinBounds (bounds : Bounds) (state : State Node Nat) : Prop :=
  (∀ node, OptionalLocalWithin bounds (state.node? node)) ∧
    (∀ node,
      (state.network node).length ≤ bounds.queueCapacity ∧
        (state.network node).Forall (MessageWithin bounds)) ∧
    TransactionsWithin bounds state.submittedTxIds

/-- Finite-data counterpart of `LocalWithin`. -/
def LocalDataWithin (bounds : Bounds) (data : LocalStateData) : Prop :=
  data.currentTerm < bounds.termCount ∧
    data.log.length ≤ bounds.logCapacity ∧
    data.log.Forall (EntryWithin bounds) ∧
    data.commitIndex < bounds.indexCount ∧
    (∀ node, data.sentIndex.get node < bounds.indexCount) ∧
    (∀ node, data.matchIndex.get node < bounds.indexCount) ∧
    OptionalIndexWithin bounds data.retirementIndex ∧
    OptionalIndexWithin bounds data.retirementCommittableIndex ∧
    OptionalIndexWithin bounds data.retiredCommittedIndex

/-- Bounds for one optional finite-data node slot. -/
def OptionalLocalDataWithin
    (bounds : Bounds)
    (data : Option LocalStateData) : Prop :=
  match data with
  | none => True
  | some localState => LocalDataWithin bounds localState

/-- Exact structural bounds predicate over finite state data. -/
def DataWithinBounds (bounds : Bounds) (data : Data) : Prop :=
  (∀ node, OptionalLocalDataWithin bounds (data.nodes.get node)) ∧
  (∀ node,
    (data.network.get node).length ≤ bounds.queueCapacity ∧
      (data.network.get node).Forall (MessageWithin bounds)) ∧
  TransactionsWithin bounds data.submittedTxIds

instance (bounds : Bounds) (entry : Entry Node Nat) :
    Decidable (EntryWithin bounds entry) := by
  cases entry with
  | mk term content =>
      cases content <;> simp only [EntryWithin] <;> infer_instance

instance (bounds : Bounds) (message : Message Node Nat) :
    Decidable (MessageWithin bounds message) := by
  cases message <;> simp only [MessageWithin] <;> infer_instance

instance (bounds : Bounds) (state : NodeState Node Nat) :
    Decidable (LocalWithin bounds state) := by
  cases retirementIndex : state.retirementIndex <;>
    cases retirementCommittableIndex : state.retirementCommittableIndex <;>
    cases retiredCommittedIndex : state.retiredCommittedIndex <;>
    simp only [LocalWithin, OptionalIndexWithin, retirementIndex,
      retirementCommittableIndex, retiredCommittedIndex] <;>
    infer_instance

instance (bounds : Bounds) (state : Option (NodeState Node Nat)) :
    Decidable (OptionalLocalWithin bounds state) := by
  cases state <;> simp only [OptionalLocalWithin] <;> infer_instance

instance (bounds : Bounds) (txIds : Finset Nat) :
  Decidable (TransactionsWithin bounds txIds) := by
  unfold TransactionsWithin
  infer_instance

instance (bounds : Bounds) (state : State Node Nat) :
  Decidable (WithinBounds bounds state) := by
  unfold WithinBounds
  infer_instance

instance (bounds : Bounds) (data : LocalStateData) :
    Decidable (LocalDataWithin bounds data) := by
  cases retirementIndex : data.retirementIndex <;>
    cases retirementCommittableIndex : data.retirementCommittableIndex <;>
    cases retiredCommittedIndex : data.retiredCommittedIndex <;>
    simp only [LocalDataWithin, OptionalIndexWithin, retirementIndex,
      retirementCommittableIndex, retiredCommittedIndex] <;>
    infer_instance

instance (bounds : Bounds) (data : Option LocalStateData) :
    Decidable (OptionalLocalDataWithin bounds data) := by
  cases data <;> simp only [OptionalLocalDataWithin] <;> infer_instance

instance (bounds : Bounds) (data : Data) :
    Decidable (DataWithinBounds bounds data) := by
  unfold DataWithinBounds
  infer_instance

/-- Executable full-data bounds check. -/
def check (bounds : Bounds) (data : Data) : Bool :=
  decide (DataWithinBounds bounds data)

end CCFRaft.BoundedState
