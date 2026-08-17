-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.ExecutableTransitionSystem
import Mathlib

set_option autoImplicit false

/-!
# Slice 1: single-term AppendEntries

This is an executable direct translation of the selected single-term
`ccfraft.tla` actions. Protocol handlers receive only the acting node's local
state and immutable message snapshots.
-/

namespace CCFRaft

/-- Number of nodes in the fixed slice-one network. -/
def NODE_COUNT : Nat := 5
/-- Node identifiers are the integers from zero through four. -/
abbrev Node := Fin NODE_COUNT

/-- Node zero is the fixed leader in slice one. -/
def LEADER : Node := ⟨0, by decide⟩
/-- Every node and entry remains in term one in this slice. -/
def TERM_ONE : Nat := 1

/-- The only leadership roles reachable before elections are introduced. -/
inductive Role where
  /-- A replica that receives AppendEntries messages. -/
  | follower
  /-- The single node that accepts requests and sends AppendEntries. -/
  | leader
  deriving DecidableEq, Repr

/-- A collapsed transaction/signature pair stored in a Raft log. -/
structure Entry (TxId : Type) where
  term : Nat
  txId : TxId
  deriving DecidableEq, Repr

/-- Immutable AppendEntries data captured when a leader sends a request. -/
structure AppendEntriesRequest (TxId : Type) where
  term : Nat
  prevLogIndex : Nat
  prevLogTerm : Nat
  entries : List (Entry TxId)
  leaderCommit : Nat
  source : Node
  destination : Node
  deriving DecidableEq, Repr

/-- ACK or NACK returned after processing an AppendEntries request. -/
structure AppendEntriesResponse where
  term : Nat
  success : Bool
  lastLogIndex : Nat
  source : Node
  destination : Node
  deriving DecidableEq, Repr

/-- The two network message kinds used by the AppendEntries slice. -/
inductive Message (TxId : Type) where
  /-- A leader-to-follower replication request. -/
  | appendEntriesRequest (request : AppendEntriesRequest TxId)
  /-- A follower-to-leader acknowledgement or rejection. -/
  | appendEntriesResponse (response : AppendEntriesResponse)
  deriving DecidableEq, Repr

variable {TxId : Type}

namespace Message

/-- Read a message's sender without inspecting any node state. -/
def source : Message TxId -> Node
  | .appendEntriesRequest request => request.source
  | .appendEntriesResponse response => response.source

/-- Read a message's intended recipient. -/
def destination : Message TxId -> Node
  | .appendEntriesRequest request => request.destination
  | .appendEntriesResponse response => response.destination

end Message

/-- Protocol state stored locally by one node. -/
structure NodeState (TxId : Type) where
  role : Role
  currentTerm : Nat
  log : List (Entry TxId)
  commitIndex : Nat
  sentIndex : Node -> Nat
  matchIndex : Node -> Nat
  isNewFollower : Bool

namespace NodeState

/-- The prefix of a node's log up to its local commit index. -/
def committedLog (state : NodeState TxId) : List (Entry TxId) :=
  state.log.take state.commitIndex

end NodeState

/-- Global proof state: local node states, network queues, and client allocation. -/
structure State (TxId : Type) where
  nodes : Node -> NodeState TxId
  network : Node -> List (Message TxId)
  submittedTxIds : Finset TxId

variable [DecidableEq TxId]

/-- Replace one node state while leaving every other node unchanged. -/
def updateNode
    (nodes : Node -> NodeState TxId)
    (node : Node)
    (value : NodeState TxId) :
    Node -> NodeState TxId :=
  Function.update nodes node value

/-- Reading the node just updated returns the new value. -/
@[simp]
theorem updateNode_same
    (nodes : Node -> NodeState TxId)
    (node : Node)
    (value : NodeState TxId) :
    updateNode nodes node value node = value := by
  simp [updateNode]

/-- Reading another node after an update returns its old value. -/
@[simp]
theorem updateNode_of_ne
    (nodes : Node -> NodeState TxId)
    (node candidate : Node)
    (value : NodeState TxId)
    (different : Not (candidate = node)) :
    updateNode nodes node value candidate = nodes candidate := by
  simp [updateNode, different]

/-- Replace one peer index in a node-local index table. -/
def updateIndex
    (indices : Node -> Nat)
    (node : Node)
    (value : Nat) :
    Node -> Nat :=
  Function.update indices node value

/-- Reading the updated peer index returns the new value. -/
@[simp]
theorem updateIndex_same
    (indices : Node -> Nat)
    (node : Node)
    (value : Nat) :
    updateIndex indices node value node = value := by
  simp [updateIndex]

/-- Updating one peer index leaves all other peer indices unchanged. -/
@[simp]
theorem updateIndex_of_ne
    (indices : Node -> Nat)
    (node candidate : Node)
    (value : Nat)
    (different : Not (candidate = node)) :
    updateIndex indices node value candidate = indices candidate := by
  simp [updateIndex, different]

/-- Replace the FIFO queue for one destination. -/
def updateQueue
    (network : Node -> List (Message TxId))
    (destination : Node)
    (queue : List (Message TxId)) :
    Node -> List (Message TxId) :=
  Function.update network destination queue

/-- Reading the replaced destination queue returns the new queue. -/
@[simp]
theorem updateQueue_same
    (network : Node -> List (Message TxId))
    (destination : Node)
    (queue : List (Message TxId)) :
    updateQueue network destination queue destination = queue := by
  simp [updateQueue]

/-- Replacing one destination queue leaves other queues unchanged. -/
@[simp]
theorem updateQueue_of_ne
    (network : Node -> List (Message TxId))
    (destination candidate : Node)
    (queue : List (Message TxId))
    (different : Not (candidate = destination)) :
    updateQueue network destination queue candidate = network candidate := by
  simp [updateQueue, different]

/-- Initialize node zero as leader and every other node as an empty follower. -/
def initialNodeState (node : Node) : NodeState TxId where
  role := if node = LEADER then .leader else .follower
  currentTerm := TERM_ONE
  log := []
  commitIndex := 0
  sentIndex := fun _ => 0
  matchIndex := fun _ => 0
  isNewFollower := true

/-- Initialize all nodes, queues, and allocated transaction IDs. -/
def initialState : State TxId where
  nodes := initialNodeState
  network := fun _ => []
  submittedTxIds := ∅

/-- Read a one-based log index, returning `none` for index zero or past the end. -/
def entryAt? (log : List (Entry TxId)) (index : Nat) : Option (Entry TxId) :=
  if index = 0 then none else log[index - 1]?

/-- Read the term at a one-based index, using zero when no entry exists. -/
def termAt (log : List (Entry TxId)) (index : Nat) : Nat :=
  (entryAt? log index).map Entry.term |>.getD 0

/-- Select the log entries between the previous index and chosen batch end. -/
def messageEntries
    (log : List (Entry TxId))
    (previousIndex batchEnd : Nat) :
    List (Entry TxId) :=
  (log.drop previousIndex).take (batchEnd - previousIndex)

/-- Append a message unless an exactly equal message is already queued. -/
def enqueueNoDup
    (network : Node -> List (Message TxId))
    (message : Message TxId) :
    Node -> List (Message TxId) :=
  let destination := message.destination
  let queue := network destination
  if message ∈ queue then
    network
  else
    updateQueue network destination (queue ++ [message])

/-- Remove the first message from a source while preserving all other order. -/
def takeFirstFrom
    (source : Node) :
    List (Message TxId) ->
      Option (Message TxId × List (Message TxId))
  | [] => none
  | message :: tail =>
      if message.source = source then
        some (message, tail)
      else
        match takeFirstFrom source tail with
        | none => none
        | some (selected, remaining) =>
            some (selected, message :: remaining)

/-- Check that a request's previous index and term match the follower log. -/
def logOk
    (state : NodeState TxId)
    (request : AppendEntriesRequest TxId) : Prop :=
  request.prevLogIndex = 0 \/
    (request.prevLogIndex <= state.log.length /\
      termAt state.log request.prevLogIndex = request.prevLogTerm)

/-- Check whether a heartbeat or all requested entry terms are already present. -/
def alreadyDone
    (state : NodeState TxId)
    (request : AppendEntriesRequest TxId) : Prop :=
  request.entries = [] \/
    (request.prevLogIndex + request.entries.length <= state.log.length /\
      ((state.log.drop request.prevLogIndex).take request.entries.length).map
          Entry.term =
        request.entries.map Entry.term)

/-- Number of request entries that overlap the follower's existing suffix. -/
def overlapLength
    (state : NodeState TxId)
    (request : AppendEntriesRequest TxId) : Nat :=
  min request.entries.length
    (state.log.length - request.prevLogIndex)

/-- Detect a differing term in the overlapping part of a request. -/
def hasTermConflict
    (state : NodeState TxId)
    (request : AppendEntriesRequest TxId) : Prop :=
  Not (request.entries = []) /\
    Not (
      ((state.log.drop request.prevLogIndex).take
          (overlapLength state request)).map Entry.term =
        (request.entries.take (overlapLength state request)).map Entry.term)

/-- Check that a request safely extends a matching follower prefix. -/
def noConflictExtension
    (state : NodeState TxId)
    (request : AppendEntriesRequest TxId) : Prop :=
  Not (request.entries = []) /\
    request.prevLogIndex <= state.log.length /\
    state.log.length < request.prevLogIndex + request.entries.length /\
    (state.log.drop request.prevLogIndex).take
        (state.log.length - request.prevLogIndex) =
      request.entries.take (state.log.length - request.prevLogIndex)

/-- Make the previous-entry consistency guard executable. -/
instance (state : NodeState TxId) (request : AppendEntriesRequest TxId) :
    Decidable (logOk state request) := by
  unfold logOk
  infer_instance

/-- Make the already-applied request guard executable. -/
instance (state : NodeState TxId) (request : AppendEntriesRequest TxId) :
    Decidable (alreadyDone state request) := by
  unfold alreadyDone
  infer_instance

/-- Make term-conflict detection executable. -/
instance (state : NodeState TxId) (request : AppendEntriesRequest TxId) :
    Decidable (hasTermConflict state request) := by
  unfold hasTermConflict
  infer_instance

/-- Make no-conflict extension detection executable. -/
instance (state : NodeState TxId) (request : AppendEntriesRequest TxId) :
    Decidable (noConflictExtension state request) := by
  unfold noConflictExtension
  infer_instance

/-- Advance a follower commit index no further than its log or the leader frontier. -/
def committedFromLeader
    (state : NodeState TxId)
    (request : AppendEntriesRequest TxId)
    (newLog : List (Entry TxId)) : Nat :=
  max state.commitIndex (min newLog.length request.leaderCommit)

/-- Construct a successful response for an applied request. -/
def successResponse
    (state : NodeState TxId)
    (request : AppendEntriesRequest TxId)
    (lastLogIndex : Nat) :
    AppendEntriesResponse where
  term := state.currentTerm
  success := true
  lastLogIndex
  source := request.destination
  destination := request.source

/-- Find the highest local index whose term could match a rejected request. -/
def findHighestPossibleMatch
    (log : List (Entry TxId))
    (index term : Nat) : Nat :=
  (List.range (min index log.length + 1)).foldl
    (fun best candidate =>
      if candidate > 0 /\ termAt log candidate <= term then
        max best candidate
      else
        best)
    0

/-- Construct source-compatible NACK metadata for stale or inconsistent requests. -/
def failureResponse
    (state : NodeState TxId)
    (request : AppendEntriesRequest TxId) :
    AppendEntriesResponse :=
  if request.term < state.currentTerm then
    { term := state.currentTerm
      success := false
      lastLogIndex := state.log.length
      source := request.destination
      destination := request.source }
  else
    let previousTerm :=
      if request.prevLogIndex = 0 then
        0
      else if request.prevLogIndex > state.log.length then
        0
      else
        termAt state.log state.log.length
    if previousTerm = 0 then
      { term := state.currentTerm
        success := false
        lastLogIndex := state.log.length
        source := request.destination
        destination := request.source }
    else
      let lastLogIndex :=
        findHighestPossibleMatch
          state.log request.prevLogIndex request.prevLogTerm
      { term :=
          if lastLogIndex = 0 then
            TERM_ONE
          else
            termAt state.log lastLogIndex
        success := false
        lastLogIndex
        source := request.destination
        destination := request.source }

/-- Reject stale-term requests or requests whose previous entry does not match. -/
def rejectAppendEntriesRequest?
    (state : NodeState TxId)
    (request : AppendEntriesRequest TxId) :
    Option (NodeState TxId × AppendEntriesResponse) :=
  if request.term < state.currentTerm \/
      (request.term = state.currentTerm /\
        state.role = .follower /\
        Not (logOk state request)) then
    some (state, failureResponse state request)
  else
    none

/-- ACK a request whose entries are already present, possibly learning commit. -/
def appendEntriesAlreadyDone?
    (state : NodeState TxId)
    (request : AppendEntriesRequest TxId) :
    Option (NodeState TxId × AppendEntriesResponse) :=
  if alreadyDone state request then
    let commitIndex := committedFromLeader state request state.log
    let nextState := { state with commitIndex }
    some
      (nextState,
        successResponse nextState request
          (request.prevLogIndex + request.entries.length))
  else
    none

/-- Truncate a conflicting uncommitted suffix without consuming the request. -/
def conflictAppendEntriesRequest?
    (state : NodeState TxId)
    (request : AppendEntriesRequest TxId) :
    Option (NodeState TxId) :=
  if hasTermConflict state request /\ state.isNewFollower then
    some
      { state with
        log := state.log.take request.prevLogIndex
        isNewFollower := false }
  else
    none

/-- Append a matching extension and return an ACK. -/
def noConflictAppendEntriesRequest?
    (state : NodeState TxId)
    (request : AppendEntriesRequest TxId) :
    Option (NodeState TxId × AppendEntriesResponse) :=
  if noConflictExtension state request then
    let newLog := state.log.take request.prevLogIndex ++ request.entries
    let commitIndex := committedFromLeader state request newLog
    let nextState := { state with log := newLog, commitIndex }
    some (nextState, successResponse nextState request newLog.length)
  else
    none

/-- Apply the accepted-request branches, composing truncation with retry. -/
def acceptAppendEntriesRequest?
    (state : NodeState TxId)
    (request : AppendEntriesRequest TxId) :
    Option (NodeState TxId × AppendEntriesResponse) :=
  if request.term = state.currentTerm /\
      state.role = .follower /\
      logOk state request /\
      request.prevLogIndex >= state.commitIndex then
    match appendEntriesAlreadyDone? state request with
    | some result => some result
    | none =>
        match noConflictAppendEntriesRequest? state request with
        | some result => some result
        | none =>
            match conflictAppendEntriesRequest? state request with
            | none => none
            | some truncated =>
                match appendEntriesAlreadyDone? truncated request with
                | some result => some result
                | none => noConflictAppendEntriesRequest? truncated request
  else
    none

/-- Prefer rejection when required; otherwise run the accepted-request logic. -/
def handleAppendEntriesRequest?
    (state : NodeState TxId)
    (request : AppendEntriesRequest TxId) :
    Option (NodeState TxId × AppendEntriesResponse) :=
  match rejectAppendEntriesRequest? state request with
  | some result => some result
  | none => acceptAppendEntriesRequest? state request

/-- Update leader match or sent indices from an ACK or NACK. -/
def handleAppendEntriesResponse?
    (state : NodeState TxId)
    (response : AppendEntriesResponse) :
    Option (NodeState TxId) :=
  if response.success = true /\
      response.term = state.currentTerm /\
      state.role = .leader then
    some
      { state with
        matchIndex :=
          updateIndex
            state.matchIndex
            response.source
            (max (state.matchIndex response.source) response.lastLogIndex) }
  else if response.success = false then
    let possible :=
      findHighestPossibleMatch state.log response.lastLogIndex response.term
    some
      { state with
        sentIndex :=
          updateIndex
            state.sentIndex
            response.source
            (max
              (min possible (state.sentIndex response.source))
              (state.matchIndex response.source)) }
  else
    none

/-- Consume a request and enqueue its response without duplicates. -/
def reply
    (network : Node -> List (Message TxId))
    (requestDestination : Node)
    (remaining : List (Message TxId))
    (response : AppendEntriesResponse) :
    Node -> List (Message TxId) :=
  enqueueNoDup
    (updateQueue network requestDestination remaining)
    (.appendEntriesResponse response)

/-- Process the first queued message from a chosen source at a destination. -/
def handleReceive?
    (state : State TxId)
    (source destination : Node) :
    Option (State TxId) :=
  match takeFirstFrom source (state.network destination) with
  | none => none
  | some (message, remaining) =>
      if message.destination != destination then
        none
      else
        match message with
        | .appendEntriesRequest request =>
            match handleAppendEntriesRequest? (state.nodes destination) request with
            | none => none
            | some (nextNode, response) =>
                some
                  { state with
                    nodes := updateNode state.nodes destination nextNode
                    network :=
                      reply state.network destination remaining response }
        | .appendEntriesResponse response =>
            match
              handleAppendEntriesResponse? (state.nodes destination) response
            with
            | none => none
            | some nextNode =>
                some
                  { state with
                    nodes := updateNode state.nodes destination nextNode
                    network :=
                      updateQueue state.network destination remaining }

/-- Snapshot leader-local replication state into an AppendEntries request. -/
def makeAppendEntriesRequest
    (state : State TxId)
    (source destination : Node)
    (batchEnd : Nat) :
    AppendEntriesRequest TxId :=
  let sourceState := state.nodes source
  let previousIndex := sourceState.sentIndex destination
  { term := sourceState.currentTerm
    prevLogIndex := previousIndex
    prevLogTerm := termAt sourceState.log previousIndex
    entries := messageEntries sourceState.log previousIndex batchEnd
    leaderCommit := sourceState.commitIndex
    source
    destination }

/-- Nodes locally known by the leader to acknowledge a candidate index. -/
def acknowledgingNodes
    (state : State TxId)
    (leader : Node)
    (index : Nat) :
    Finset Node :=
  Finset.univ.filter fun node =>
    node = leader \/
      (state.nodes leader).matchIndex node >= index

/-- True when the leader plus recorded ACKs form a strict majority. -/
def hasMajorityAt
    (state : State TxId)
    (leader : Node)
    (index : Nat) : Prop :=
  (acknowledgingNodes state leader index).card * 2 > NODE_COUNT

/-- Make the five-node majority predicate executable. -/
instance (state : State TxId) (leader : Node) (index : Nat) :
    Decidable (hasMajorityAt state leader index) := by
  unfold hasMajorityAt
  infer_instance

/-- Greatest newer current-term index acknowledged by a majority. -/
def highestCommittableIndex
    (state : State TxId)
    (leader : Node) : Nat :=
  let leaderState := state.nodes leader
  (List.range (leaderState.log.length + 1)).foldl
    (fun best index =>
      if index > leaderState.commitIndex /\
          termAt leaderState.log index = leaderState.currentTerm /\
          hasMajorityAt state leader index then
        max best index
      else
        best)
    0

/-- Explicit witnesses for every source of transition nondeterminism. -/
inductive Action (TxId : Type) where
  /-- Submit a fresh external transaction to a node. -/
  | clientRequest (node : Node) (txId : TxId)
  /-- Send the next entry or a heartbeat from one node to another. -/
  | appendEntries (source destination : Node) (batchEnd : Nat)
  /-- Process the first queued message from a selected source. -/
  | receive (source destination : Node)
  /-- Advance a leader to its locally computed quorum commit frontier. -/
  | advanceCommitIndex (node : Node)
  deriving DecidableEq, Repr

/-- Protocol guard determining whether an action may occur in a state. -/
def Enabled
    (state : State TxId) :
    Action TxId -> Prop
  | .clientRequest node txId =>
      (state.nodes node).role = .leader /\
        txId ∉ state.submittedTxIds
  | .appendEntries source destination batchEnd =>
      (state.nodes source).role = .leader /\
        Not (source = destination) /\
        batchEnd =
          min
            ((state.nodes source).sentIndex destination + 1)
            (state.nodes source).log.length
  | .receive source destination =>
      (handleReceive? state source destination).isSome
  | .advanceCommitIndex node =>
      (state.nodes node).role = .leader /\
        (state.nodes node).commitIndex <
          highestCommittableIndex state node

/-- Make every action guard directly executable. -/
instance (state : State TxId) (action : Action TxId) :
    Decidable (Enabled state action) := by
  cases action <;> simp only [Enabled] <;> infer_instance

/-- Deterministically apply the state update selected by an action witness. -/
def next
    (state : State TxId) :
    Action TxId -> State TxId
  | .clientRequest node txId =>
      let nodeState := state.nodes node
      let entry := { term := nodeState.currentTerm, txId }
      { state with
        nodes :=
          updateNode state.nodes node
            { nodeState with log := nodeState.log ++ [entry] }
        submittedTxIds := insert txId state.submittedTxIds }
  | .appendEntries source destination batchEnd =>
      let sourceState := state.nodes source
      let request := makeAppendEntriesRequest state source destination batchEnd
      { state with
        nodes :=
          updateNode state.nodes source
            { sourceState with
              sentIndex :=
                updateIndex sourceState.sentIndex destination batchEnd }
        network :=
          enqueueNoDup state.network (.appendEntriesRequest request) }
  | .receive source destination =>
      (handleReceive? state source destination).getD state
  | .advanceCommitIndex node =>
      let nodeState := state.nodes node
      { state with
        nodes :=
          updateNode state.nodes node
            { nodeState with
              commitIndex := highestCommittableIndex state node } }

/-- Package the Raft slice as a reusable executable transition system. -/
def system [DecidableEq TxId] : ExecutableTransitionSystem where
  State := State TxId
  Action := Action TxId
  initial := initialState
  Enabled
  enabledDecidable := fun _ _ => inferInstance
  next

/-- States reachable through enabled slice-one Raft actions. -/
abbrev Reachable [DecidableEq TxId] :=
  (system (TxId := TxId)).Reachable

namespace Reachable

/-- The Raft initial state is reachable. -/
theorem initial :
    Reachable (initialState : State TxId) :=
  ExecutableTransitionSystem.Reachable.initial

/-- Taking an enabled action from a reachable state preserves reachability. -/
theorem step
    {state : State TxId}
    (reachable : Reachable state)
    {action : Action TxId}
    (enabled : Enabled state action) :
    Reachable (next state action) :=
  ExecutableTransitionSystem.Reachable.step reachable enabled

end Reachable

end CCFRaft
