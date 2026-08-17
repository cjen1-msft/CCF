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

def NODE_COUNT : Nat := 5
abbrev Node := Fin NODE_COUNT

def LEADER : Node := ⟨0, by decide⟩
def TERM_ONE : Nat := 1

inductive Role where
  | follower
  | leader
  deriving DecidableEq, Repr

structure Entry (TxId : Type) where
  term : Nat
  txId : TxId
  deriving DecidableEq, Repr

structure AppendEntriesRequest (TxId : Type) where
  term : Nat
  prevLogIndex : Nat
  prevLogTerm : Nat
  entries : List (Entry TxId)
  leaderCommit : Nat
  source : Node
  destination : Node
  deriving DecidableEq, Repr

structure AppendEntriesResponse where
  term : Nat
  success : Bool
  lastLogIndex : Nat
  source : Node
  destination : Node
  deriving DecidableEq, Repr

inductive Message (TxId : Type) where
  | appendEntriesRequest (request : AppendEntriesRequest TxId)
  | appendEntriesResponse (response : AppendEntriesResponse)
  deriving DecidableEq, Repr

variable {TxId : Type}

namespace Message

def source : Message TxId -> Node
  | .appendEntriesRequest request => request.source
  | .appendEntriesResponse response => response.source

def destination : Message TxId -> Node
  | .appendEntriesRequest request => request.destination
  | .appendEntriesResponse response => response.destination

end Message

structure NodeState (TxId : Type) where
  role : Role
  currentTerm : Nat
  log : List (Entry TxId)
  commitIndex : Nat
  sentIndex : Node -> Nat
  matchIndex : Node -> Nat
  isNewFollower : Bool

namespace NodeState

def committedLog (state : NodeState TxId) : List (Entry TxId) :=
  state.log.take state.commitIndex

end NodeState

structure State (TxId : Type) where
  nodes : Node -> NodeState TxId
  network : Node -> List (Message TxId)
  submittedTxIds : Finset TxId

variable [DecidableEq TxId]

def updateNode
    (nodes : Node -> NodeState TxId)
    (node : Node)
    (value : NodeState TxId) :
    Node -> NodeState TxId :=
  Function.update nodes node value

@[simp]
theorem updateNode_same
    (nodes : Node -> NodeState TxId)
    (node : Node)
    (value : NodeState TxId) :
    updateNode nodes node value node = value := by
  simp [updateNode]

@[simp]
theorem updateNode_of_ne
    (nodes : Node -> NodeState TxId)
    (node candidate : Node)
    (value : NodeState TxId)
    (different : Not (candidate = node)) :
    updateNode nodes node value candidate = nodes candidate := by
  simp [updateNode, different]

def updateIndex
    (indices : Node -> Nat)
    (node : Node)
    (value : Nat) :
    Node -> Nat :=
  Function.update indices node value

@[simp]
theorem updateIndex_same
    (indices : Node -> Nat)
    (node : Node)
    (value : Nat) :
    updateIndex indices node value node = value := by
  simp [updateIndex]

@[simp]
theorem updateIndex_of_ne
    (indices : Node -> Nat)
    (node candidate : Node)
    (value : Nat)
    (different : Not (candidate = node)) :
    updateIndex indices node value candidate = indices candidate := by
  simp [updateIndex, different]

def updateQueue
    (network : Node -> List (Message TxId))
    (destination : Node)
    (queue : List (Message TxId)) :
    Node -> List (Message TxId) :=
  Function.update network destination queue

@[simp]
theorem updateQueue_same
    (network : Node -> List (Message TxId))
    (destination : Node)
    (queue : List (Message TxId)) :
    updateQueue network destination queue destination = queue := by
  simp [updateQueue]

@[simp]
theorem updateQueue_of_ne
    (network : Node -> List (Message TxId))
    (destination candidate : Node)
    (queue : List (Message TxId))
    (different : Not (candidate = destination)) :
    updateQueue network destination queue candidate = network candidate := by
  simp [updateQueue, different]

def initialNodeState (node : Node) : NodeState TxId where
  role := if node = LEADER then .leader else .follower
  currentTerm := TERM_ONE
  log := []
  commitIndex := 0
  sentIndex := fun _ => 0
  matchIndex := fun _ => 0
  isNewFollower := true

def initialState : State TxId where
  nodes := initialNodeState
  network := fun _ => []
  submittedTxIds := ∅

def entryAt? (log : List (Entry TxId)) (index : Nat) : Option (Entry TxId) :=
  if index = 0 then none else log[index - 1]?

def termAt (log : List (Entry TxId)) (index : Nat) : Nat :=
  (entryAt? log index).map Entry.term |>.getD 0

def messageEntries
    (log : List (Entry TxId))
    (previousIndex batchEnd : Nat) :
    List (Entry TxId) :=
  (log.drop previousIndex).take (batchEnd - previousIndex)

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

def logOk
    (state : NodeState TxId)
    (request : AppendEntriesRequest TxId) : Prop :=
  request.prevLogIndex = 0 \/
    (request.prevLogIndex <= state.log.length /\
      termAt state.log request.prevLogIndex = request.prevLogTerm)

def alreadyDone
    (state : NodeState TxId)
    (request : AppendEntriesRequest TxId) : Prop :=
  request.entries = [] \/
    (request.prevLogIndex + request.entries.length <= state.log.length /\
      ((state.log.drop request.prevLogIndex).take request.entries.length).map
          Entry.term =
        request.entries.map Entry.term)

def overlapLength
    (state : NodeState TxId)
    (request : AppendEntriesRequest TxId) : Nat :=
  min request.entries.length
    (state.log.length - request.prevLogIndex)

def hasTermConflict
    (state : NodeState TxId)
    (request : AppendEntriesRequest TxId) : Prop :=
  Not (request.entries = []) /\
    Not (
      ((state.log.drop request.prevLogIndex).take
          (overlapLength state request)).map Entry.term =
        (request.entries.take (overlapLength state request)).map Entry.term)

def noConflictExtension
    (state : NodeState TxId)
    (request : AppendEntriesRequest TxId) : Prop :=
  Not (request.entries = []) /\
    request.prevLogIndex <= state.log.length /\
    state.log.length < request.prevLogIndex + request.entries.length /\
    (state.log.drop request.prevLogIndex).take
        (state.log.length - request.prevLogIndex) =
      request.entries.take (state.log.length - request.prevLogIndex)

instance (state : NodeState TxId) (request : AppendEntriesRequest TxId) :
    Decidable (logOk state request) := by
  unfold logOk
  infer_instance

instance (state : NodeState TxId) (request : AppendEntriesRequest TxId) :
    Decidable (alreadyDone state request) := by
  unfold alreadyDone
  infer_instance

instance (state : NodeState TxId) (request : AppendEntriesRequest TxId) :
    Decidable (hasTermConflict state request) := by
  unfold hasTermConflict
  infer_instance

instance (state : NodeState TxId) (request : AppendEntriesRequest TxId) :
    Decidable (noConflictExtension state request) := by
  unfold noConflictExtension
  infer_instance

def committedFromLeader
    (state : NodeState TxId)
    (request : AppendEntriesRequest TxId)
    (newLog : List (Entry TxId)) : Nat :=
  max state.commitIndex (min newLog.length request.leaderCommit)

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

def handleAppendEntriesRequest?
    (state : NodeState TxId)
    (request : AppendEntriesRequest TxId) :
    Option (NodeState TxId × AppendEntriesResponse) :=
  match rejectAppendEntriesRequest? state request with
  | some result => some result
  | none => acceptAppendEntriesRequest? state request

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

def reply
    (network : Node -> List (Message TxId))
    (requestDestination : Node)
    (remaining : List (Message TxId))
    (response : AppendEntriesResponse) :
    Node -> List (Message TxId) :=
  enqueueNoDup
    (updateQueue network requestDestination remaining)
    (.appendEntriesResponse response)

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

def acknowledgingNodes
    (state : State TxId)
    (leader : Node)
    (index : Nat) :
    Finset Node :=
  Finset.univ.filter fun node =>
    node = leader \/
      (state.nodes leader).matchIndex node >= index

def hasMajorityAt
    (state : State TxId)
    (leader : Node)
    (index : Nat) : Prop :=
  (acknowledgingNodes state leader index).card * 2 > NODE_COUNT

instance (state : State TxId) (leader : Node) (index : Nat) :
    Decidable (hasMajorityAt state leader index) := by
  unfold hasMajorityAt
  infer_instance

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

inductive Action (TxId : Type) where
  | clientRequest (node : Node) (txId : TxId)
  | appendEntries (source destination : Node) (batchEnd : Nat)
  | receive (source destination : Node)
  | advanceCommitIndex (node : Node)
  deriving DecidableEq, Repr

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

instance (state : State TxId) (action : Action TxId) :
    Decidable (Enabled state action) := by
  cases action <;> simp only [Enabled] <;> infer_instance

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

def system [DecidableEq TxId] : ExecutableTransitionSystem where
  State := State TxId
  Action := Action TxId
  initial := initialState
  Enabled
  enabledDecidable := fun _ _ => inferInstance
  next

abbrev Reachable [DecidableEq TxId] :=
  (system (TxId := TxId)).Reachable

namespace Reachable

theorem initial :
    Reachable (initialState : State TxId) :=
  ExecutableTransitionSystem.Reachable.initial

theorem step
    {state : State TxId}
    (reachable : Reachable state)
    {action : Action TxId}
    (enabled : Enabled state action) :
    Reachable (next state action) :=
  ExecutableTransitionSystem.Reachable.step reachable enabled

end Reachable

end CCFRaft
