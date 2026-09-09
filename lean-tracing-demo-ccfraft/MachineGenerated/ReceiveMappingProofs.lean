-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.ControlActionMappingProofs

set_option autoImplicit false

namespace CCFRaft.ReceiveMapping

open TransactionMapping

variable {Node TxId OtherTxId : Type}
variable [DecidableEq Node] [DecidableEq TxId] [DecidableEq OtherTxId]
variable [Bootstrap Node]

def mapRequest (f : TxId -> OtherTxId) (request : AppendEntriesRequest Node TxId) :
    AppendEntriesRequest Node OtherTxId :=
  { request with entries := request.entries.map (mapEntry f) }

def mapResult {Response : Type} (f : TxId -> OtherTxId)
    (result : NodeState Node TxId × Response) : NodeState Node OtherTxId × Response :=
  (mapNodeState f result.1, result.2)

@[simp] theorem logOk_map (f : TxId -> OtherTxId)
    (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId) :
    logOk (mapNodeState f state) (mapRequest f request) ↔ logOk state request := by
  simp [logOk, mapRequest, mapNodeState]

@[simp] theorem alreadyDone_map (f : TxId -> OtherTxId)
    (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId) :
    alreadyDone (mapNodeState f state) (mapRequest f request) ↔
      alreadyDone state request := by
  simp [alreadyDone, mapRequest, mapNodeState, ← List.map_drop, ← List.map_take,
    List.map_map, Function.comp_def]

@[simp] theorem hasTermConflict_map (f : TxId -> OtherTxId)
    (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId) :
    hasTermConflict (mapNodeState f state) (mapRequest f request) ↔
      hasTermConflict state request := by
  simp [hasTermConflict, overlapLength, mapRequest, mapNodeState,
    ← List.map_drop, ← List.map_take, List.map_map, Function.comp_def]

@[simp] theorem committedFromLeader_map (f : TxId -> OtherTxId)
    (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId)
    (log : List (Entry Node TxId)) :
    committedFromLeader (mapNodeState f state) (mapRequest f request)
        (log.map (mapEntry f)) = committedFromLeader state request log := by
  simp [committedFromLeader, mapRequest, mapNodeState]

@[simp] theorem successResponse_map (f : TxId -> OtherTxId)
    (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId)
    (index : Nat) :
    successResponse (mapNodeState f state) (mapRequest f request) index =
      successResponse state request index := rfl

@[simp] theorem findHighestPossibleMatch_map (f : TxId -> OtherTxId)
    (log : List (Entry Node TxId)) (index term : Nat) :
    findHighestPossibleMatch (log.map (mapEntry f)) index term =
      findHighestPossibleMatch log index term := by
  simp [findHighestPossibleMatch]

@[simp] theorem failureResponse_map (f : TxId -> OtherTxId)
    (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId) :
    failureResponse (mapNodeState f state) (mapRequest f request) =
      failureResponse state request := by
  simp [failureResponse, mapRequest, mapNodeState]

@[simp] theorem reject_map (f : TxId -> OtherTxId)
    (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId) :
    rejectAppendEntriesRequest? (mapNodeState f state) (mapRequest f request) =
      (rejectAppendEntriesRequest? state request).map (mapResult f) := by
  simp only [rejectAppendEntriesRequest?, logOk_map, failureResponse_map]
  change (if request.term < state.currentTerm ∨
    (request.term = state.currentTerm ∧ state.role = .follower ∧ ¬logOk state request)
    then _ else _) = _
  split <;> simp_all [mapResult]

@[simp] theorem alreadyDoneResult_map (f : TxId -> OtherTxId)
    (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId) :
    appendEntriesAlreadyDone? (mapNodeState f state) (mapRequest f request) =
      (appendEntriesAlreadyDone? state request).map (mapResult f) := by
  simp only [appendEntriesAlreadyDone?, alreadyDone_map]
  split <;>
    simp [mapRequest, mapResult, mapNodeState, committedFromLeader, successResponse]

@[simp] theorem conflict_map (f : TxId -> OtherTxId)
    (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId) :
    conflictAppendEntriesRequest? (mapNodeState f state) (mapRequest f request) =
      (conflictAppendEntriesRequest? state request).map (mapNodeState f) := by
  simp only [conflictAppendEntriesRequest?, hasTermConflict_map]
  change (if hasTermConflict state request ∧ state.isNewFollower = true then _ else _) = _
  split <;> simp [mapNodeState, mapRequest]

@[simp] theorem returnToFollower_map (f : TxId -> OtherTxId)
    (state : NodeState Node TxId) (request : AppendEntriesRequest Node TxId) :
    returnToFollowerState? (mapNodeState f state) (mapRequest f request) =
      (returnToFollowerState? state request).map (mapNodeState f) := by
  simp only [returnToFollowerState?, mapRequest, mapNodeState_role,
    mapNodeState_currentTerm]
  split <;> simp [mapNodeState]

@[simp] theorem appendResponse_map (f : TxId -> OtherTxId)
    (state : NodeState Node TxId) (response : AppendEntriesResponse Node) :
    handleAppendEntriesResponse? (mapNodeState f state) response =
      (handleAppendEntriesResponse? state response).map (mapNodeState f) := by
  simp only [handleAppendEntriesResponse?, mapNodeState_role, mapNodeState_currentTerm]
  split
  · simp [mapNodeState]
  · split
    · simp [mapNodeState]
    · split
      · rfl
      · split <;> rfl

@[simp] theorem voteLogUpToDate_map (f : TxId -> OtherTxId)
    (state : NodeState Node TxId) (request : RequestVoteRequest Node) :
    voteLogUpToDate (mapNodeState f state) request ↔ voteLogUpToDate state request := by
  simp [voteLogUpToDate, mapNodeState, maxCommittableTerm]

@[simp] theorem voteRequest_map (f : TxId -> OtherTxId)
    (state : NodeState Node TxId) (request : RequestVoteRequest Node) :
    handleRequestVoteRequest? (mapNodeState f state) request =
      (handleRequestVoteRequest? state request).map (mapResult f) := by
  simp only [handleRequestVoteRequest?, mapNodeState_currentTerm, voteLogUpToDate_map]
  change (if request.term ≤ state.currentTerm then _ else _) = _
  split
  · simp only [mapNodeState]
    split <;> rfl
  · rfl

@[simp] theorem preVoteRequest_map (f : TxId -> OtherTxId)
    (state : NodeState Node TxId) (request : RequestPreVote Node) :
    handleRequestPreVote? (mapNodeState f state) request =
      (handleRequestPreVote? state request).map (mapResult f) := by
  simp only [handleRequestPreVote?, mapNodeState_currentTerm, voteLogUpToDate_map]
  split <;> rfl

@[simp] theorem voteResponse_map (f : TxId -> OtherTxId)
    (state : NodeState Node TxId) (response : RequestVoteResponse Node) :
    handleRequestVoteResponse? (mapNodeState f state) response =
      (handleRequestVoteResponse? state response).map (mapNodeState f) := by
  simp only [handleRequestVoteResponse?, mapNodeState_currentTerm, mapNodeState_role]
  split
  · rfl
  · split
    · rfl
    · split
      · split <;> rfl
      · rfl

@[simp] theorem preVoteResponse_map (f : TxId -> OtherTxId)
    (state : NodeState Node TxId) (response : RequestPreVoteResponse Node) :
    handleRequestPreVoteResponse? (mapNodeState f state) response =
      (handleRequestPreVoteResponse? state response).map (mapNodeState f) := by
  simp only [handleRequestPreVoteResponse?, mapNodeState_currentTerm, mapNodeState_role]
  split
  · rfl
  · split
    · rfl
    · split
      · split <;> rfl
      · rfl

@[simp] theorem proposeVote_map (f : TxId -> OtherTxId)
    (state : State Node TxId) (destination : Node) (request : ProposeVoteRequest Node) :
    handleProposeVoteRequest? (mapState f state) destination request =
      (handleProposeVoteRequest? state destination request).map (mapNodeState f) := by
  simp only [handleProposeVoteRequest?, mapState_nodes_get, mapNodeState_currentTerm,
    candidateTransitionEnabled_mapState]
  split
  · rfl
  · split <;> rfl

def NonRequest : Message Node TxId -> Prop
  | .appendEntriesRequest _ => False
  | _ => True

theorem nonRequest_eq_map (f : TxId -> OtherTxId)
    (left right : Message Node TxId) (fixed : NonRequest left) :
    mapMessage f left = mapMessage f right ↔ left = right := by
  cases left <;> cases right <;> simp_all [NonRequest, mapMessage]

theorem enqueue_map (f : TxId -> OtherTxId)
    (network : Node -> List (Message Node TxId))
    (message : Message Node TxId) (fixed : NonRequest message) :
    (fun node => (enqueueNoDup network message node).map (mapMessage f)) =
      enqueueNoDup (fun node => (network node).map (mapMessage f))
        (mapMessage f message) := by
  apply enqueueNoDup_map_of_fixed f network message _ rfl
  constructor
  · intro member
    obtain ⟨other, member, same⟩ := List.mem_map.mp member
    exact (nonRequest_eq_map f message other fixed).mp same.symm ▸ member
  · exact fun member => List.mem_map.mpr ⟨message, member, rfl⟩

@[simp] theorem updateQueue_map (f : TxId -> OtherTxId)
    (network : Node -> List (Message Node TxId))
    (destination : Node) (remaining : List (Message Node TxId)) :
    (fun node => (updateQueue network destination remaining node).map (mapMessage f)) =
      updateQueue (fun node => (network node).map (mapMessage f)) destination
        (remaining.map (mapMessage f)) := by
  funext node
  by_cases same : node = destination <;> simp [updateQueue, Function.update_apply, same]

@[simp] theorem reply_map (f : TxId -> OtherTxId)
    (network : Node -> List (Message Node TxId)) (destination : Node)
    (remaining : List (Message Node TxId)) (response : AppendEntriesResponse Node) :
    (fun node => (reply network destination remaining response node).map (mapMessage f)) =
      reply (fun node => (network node).map (mapMessage f)) destination
        (remaining.map (mapMessage f)) response := by
  rw [reply, enqueue_map f _ _ (by trivial), updateQueue_map]
  rfl

/-- Finish an accepted AppendEntries request; step-down never calls this function. -/
def finishAppend (state : State Node TxId) (destination : Node)
    (remaining : List (Message Node TxId))
    (result : NodeState Node TxId × AppendEntriesResponse Node) : State Node TxId :=
  let refreshed := refreshRetirementState destination result.1
  { state with
    nodes := updateNode state.nodes destination refreshed
    network := reply state.network destination remaining result.2
    retirementCompleted :=
      refreshRetirementCompleted state.retirementCompleted destination refreshed }

@[simp] theorem finishAppend_map (f : TxId -> OtherTxId)
    (state : State Node TxId) (destination : Node)
    (remaining : List (Message Node TxId))
    (result : NodeState Node TxId × AppendEntriesResponse Node) :
    mapState f (finishAppend state destination remaining result) =
      finishAppend (mapState f state) destination (remaining.map (mapMessage f))
        (mapResult f result) := by
  simp only [finishAppend, mapResult, ← mapNodeState_refreshRetirementState]
  simp only [mapState, mapNodeStore_updateNode, reply_map]
  rw [refreshRetirementCompleted_mapNodeState]

theorem nonRequest_receive_map (f : TxId -> OtherTxId)
    (state : State Node TxId) (source destination : Node)
    (message : Message Node TxId) (remaining : List (Message Node TxId))
    (selected : takeFirstFrom source (state.network destination) = some (message, remaining))
    (fixed : NonRequest message) :
    handleReceive? (mapState f state) source destination =
      (handleReceive? state source destination).map (mapState f) := by
  have mappedSelected :
      takeFirstFrom source ((mapState f state).network destination) =
        some (mapMessage f message, remaining.map (mapMessage f)) := by
    change takeFirstFrom source ((state.network destination).map (mapMessage f)) = _
    rw [takeFirstFrom_map, selected]
    rfl
  simp only [handleReceive?, selected, mappedSelected, mapMessage_destination]
  by_cases wrong : message.destination != destination
  · simp [wrong]
  · simp only [wrong, Bool.false_eq_true, ↓reduceIte]
    cases message with
    | appendEntriesRequest request => exact False.elim fixed
    | appendEntriesResponse response =>
        simp only [mapMessage, mapState_allocated, mapState_nodes_get, appendResponse_map]
        split
        · cases handleAppendEntriesResponse? (state.nodes destination) response <;>
            simp [mapState, mapNodeStore_updateNode]
        · simp [mapState]
    | requestVoteRequest request =>
        simp only [mapMessage, mapState_nodes_get, voteRequest_map]
        cases handleRequestVoteRequest? (state.nodes destination) request with
        | none => rfl
        | some result =>
            simp only [Option.map_some, mapResult]
            congr 1
            simp only [mapState, mapNodeStore_updateNode]
            congr 1
            rw [enqueue_map f _ _ (by trivial), updateQueue_map]
            rfl
    | requestVoteResponse response =>
        simp only [mapMessage, mapState_allocated, mapState_nodes_get, voteResponse_map]
        split
        · cases handleRequestVoteResponse? (state.nodes destination) response <;>
            simp [mapState, mapNodeStore_updateNode]
        · simp [mapState]
    | requestPreVote request =>
        simp only [mapMessage, mapState_nodes_get, preVoteRequest_map]
        cases handleRequestPreVote? (state.nodes destination) request with
        | none => rfl
        | some result =>
            simp only [Option.map_some, mapResult]
            congr 1
            simp only [mapState, mapNodeStore_updateNode]
            congr 1
            rw [enqueue_map f _ _ (by trivial), updateQueue_map]
            rfl
    | requestPreVoteResponse response =>
        simp only [mapMessage, mapState_allocated, mapState_nodes_get, preVoteResponse_map]
        split
        · cases handleRequestPreVoteResponse? (state.nodes destination) response <;>
            simp [mapState, mapNodeStore_updateNode]
        · simp [mapState]
    | proposeVoteRequest request =>
        simp only [mapMessage, proposeVote_map]
        cases handleProposeVoteRequest? state destination request <;>
          simp [mapState, mapNodeStore_updateNode]

end CCFRaft.ReceiveMapping
