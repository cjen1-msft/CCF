-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicReceiveState
import MachineGenerated.SymbolicReceiveBounds

set_option autoImplicit false
set_option maxHeartbeats 1000000

namespace CCFRaft.SymbolicReceive

open Symbolic SymbolicModel SymbolicTransition

def consumed (state : State Node Nat) (destination : Node) (remaining : List (Message Node Nat))
    (value : NodeState Node Nat) : State Node Nat :=
  { state with
    nodes := updateNode state.nodes destination value
    network := updateQueue state.network destination remaining }

def responded {R : Type} (state : State Node Nat) (destination : Node)
    (remaining : List (Message Node Nat)) (message : R → Message Node Nat)
    (result : NodeState Node Nat × R) : State Node Nat :=
  { state with
    nodes := updateNode state.nodes destination result.1
    network := CCFRaft.enqueue (updateQueue state.network destination remaining) (message result.2) }

def appendResponded (state : State Node Nat) (destination : Node)
    (remaining : List (Message Node Nat)) (result : NodeState Node Nat × AppendEntriesResponse Node) :
    State Node Nat :=
  let refreshed := refreshRetirementState destination result.1
  { state with
    nodes := updateNode state.nodes destination refreshed
    network := reply state.network destination remaining result.2
    retirementCompleted := refreshRetirementCompleted state.retirementCompleted destination refreshed }

def dispatchModel (state : State Node Nat) (destination : Node)
    (remaining : List (Message Node Nat)) (message : Message Node Nat) : Option (State Node Nat) :=
  match message with
  | .appendEntriesRequest request =>
    match returnToFollowerState? (state.nodes destination) request with
    | some value => some { state with nodes := updateNode state.nodes destination value }
    | none => (handleAppendEntriesRequest? (state.nodes destination) request).map
        (appendResponded state destination remaining)
  | .appendEntriesResponse response =>
    if state.allocated response.source then
      (handleAppendEntriesResponse? (state.nodes destination) response).map (consumed state destination remaining)
    else some { state with network := updateQueue state.network destination remaining }
  | .requestVoteRequest request =>
    (handleRequestVoteRequest? (state.nodes destination) request).map
      (responded state destination remaining Message.requestVoteResponse)
  | .requestVoteResponse response =>
    if state.allocated response.source then
      (handleRequestVoteResponse? (state.nodes destination) response).map (consumed state destination remaining)
    else some { state with network := updateQueue state.network destination remaining }
  | .requestPreVote request =>
    (handleRequestPreVote? (state.nodes destination) request).map
      (responded state destination remaining Message.requestPreVoteResponse)
  | .requestPreVoteResponse response =>
    if state.allocated response.source then
      (handleRequestPreVoteResponse? (state.nodes destination) response).map (consumed state destination remaining)
    else some { state with network := updateQueue state.network destination remaining }
  | .proposeVoteRequest request =>
    (handleProposeVoteRequest? state destination request).map (consumed state destination remaining)

def consume (bounds : BoundedState.Bounds) (entry : Expr (stateCodec bounds.transactionCount).ty)
    (destination : Expr nodeCodec.ty) (remaining : Expr queueCodec.ty)
    (value : Expr nodeStateCodec.option.ty) : Expr (stateCodec bounds.transactionCount).option.ty :=
  chooseOption nodeStateCodec value (.inl .unit) fun nextNode =>
    .inr (writeQueue bounds.transactionCount
      (writeLocal bounds.transactionCount entry destination nextNode) destination remaining)

theorem consume_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (entry : Expr (stateCodec bounds.transactionCount).ty) (destination : Expr nodeCodec.ty)
    (remaining : Expr queueCodec.ty) (value : Expr nodeStateCodec.option.ty) :
    evalOptional bounds ρ (consume bounds entry destination remaining value) =
      (nodeStateCodec.option.decode ρ value).map
        (consumed (evalEntry bounds ρ entry) (nodeCodec.decode ρ destination) (queueCodec.decode ρ remaining)) := by
  rw [consume, evalOptional_cases nodeStateCodec bounds ρ _ _ _
    (fun node => some (consumed (evalEntry bounds ρ entry) (nodeCodec.decode ρ destination)
      (queueCodec.decode ρ remaining) node)) (by
      intro node _
      rw [evalOptional_some, writeQueue_correct, writeLocal_correct]
      rfl)]
  rw [evalOptional_none]
  cases nodeStateCodec.option.decode ρ value <;> rfl

def respond {R : Type} (codec : Codec R) (bounds : BoundedState.Bounds)
    (entry : Expr (stateCodec bounds.transactionCount).ty) (destination : Expr nodeCodec.ty)
    (remaining : Expr queueCodec.ty) (message : Expr codec.ty → Expr messageCodec.ty)
    (value : Expr (nodeStateCodec.prod codec).option.ty) : Expr (stateCodec bounds.transactionCount).option.ty :=
  chooseOption (nodeStateCodec.prod codec) value (.inl .unit) fun result =>
    .inr (enqueue bounds.transactionCount
      (writeQueue bounds.transactionCount
        (writeLocal bounds.transactionCount entry destination result.fst) destination remaining)
      (message result.snd))

theorem respond_correct {R : Type} (codec : Codec R) (bounds : BoundedState.Bounds) (ρ : Assignment)
    (entry : Expr (stateCodec bounds.transactionCount).ty) (destination : Expr nodeCodec.ty)
    (remaining : Expr queueCodec.ty) (message : Expr codec.ty → Expr messageCodec.ty)
    (f : R → Message Node Nat) (messageCorrect : ∀ x, messageCodec.decode ρ (message x) = f (codec.decode ρ x))
    (value : Expr (nodeStateCodec.prod codec).option.ty) :
    evalOptional bounds ρ (respond codec bounds entry destination remaining message value) =
      ((nodeStateCodec.prod codec).option.decode ρ value).map
        (responded (evalEntry bounds ρ entry) (nodeCodec.decode ρ destination) (queueCodec.decode ρ remaining) f) := by
  rw [respond, evalOptional_cases (nodeStateCodec.prod codec) bounds ρ _ _ _
    (fun result => some (responded (evalEntry bounds ρ entry) (nodeCodec.decode ρ destination)
      (queueCodec.decode ρ remaining) f result)) (by
      intro result _
      rw [evalOptional_some, enqueue_correct, writeQueue_correct, writeLocal_correct, messageCorrect]
      rfl)]
  rw [evalOptional_none]
  cases (nodeStateCodec.prod codec).option.decode ρ value <;> rfl

def respondAppend (bounds : BoundedState.Bounds) (entry : Expr (stateCodec bounds.transactionCount).ty)
    (destination : Expr nodeCodec.ty) (remaining : Expr queueCodec.ty)
    (value : Expr (nodeStateCodec.prod appendResponseCodec).option.ty) :
    Expr (stateCodec bounds.transactionCount).option.ty :=
  chooseOption (nodeStateCodec.prod appendResponseCodec) value (.inl .unit) fun result =>
    let refreshed := refresh (bounds.logCapacity * 2) destination (Local.unpack result.fst)
    let updated := writeLocal bounds.transactionCount entry destination refreshed.pack
    let replied := enqueue bounds.transactionCount
      (writeQueue bounds.transactionCount updated destination remaining) (.inr (.inl result.snd))
    .inr (writeCompleted bounds.transactionCount replied destination
      (completedNodes (bounds.logCapacity * 2) refreshed.log refreshed.commitIndex))

theorem respondAppend_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (entry : Expr (stateCodec bounds.transactionCount).ty) (destination : Expr nodeCodec.ty)
    (remaining : Expr queueCodec.ty) (value : Expr (nodeStateCodec.prod appendResponseCodec).option.ty)
    (bound : ∀ result, (nodeStateCodec.prod appendResponseCodec).option.decode ρ value = some result →
      result.1.log.length ≤ bounds.logCapacity * 2) :
    evalOptional bounds ρ (respondAppend bounds entry destination remaining value) =
      ((nodeStateCodec.prod appendResponseCodec).option.decode ρ value).map
        (appendResponded (evalEntry bounds ρ entry) (nodeCodec.decode ρ destination) (queueCodec.decode ρ remaining)) := by
  rw [respondAppend, evalOptional_cases (nodeStateCodec.prod appendResponseCodec) bounds ρ _ _ _
    (fun result => some (appendResponded (evalEntry bounds ρ entry) (nodeCodec.decode ρ destination)
      (queueCodec.decode ρ remaining) result)) (by
      intro result selected
      have logBound : (logCodec.decode ρ (Local.unpack result.fst).log).length ≤ bounds.logCapacity * 2 := by
        change ((Local.unpack result.fst).eval ρ).log.length ≤ _
        rw [Local.unpack_correct]
        exact bound _ selected
      have refreshed := refresh_correct ρ (bounds.logCapacity * 2) destination (Local.unpack result.fst) logBound
      have unchangedLog : (refresh (bounds.logCapacity * 2) destination (Local.unpack result.fst)).log =
          (Local.unpack result.fst).log := rfl
      rw [evalOptional_some, writeCompleted_correct, enqueue_correct, writeQueue_correct, writeLocal_correct]
      change some _ = _
      have completed := completedNodes_correct ρ (bounds.logCapacity * 2)
        (refresh (bounds.logCapacity * 2) destination (Local.unpack result.fst)).log
        (refresh (bounds.logCapacity * 2) destination (Local.unpack result.fst)).commitIndex
        (by rw [unchangedLog]; exact logBound)
      change nodeSetCodec.decode ρ _ =
        retirementCompletedNodes
          ((refresh (bounds.logCapacity * 2) destination (Local.unpack result.fst)).eval ρ).log
          ((refresh (bounds.logCapacity * 2) destination (Local.unpack result.fst)).eval ρ).commitIndex at completed
      simp only [show ∀ x, BoundedState.decodeLocal (localCodec.decode ρ x) =
        nodeStateCodec.decode ρ x from fun _ => rfl, Local.pack_correct, completed, refreshed,
        Local.unpack_correct]
      rfl)]
  rw [evalOptional_none]
  cases (nodeStateCodec.prod appendResponseCodec).option.decode ρ value <;> rfl

def receiveAppend (bounds : BoundedState.Bounds) (entry : Expr (stateCodec bounds.transactionCount).ty)
    (destination : Expr nodeCodec.ty) (remaining : Expr queueCodec.ty) (request : Expr appendRequestCodec.ty) :
    Expr (stateCodec bounds.transactionCount).option.ty :=
  let state := Local.unpack (readLocal bounds.transactionCount entry destination)
  chooseOption nodeStateCodec (returnToFollower state request)
    (respondAppend bounds entry destination remaining (appendRequest bounds.logCapacity state (Append.unpack request)))
    (fun node => .inr (writeLocal bounds.transactionCount entry destination node))

theorem receiveAppend_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (entry : Expr (stateCodec bounds.transactionCount).ty) (destination : Expr nodeCodec.ty)
    (remaining : Expr queueCodec.ty) (request : Expr appendRequestCodec.ty)
    (stateBound : ((evalEntry bounds ρ entry).nodes (nodeCodec.decode ρ destination)).log.length ≤ bounds.logCapacity)
    (requestBound : (appendRequestCodec.decode ρ request).entries.length ≤ bounds.logCapacity) :
    evalOptional bounds ρ (receiveAppend bounds entry destination remaining request) =
      dispatchModel (evalEntry bounds ρ entry) (nodeCodec.decode ρ destination) (queueCodec.decode ρ remaining)
        (.appendEntriesRequest (appendRequestCodec.decode ρ request)) := by
  let state := Local.unpack (readLocal bounds.transactionCount entry destination)
  have localCorrect : state.eval ρ = (evalEntry bounds ρ entry).nodes (nodeCodec.decode ρ destination) :=
    (Local.unpack_correct ρ _).trans (readLocal_correct bounds ρ entry destination)
  have logBound : (logCodec.decode ρ state.log).length ≤ bounds.logCapacity := by
    change (state.eval ρ).log.length ≤ _
    rw [localCorrect]
    exact stateBound
  have requestCorrect := appendRequest_correct ρ bounds.logCapacity state (Append.unpack request) logBound requestBound
  rw [Append.unpack_correct, localCorrect] at requestCorrect
  have responseBound : ∀ result,
      (nodeStateCodec.prod appendResponseCodec).option.decode ρ
          (appendRequest bounds.logCapacity state (Append.unpack request)) = some result →
        result.1.log.length ≤ bounds.logCapacity * 2 := by
    intro result selected
    rw [requestCorrect] at selected
    exact append_result_log_bound bounds.logCapacity _ _ result stateBound requestBound selected
  have responseCorrect := respondAppend_correct bounds ρ entry destination remaining
    (appendRequest bounds.logCapacity state (Append.unpack request)) responseBound
  rw [requestCorrect] at responseCorrect
  have follower := returnToFollower_correct ρ state request
  rw [localCorrect] at follower
  unfold receiveAppend
  rw [evalOptional_cases nodeStateCodec bounds ρ _ _ _
    (fun node => some { evalEntry bounds ρ entry with
      nodes := updateNode (evalEntry bounds ρ entry).nodes (nodeCodec.decode ρ destination) node }) (by
        intro node _
        rw [evalOptional_some, writeLocal_correct]
        rfl)]
  change (nodeStateCodec.option.decode ρ (returnToFollower state request)).elim _ _ = _
  rw [follower, responseCorrect]
  simp only [dispatchModel]
  cases returnToFollowerState? ((evalEntry bounds ρ entry).nodes (nodeCodec.decode ρ destination))
    (appendRequestCodec.decode ρ request) <;> rfl

end CCFRaft.SymbolicReceive
