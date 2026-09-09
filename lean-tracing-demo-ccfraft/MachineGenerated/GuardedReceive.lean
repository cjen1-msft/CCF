-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.Guarded
import MachineGenerated.MessageEquality
import MachineGenerated.ReceiveMappingProofs

set_option autoImplicit false

namespace CCFRaft.GuardedReceive

open TraceSmt TransactionMapping MessageEquality ReceiveMapping

variable {holes : Nat}

/-- Only full entry equality depends on the transaction assignment. -/
def prefixEqual (state : NodeState Node (NatTerm holes))
    (request : AppendEntriesRequest Node (NatTerm holes)) : Expr holes :=
  listEqual entryEqual
    ((state.log.drop request.prevLogIndex).take (state.log.length - request.prevLogIndex))
    (request.entries.take (state.log.length - request.prevLogIndex))

theorem prefixEqual_correct (assignment : Fin holes -> Nat)
    (state : NodeState Node (NatTerm holes))
    (request : AppendEntriesRequest Node (NatTerm holes)) :
    (prefixEqual state request).Holds assignment ↔
      (((mapNodeState (NatTerm.eval assignment) state).log.drop request.prevLogIndex).take
        (state.log.length - request.prevLogIndex)) =
      (mapRequest (NatTerm.eval assignment) request).entries.take
        (state.log.length - request.prevLogIndex) := by
  rw [prefixEqual, listEqual_correct assignment _ _ (entryEqual_correct assignment)]
  simp [mapNodeState, mapRequest, List.map_take, List.map_drop]

def extension (state : NodeState Node (NatTerm holes))
    (request : AppendEntriesRequest Node (NatTerm holes)) :
    Guarded holes (Option (NodeState Node (NatTerm holes) × AppendEntriesResponse Node)) :=
  if request.entries ≠ [] ∧ request.prevLogIndex ≤ state.log.length ∧
      state.log.length < request.prevLogIndex + request.entries.length then
    let log := state.log.take request.prevLogIndex ++ request.entries
    let nextState := { state with log, commitIndex := committedFromLeader state request log }
    Guarded.branchSmart (prefixEqual state request)
      (.pure (some (nextState, successResponse nextState request log.length)))
      (.pure none)
  else
    .pure none

theorem extension_correct (assignment : Fin holes -> Nat)
    (state : NodeState Node (NatTerm holes))
    (request : AppendEntriesRequest Node (NatTerm holes)) :
    ((extension state request).eval assignment).map (mapResult (NatTerm.eval assignment)) =
      noConflictAppendEntriesRequest?
        (mapNodeState (NatTerm.eval assignment) state)
        (mapRequest (NatTerm.eval assignment) request) := by
  simp only [extension, noConflictAppendEntriesRequest?, noConflictExtension,
    mapRequest, mapNodeState, List.map_eq_nil_iff, List.length_map]
  split
  · rename_i structural
    rw [Guarded.eval_branchSmart]
    simp only [prefixEqual_correct]
    simp only [Guarded.eval]
    split
    · rename_i equal
      simp only [mapNodeState, mapRequest] at equal
      simp [structural, equal, mapResult, mapNodeState, mapRequest,
        committedFromLeader, successResponse, ← List.map_take, ← List.map_append]
    · rename_i different
      simp only [mapNodeState, mapRequest] at different
      simp [structural, different]
  · rename_i structural
    simp only [Guarded.eval, Option.map_none]
    have impossible :
        ¬(request.entries ≠ [] ∧ request.prevLogIndex ≤ state.log.length ∧
          state.log.length < request.prevLogIndex + request.entries.length ∧
          ((state.log.map (mapEntry (NatTerm.eval assignment))).drop request.prevLogIndex).take
              (state.log.length - request.prevLogIndex) =
            (request.entries.map (mapEntry (NatTerm.eval assignment))).take
              (state.log.length - request.prevLogIndex)) :=
      fun h => structural ⟨h.1, h.2.1, h.2.2.1⟩
    rw [if_neg impossible]

def accept (state : NodeState Node (NatTerm holes))
    (request : AppendEntriesRequest Node (NatTerm holes)) :
    Guarded holes (Option (NodeState Node (NatTerm holes) × AppendEntriesResponse Node)) :=
  if request.term = state.currentTerm ∧ state.role = .follower ∧
      logOk state request ∧ request.prevLogIndex ≥ state.commitIndex then
    match appendEntriesAlreadyDone? state request with
    | some result => .pure (some result)
    | none =>
        (extension state request).bind fun extended =>
          match extended with
          | some result => .pure (some result)
          | none =>
              match conflictAppendEntriesRequest? state request with
              | none => .pure none
              | some truncated =>
                  match appendEntriesAlreadyDone? truncated request with
                  | some result => .pure (some result)
                  | none => extension truncated request
  else .pure none

theorem accept_correct (assignment : Fin holes -> Nat)
    (state : NodeState Node (NatTerm holes))
    (request : AppendEntriesRequest Node (NatTerm holes)) :
    ((accept state request).eval assignment).map (mapResult (NatTerm.eval assignment)) =
      acceptAppendEntriesRequest?
        (mapNodeState (NatTerm.eval assignment) state)
        (mapRequest (NatTerm.eval assignment) request) := by
  simp only [accept, acceptAppendEntriesRequest?, logOk_map]
  change Option.map (mapResult (NatTerm.eval assignment))
    (Guarded.eval assignment (if request.term = state.currentTerm ∧
    state.role = Role.follower ∧ logOk state request ∧ request.prevLogIndex ≥ state.commitIndex
    then _ else _)) = (if request.term = state.currentTerm ∧
    state.role = Role.follower ∧ logOk state request ∧ request.prevLogIndex ≥ state.commitIndex
    then _ else _)
  split
  · rw [alreadyDoneResult_map]
    cases appendEntriesAlreadyDone? state request with
    | some result => rfl
    | none =>
        simp only [Option.map_none, Guarded.eval_bind]
        rw [← extension_correct]
        cases (extension state request).eval assignment with
        | some result => rfl
        | none =>
            simp only [Option.map_none]
            rw [conflict_map]
            cases conflictAppendEntriesRequest? state request with
            | none => rfl
            | some truncated =>
                simp only [Option.map_some]
                rw [alreadyDoneResult_map]
                cases appendEntriesAlreadyDone? truncated request with
                | some result => rfl
                | none => exact extension_correct assignment truncated request
  · rfl

def append (state : NodeState Node (NatTerm holes))
    (request : AppendEntriesRequest Node (NatTerm holes)) :
    Guarded holes (Option (NodeState Node (NatTerm holes) × AppendEntriesResponse Node)) :=
  match rejectAppendEntriesRequest? state request with
  | some result => .pure (some result)
  | none => accept state request

theorem append_correct (assignment : Fin holes -> Nat)
    (state : NodeState Node (NatTerm holes))
    (request : AppendEntriesRequest Node (NatTerm holes)) :
    ((append state request).eval assignment).map (mapResult (NatTerm.eval assignment)) =
      handleAppendEntriesRequest?
        (mapNodeState (NatTerm.eval assignment) state)
        (mapRequest (NatTerm.eval assignment) request) := by
  rw [append, handleAppendEntriesRequest?, reject_map]
  cases rejectAppendEntriesRequest? state request with
  | some result => rfl
  | none => exact accept_correct assignment state request

/-- Select the first packet from `source`, not the head of the destination queue. -/
def handle (state : State Node (NatTerm holes)) (source destination : Node) :
    Guarded holes (Option (State Node (NatTerm holes))) :=
  match takeFirstFrom source (state.network destination) with
  | none => .pure none
  | some (.appendEntriesRequest request, remaining) =>
      if request.destination != destination then .pure none
      else
        match returnToFollowerState? (state.nodes destination) request with
        | some nextNode =>
            .pure (some { state with nodes := updateNode state.nodes destination nextNode })
        | none =>
            (append (state.nodes destination) request).map fun result =>
              result.map (finishAppend state destination remaining)
  | some (_, _) => .pure (handleReceive? state source destination)

theorem handle_correct (assignment : Fin holes -> Nat)
    (state : State Node (NatTerm holes)) (source destination : Node) :
    ((handle state source destination).eval assignment).map (mapState (NatTerm.eval assignment)) =
      handleReceive? (mapState (NatTerm.eval assignment) state) source destination := by
  have mappedSelected :
      takeFirstFrom source ((mapState (NatTerm.eval assignment) state).network destination) =
        (takeFirstFrom source (state.network destination)).map
          (fun selected => (mapMessage (NatTerm.eval assignment) selected.1,
            selected.2.map (mapMessage (NatTerm.eval assignment)))) :=
    takeFirstFrom_map (NatTerm.eval assignment) source (state.network destination)
  cases selected : takeFirstFrom source (state.network destination) with
  | none => simp [handle, selected, handleReceive?, mappedSelected, Guarded.eval]
  | some selectedPacket =>
      rcases selectedPacket with ⟨message, remaining⟩
      cases message with
      | appendEntriesRequest request =>
          simp only [handle, selected]
          rw [handleReceive?, mappedSelected, selected]
          simp only [Option.map_some, mapMessage, Message.destination]
          split
          · rfl
          · rw [mapState_nodes_get]
            have mappedStepdown := returnToFollower_map
              (NatTerm.eval assignment) (state.nodes destination) request
            dsimp only [mapRequest] at mappedStepdown
            rw [mappedStepdown]
            cases returnToFollowerState? (state.nodes destination) request with
            | some nextNode =>
                simp [Guarded.eval, mapState, mapNodeStore_updateNode]
            | none =>
                simp only [Option.map_none, Guarded.eval_map]
                have mappedAppend := append_correct assignment (state.nodes destination) request
                dsimp only [mapRequest] at mappedAppend
                rw [← mappedAppend]
                cases (append (state.nodes destination) request).eval assignment with
                | none => rfl
                | some result =>
                    exact congrArg some (finishAppend_map (NatTerm.eval assignment)
                      state destination remaining result)
      | appendEntriesResponse response =>
          simpa only [handle, selected, Guarded.eval] using
            (nonRequest_receive_map (NatTerm.eval assignment) state source destination
            _ remaining selected (by trivial)).symm
      | requestVoteRequest request =>
          simpa only [handle, selected, Guarded.eval] using
            (nonRequest_receive_map (NatTerm.eval assignment) state source destination
            _ remaining selected (by trivial)).symm
      | requestVoteResponse response =>
          simpa only [handle, selected, Guarded.eval] using
            (nonRequest_receive_map (NatTerm.eval assignment) state source destination
            _ remaining selected (by trivial)).symm
      | requestPreVote request =>
          simpa only [handle, selected, Guarded.eval] using
            (nonRequest_receive_map (NatTerm.eval assignment) state source destination
            _ remaining selected (by trivial)).symm
      | requestPreVoteResponse response =>
          simpa only [handle, selected, Guarded.eval] using
            (nonRequest_receive_map (NatTerm.eval assignment) state source destination
            _ remaining selected (by trivial)).symm
      | proposeVoteRequest request =>
          simpa only [handle, selected, Guarded.eval] using
            (nonRequest_receive_map (NatTerm.eval assignment) state source destination
            _ remaining selected (by trivial)).symm

structure Result (holes : Nat) where
  enabled : Bool
  successor : State Node (NatTerm holes)

def Result.enabledExpr (result : Result holes) : Expr holes :=
  .boolean result.enabled

/-- Both fields describe the real receive under the same guard assignment. -/
def step (state : State Node (NatTerm holes)) (source destination : Node) :
    Guarded holes (Result holes) :=
  (handle state source destination).map fun result =>
    { enabled := decide (state.allocated destination) && result.isSome
      successor := result.getD state }

theorem step_enabled_correct (assignment : Fin holes -> Nat)
    (state : State Node (NatTerm holes)) (source destination : Node) :
    ((step state source destination).eval assignment).enabled = true ↔
      Enabled (mapState (NatTerm.eval assignment) state) (.receive source destination) := by
  have correct := handle_correct assignment state source destination
  simp only [step, Guarded.eval_map, Enabled, mapState_allocated, Bool.and_eq_true,
    decide_eq_true_eq]
  rw [← correct]
  simp

theorem step_enabledExpr_correct (assignment : Fin holes -> Nat)
    (state : State Node (NatTerm holes)) (source destination : Node) :
    ((step state source destination).eval assignment).enabledExpr.Holds assignment ↔
      Enabled (mapState (NatTerm.eval assignment) state) (.receive source destination) :=
  step_enabled_correct assignment state source destination

theorem step_correct (assignment : Fin holes -> Nat)
    (state : State Node (NatTerm holes)) (source destination : Node) :
    mapState (NatTerm.eval assignment)
        ((step state source destination).eval assignment).successor =
      next (mapState (NatTerm.eval assignment) state) (.receive source destination) := by
  have correct := handle_correct assignment state source destination
  simp only [step, Guarded.eval_map, next]
  rw [← correct]
  cases (handle state source destination).eval assignment <;> rfl

end CCFRaft.GuardedReceive
