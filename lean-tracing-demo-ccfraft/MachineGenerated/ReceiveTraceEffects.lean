-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.GuardedReceive
import MachineGenerated.HandlerProofs

set_option autoImplicit false

namespace CCFRaft.ReceiveTraceEffects

open TraceSmt

def LogShape {holes : Nat} (before : NodeState Node (NatTerm holes))
    (request : AppendEntriesRequest Node (NatTerm holes)) (after : NodeState Node (NatTerm holes)) : Prop :=
  after.log = before.log ∨ after.log = before.log.take request.prevLogIndex ∨
    after.log = before.log.take request.prevLogIndex ++ request.entries

theorem extension_log {holes : Nat} (assignment : Fin holes -> Nat)
    (before after : NodeState Node (NatTerm holes)) (request : AppendEntriesRequest Node (NatTerm holes))
    (response : AppendEntriesResponse Node)
    (handled : ((GuardedReceive.extension before request).eval assignment) = some (after, response)) :
    after.log = before.log.take request.prevLogIndex ++ request.entries := by
  unfold GuardedReceive.extension at handled
  split at handled
  · simp only [Guarded.eval_branchSmart, Guarded.eval] at handled
    split at handled <;> simp_all
    exact (congrArg NodeState.log handled.1).symm
  · simp [Guarded.eval] at handled

theorem already_log {holes : Nat}
    (before after : NodeState Node (NatTerm holes)) (request : AppendEntriesRequest Node (NatTerm holes))
    (response : AppendEntriesResponse Node)
    (handled : appendEntriesAlreadyDone? before request = some (after, response)) :
    after.log = before.log := by
  unfold appendEntriesAlreadyDone? at handled
  split at handled <;> simp_all
  exact (congrArg NodeState.log handled.1).symm

theorem accept_log {holes : Nat} (assignment : Fin holes -> Nat)
    (before after : NodeState Node (NatTerm holes)) (request : AppendEntriesRequest Node (NatTerm holes))
    (response : AppendEntriesResponse Node)
    (handled : ((GuardedReceive.accept before request).eval assignment) = some (after, response)) :
    LogShape before request after := by
  unfold GuardedReceive.accept at handled
  split at handled
  · cases done : appendEntriesAlreadyDone? before request with
    | some pair =>
        simp only [done, Guarded.eval] at handled
        cases handled
        exact Or.inl (already_log before after request response done)
    | none =>
        simp only [done, Guarded.eval_bind] at handled
        cases extended : (GuardedReceive.extension before request).eval assignment with
        | some pair =>
            simp only [extended, Guarded.eval] at handled
            cases handled
            exact Or.inr (Or.inr (extension_log assignment before after request response extended))
        | none =>
            simp only [extended] at handled
            cases conflict : conflictAppendEntriesRequest? before request with
            | none => simp [conflict, Guarded.eval] at handled
            | some truncated =>
                have truncatedLog : truncated.log = before.log.take request.prevLogIndex := by
                  unfold conflictAppendEntriesRequest? at conflict
                  split at conflict <;> simp_all
                  exact (congrArg NodeState.log conflict).symm
                simp only [conflict] at handled
                cases retried : appendEntriesAlreadyDone? truncated request with
                | some pair =>
                    simp only [retried, Guarded.eval] at handled
                    cases handled
                    exact Or.inr (Or.inl ((already_log truncated after request response retried).trans truncatedLog))
                | none =>
                    simp only [retried] at handled
                    have copied := extension_log assignment truncated after request response handled
                    exact Or.inr (Or.inr (by simpa [truncatedLog, List.take_take] using copied))
  · simp [Guarded.eval] at handled

theorem append_log {holes : Nat} (assignment : Fin holes -> Nat)
    (before after : NodeState Node (NatTerm holes)) (request : AppendEntriesRequest Node (NatTerm holes))
    (response : AppendEntriesResponse Node)
    (handled : ((GuardedReceive.append before request).eval assignment) = some (after, response)) :
    LogShape before request after := by
  unfold GuardedReceive.append at handled
  cases rejected : rejectAppendEntriesRequest? before request with
  | none =>
      simp only [rejected] at handled
      exact accept_log assignment before after request response handled
  | some pair =>
      simp only [rejected, Guarded.eval] at handled
      cases handled
      unfold rejectAppendEntriesRequest? at rejected
      split at rejected <;> simp_all [LogShape]

theorem step_log {holes : Nat} (assignment : Fin holes -> Nat)
    (before : State Node (NatTerm holes)) (source destination : Node)
    (request : AppendEntriesRequest Node (NatTerm holes)) (remaining : List (Message Node (NatTerm holes)))
    (selected : takeFirstFrom source (before.network destination) = some (.appendEntriesRequest request, remaining)) :
    LogShape (before.nodes destination) request
      (((GuardedReceive.step before source destination).eval assignment).successor.nodes destination) := by
  simp only [GuardedReceive.step, Guarded.eval_map, GuardedReceive.handle, selected]
  split
  · exact Or.inl rfl
  · cases stepped : returnToFollowerState? (before.nodes destination) request with
    | some node =>
        simp only [stepped, Guarded.eval, Option.getD_some]
        have unchanged : node.log = (before.nodes destination).log := by
          unfold returnToFollowerState? at stepped
          split at stepped <;> simp_all
          exact (congrArg NodeState.log stepped).symm
        simpa [LogShape] using Or.inl (b := node.log = (before.nodes destination).log.take request.prevLogIndex ∨
          node.log = (before.nodes destination).log.take request.prevLogIndex ++ request.entries) unchanged
    | none =>
        simp only [stepped, Guarded.eval_map]
        cases handled : (GuardedReceive.append (before.nodes destination) request).eval assignment with
        | none => simp [handled, LogShape]
        | some pair =>
            have shape := append_log assignment (before.nodes destination) pair.1 request pair.2 handled
            simpa [handled, LogShape, ReceiveMapping.finishAppend, refreshRetirementState] using shape

theorem handler_commit {Tx : Type} [DecidableEq Tx]
    (before after : NodeState Node Tx) (request : AppendEntriesRequest Node Tx)
    (response : AppendEntriesResponse Node)
    (handled : handleAppendEntriesRequest? before request = some (after, response)) :
    after.commitIndex = before.commitIndex ∨
      after.commitIndex = committedFromLeader before request after.log := by
  simp only [handleAppendEntriesRequest?, rejectAppendEntriesRequest?, acceptAppendEntriesRequest?,
    appendEntriesAlreadyDone?, noConflictAppendEntriesRequest?, conflictAppendEntriesRequest?] at handled
  repeat' (split_ifs at handled <;> simp_all only [Option.some.injEq, Prod.mk.injEq])
  all_goals first
    | contradiction
    | rcases handled with ⟨rfl, rfl⟩; simp [committedFromLeader]

theorem receive_commit {Tx : Type} [DecidableEq Tx] (before : State Node Tx) (source destination : Node)
    (request : AppendEntriesRequest Node Tx) (remaining : List (Message Node Tx))
    (selected : takeFirstFrom source (before.network destination) = some (.appendEntriesRequest request, remaining)) :
    ((next before (.receive source destination)).nodes destination).commitIndex = (before.nodes destination).commitIndex ∨
      ((next before (.receive source destination)).nodes destination).commitIndex =
        committedFromLeader (before.nodes destination) request ((next before (.receive source destination)).nodes destination).log := by
  by_cases routed : request.destination = destination
  · cases stepped : returnToFollowerState? (before.nodes destination) request with
    | some node =>
        have unchanged : node.commitIndex = (before.nodes destination).commitIndex := by
          unfold returnToFollowerState? at stepped
          split at stepped <;> simp_all
          exact (congrArg NodeState.commitIndex stepped).symm
        simp [next, handleReceive?, selected, Message.destination, routed, stepped, unchanged]
    | none =>
        cases handled : handleAppendEntriesRequest? (before.nodes destination) request with
        | none => simp [next, handleReceive?, selected, Message.destination, routed, stepped, handled]
        | some pair =>
            simpa [next, handleReceive?, selected, Message.destination, routed, stepped, handled,
              refreshRetirementState] using handler_commit (before.nodes destination) pair.1 request pair.2 handled
  · simp [next, handleReceive?, selected, Message.destination, routed]

theorem termAt_append_right {Tx : Type} (left right : List (Entry Node Tx)) (index : Nat)
    (beyond : left.length < index) :
    termAt (left ++ right) index = termAt right (index - left.length) := by
  have positive : index ≠ 0 := by omega
  have offset : index - left.length ≠ 0 := by omega
  have outside : ¬index - 1 < left.length := by omega
  simp [termAt, entryAt?, positive, offset, List.getElem?_append, outside, Nat.sub_sub,
    Nat.add_comm]

theorem receive_role {Tx : Type} [DecidableEq Tx] (before : State Node Tx) (source destination : Node)
    (request : AppendEntriesRequest Node Tx) (remaining : List (Message Node Tx))
    (selected : takeFirstFrom source (before.network destination) = some (.appendEntriesRequest request, remaining)) :
    ((next before (.receive source destination)).nodes destination).role =
      if request.destination = destination ∧ request.term = (before.nodes destination).currentTerm ∧
          ((before.nodes destination).role = .candidate ∨ (before.nodes destination).role = .preVoteCandidate) then
        .follower else (before.nodes destination).role := by
  by_cases routed : request.destination = destination
  · by_cases stepped : request.term = (before.nodes destination).currentTerm ∧
        ((before.nodes destination).role = .candidate ∨ (before.nodes destination).role = .preVoteCandidate)
    · simp [next, handleReceive?, selected, Message.destination, routed, returnToFollowerState?, stepped]
    · have noStep : returnToFollowerState? (before.nodes destination) request = none := by
        simp [returnToFollowerState?, stepped]
      cases handled : handleAppendEntriesRequest? (before.nodes destination) request with
      | none => simp [next, handleReceive?, selected, Message.destination, routed, noStep, handled, stepped]
      | some pair =>
          have role := (handleAppendEntriesRequestLocalPost handled).roleUnchanged
          simp [next, handleReceive?, selected, Message.destination, routed, noStep, handled, stepped,
            refreshRetirementState, role]
  · simp [next, handleReceive?, selected, Message.destination, routed]

theorem takeFirst_length {Tx : Type} (source : Node) (queue remaining : List (Message Node Tx))
    (message : Message Node Tx) (selected : takeFirstFrom source queue = some (message, remaining)) :
    remaining.length + 1 = queue.length := by
  induction queue generalizing remaining with
  | nil => simp [takeFirstFrom] at selected
  | cons head rest ih =>
      simp only [takeFirstFrom] at selected
      split at selected
      · simp_all
      · cases taken : takeFirstFrom source rest with
        | none => simp [taken] at selected
        | some pair =>
            simp only [taken, Option.some.injEq, Prod.mk.injEq] at selected
            rcases selected with ⟨rfl, rfl⟩
            simpa using ih pair.2 taken

end CCFRaft.ReceiveTraceEffects
