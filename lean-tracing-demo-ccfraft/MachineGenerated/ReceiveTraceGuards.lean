-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.GuardedReceive
import MachineGenerated.HandlerProofs

set_option autoImplicit false

namespace CCFRaft.ReceiveTraceGuards

def progress {Tx : Type} (state : NodeState Node Tx) (request : AppendEntriesRequest Node Tx) : Prop :=
  alreadyDone state request ∨
    (request.entries ≠ [] ∧ request.prevLogIndex ≤ state.log.length ∧
      state.log.length < request.prevLogIndex + request.entries.length ∧ ¬hasTermConflict state request) ∨
    (hasTermConflict state request ∧ state.isNewFollower = true)

instance {Tx : Type} (state : NodeState Node Tx) (request : AppendEntriesRequest Node Tx) :
    Decidable (progress state request) := by
  unfold progress
  infer_instance

theorem accept_progress {Tx : Type} [DecidableEq Tx] (state : NodeState Node Tx)
    (request : AppendEntriesRequest Node Tx)
    (possible : (acceptAppendEntriesRequest? state request).isSome) : progress state request := by
  by_contra invalid
  have noDone : appendEntriesAlreadyDone? state request = none := by
    unfold appendEntriesAlreadyDone?
    split_ifs <;> first | rfl | exact False.elim (invalid (Or.inl ‹_›))
  have noExtension : noConflictAppendEntriesRequest? state request = none := by
    have prefixTerms (extension : noConflictExtension state request) : ¬hasTermConflict state request := by
      have count : overlapLength state request = state.log.length - request.prevLogIndex := by
        have shorter := extension.2.2.1
        unfold overlapLength
        omega
      intro conflict
      apply conflict.2
      rw [count]
      exact congrArg (List.map Entry.term) extension.2.2.2
    unfold noConflictAppendEntriesRequest?
    split_ifs <;> first
      | rfl
      | exact False.elim (invalid (Or.inr (Or.inl ⟨‹noConflictExtension state request›.1,
          ‹noConflictExtension state request›.2.1, ‹noConflictExtension state request›.2.2.1,
          prefixTerms ‹noConflictExtension state request›⟩)))
  have noConflict : conflictAppendEntriesRequest? state request = none := by
    unfold conflictAppendEntriesRequest?
    split_ifs <;> first | rfl | exact False.elim (invalid (Or.inr (Or.inr ‹_›)))
  simp [acceptAppendEntriesRequest?, noDone, noExtension, noConflict] at possible

def header {Tx : Type} (state : State Node Tx) (destination : Node) (message : Message Node Tx) : Prop :=
  message.destination = destination ∧
    match message with
    | .appendEntriesRequest request =>
        request.term < (state.nodes destination).currentTerm ∨
          (request.term = (state.nodes destination).currentTerm ∧
            ((state.nodes destination).role = .candidate ∨
              (state.nodes destination).role = .preVoteCandidate ∨
              ((state.nodes destination).role = .follower ∧
                (¬ logOk (state.nodes destination) request ∨
                  ((state.nodes destination).commitIndex ≤ request.prevLogIndex ∧
                    progress (state.nodes destination) request)))))
    | .appendEntriesResponse response =>
        ¬state.allocated response.source ∨ response.success = false ∨
          (state.nodes destination).role ≠ .leader ∨ response.term ≤ (state.nodes destination).currentTerm
    | .requestVoteRequest request => request.term ≤ (state.nodes destination).currentTerm
    | .requestPreVote request => request.term ≤ (state.nodes destination).currentTerm
    | .requestVoteResponse response =>
        ¬state.allocated response.source ∨ (state.nodes destination).role ≠ .candidate ∨
          response.term ≤ (state.nodes destination).currentTerm
    | .requestPreVoteResponse response =>
        ¬state.allocated response.source ∨ (state.nodes destination).role ≠ .preVoteCandidate ∨
          response.term ≤ (state.nodes destination).currentTerm
    | .proposeVoteRequest request => request.term ≤ (state.nodes destination).currentTerm

instance {Tx : Type} (state : State Node Tx) (destination : Node) (message : Message Node Tx) :
    Decidable (header state destination message) := by
  cases message <;> unfold header <;> infer_instance

theorem append_header {Tx : Type} [DecidableEq Tx] (state : NodeState Node Tx)
    (request : AppendEntriesRequest Node Tx)
    (possible : (returnToFollowerState? state request).isSome ∨
      (handleAppendEntriesRequest? state request).isSome) :
    request.term < state.currentTerm ∨
      request.term = state.currentTerm ∧
        (state.role = .candidate ∨ state.role = .preVoteCandidate ∨
          (state.role = .follower ∧ (¬ logOk state request ∨
            (state.commitIndex ≤ request.prevLogIndex ∧ progress state request)))) := by
  by_contra invalid
  have noStep : returnToFollowerState? state request = none := by
    unfold returnToFollowerState?
    split_ifs <;> first | rfl | tauto
  have noReject : rejectAppendEntriesRequest? state request = none := by
    unfold rejectAppendEntriesRequest?
    split_ifs <;> first | rfl | tauto
  have noAccept : acceptAppendEntriesRequest? state request = none := by
    by_cases progress : progress state request
    · unfold acceptAppendEntriesRequest?
      split_ifs <;> first | rfl | tauto
    · cases result : acceptAppendEntriesRequest? state request with
      | none => rfl
      | some value => exact False.elim (progress (accept_progress state request (by simp [result])))
  simp [noStep, handleAppendEntriesRequest?, noReject, noAccept] at possible

theorem header_necessary {Tx : Type} [DecidableEq Tx]
    (state : State Node Tx) (source destination : Node) (message : Message Node Tx)
    (remaining : List (Message Node Tx))
    (selected : takeFirstFrom source (state.network destination) = some (message, remaining))
    (enabled : (handleReceive? state source destination).isSome) :
    header state destination message := by
  have routed : message.destination = destination := by
    by_contra wrong
    simp [handleReceive?, selected, wrong] at enabled
  refine ⟨routed, ?_⟩
  cases message with
  | appendEntriesRequest request =>
      apply append_header (state.nodes destination) request
      cases step : returnToFollowerState? (state.nodes destination) request with
      | some node => simp [step]
      | none =>
          cases result : handleAppendEntriesRequest? (state.nodes destination) request with
          | some result => simp [result]
          | none => simp [handleReceive?, selected, routed, step, result] at enabled
  | appendEntriesResponse response =>
      by_contra wrong
      simp only [not_or, not_not, Bool.not_eq_false] at wrong
      rcases wrong with ⟨allocated, success, role, term⟩
      have greater : (state.nodes destination).currentTerm < response.term := by omega
      simp [handleReceive?, selected, routed, allocated, handleAppendEntriesResponse?,
        success, role, Nat.ne_of_gt greater, Nat.not_lt_of_ge (Nat.le_of_lt greater)] at enabled
  | requestVoteRequest request =>
      by_contra wrong
      simp [handleReceive?, selected, routed, handleRequestVoteRequest?, wrong] at enabled
  | requestPreVote request =>
      by_contra wrong
      simp [handleReceive?, selected, routed, handleRequestPreVote?, wrong, RequestPreVote.toRequestVoteRequest] at enabled
  | requestVoteResponse response =>
      by_contra wrong
      simp only [not_or, not_not] at wrong
      rcases wrong with ⟨allocated, role, term⟩
      have greater : (state.nodes destination).currentTerm < response.term := by omega
      simp [handleReceive?, selected, routed, allocated, handleRequestVoteResponse?,
        role, Nat.ne_of_gt greater, Nat.not_lt_of_ge (Nat.le_of_lt greater)] at enabled
  | requestPreVoteResponse response =>
      by_contra wrong
      simp only [not_or, not_not] at wrong
      rcases wrong with ⟨allocated, role, term⟩
      have greater : (state.nodes destination).currentTerm < response.term := by omega
      simp [handleReceive?, selected, routed, allocated, handleRequestPreVoteResponse?,
        role, Nat.ne_of_gt greater, Nat.not_lt_of_ge (Nat.le_of_lt greater)] at enabled
  | proposeVoteRequest request =>
      by_contra wrong
      have greater : (state.nodes destination).currentTerm < request.term := by omega
      simp [handleReceive?, selected, routed, handleProposeVoteRequest?, greater] at enabled

def allowed {Tx : Type} (state : State Node Tx) (source destination : Node) : Bool :=
  decide (state.allocated destination) &&
    ((takeFirstFrom source (state.network destination)).map
      (fun selected => decide (header state destination selected.1))).getD false

theorem allowed_of_enabled {Tx : Type} [DecidableEq Tx]
    (state : State Node Tx) (source destination : Node)
    (enabled : Enabled state (.receive source destination)) :
    allowed state source destination = true := by
  rcases enabled with ⟨allocated, enabled⟩
  cases selected : takeFirstFrom source (state.network destination) with
  | none => simp [handleReceive?, selected] at enabled
  | some pair =>
      have valid := header_necessary state source destination pair.1 pair.2 selected enabled
      simp [allowed, allocated, selected, valid]

theorem proposal_node {Tx : Type} [DecidableEq Tx] (state : State Node Tx)
    (source destination : Node) (request : ProposeVoteRequest Node) (remaining : List (Message Node Tx))
    (selected : takeFirstFrom source (state.network destination) = some (.proposeVoteRequest request, remaining)) :
    (next state (.receive source destination)).nodes destination =
      if request.destination = destination ∧ request.term = (state.nodes destination).currentTerm ∧
          candidateTransitionEnabled state destination then
        becomeCandidateNodeState (state.nodes destination) destination
      else state.nodes destination := by
  by_cases routed : request.destination = destination
  · by_cases greater : (state.nodes destination).currentTerm < request.term
    · simp [next, handleReceive?, selected, Message.destination, routed,
        handleProposeVoteRequest?, greater, Nat.ne_of_gt greater]
    · by_cases eligible : request.term = (state.nodes destination).currentTerm ∧ candidateTransitionEnabled state destination
      · simp [next, handleReceive?, selected, Message.destination, routed,
          handleProposeVoteRequest?, greater, eligible]
      · simp [next, handleReceive?, selected, Message.destination, routed,
          handleProposeVoteRequest?, greater, eligible]
  · simp [next, handleReceive?, selected, Message.destination, routed]

theorem proposal_step_state {holes : Nat} (assignment : Fin holes -> Nat)
    (state : State Node (TraceSmt.NatTerm holes)) (source destination : Node)
    (request : ProposeVoteRequest Node) (remaining : List (Message Node (TraceSmt.NatTerm holes)))
    (selected : takeFirstFrom source (state.network destination) = some (.proposeVoteRequest request, remaining)) :
    ((GuardedReceive.step state source destination).eval assignment).successor =
      next state (.receive source destination) := by
  simp only [GuardedReceive.step, TraceSmt.Guarded.eval_map, GuardedReceive.handle, selected,
    TraceSmt.Guarded.eval, next]

theorem response_node {Tx : Type} [DecidableEq Tx] (state : State Node Tx)
    (source destination : Node) (response : AppendEntriesResponse Node) (remaining : List (Message Node Tx))
    (selected : takeFirstFrom source (state.network destination) = some (.appendEntriesResponse response, remaining)) :
    (next state (.receive source destination)).nodes destination =
      if response.destination = destination ∧ state.allocated source then
        if response.success = true ∧ response.term = (state.nodes destination).currentTerm ∧
            (state.nodes destination).role = .leader then
          { state.nodes destination with
            matchIndex := updateIndex (state.nodes destination).matchIndex source
              (max ((state.nodes destination).matchIndex source) response.lastLogIndex) }
        else if response.success = false then
          { state.nodes destination with
            sentIndex := updateIndex (state.nodes destination).sentIndex source
              (max (min (findHighestPossibleMatch (state.nodes destination).log response.lastLogIndex response.term)
                ((state.nodes destination).sentIndex source)) ((state.nodes destination).matchIndex source)) }
        else state.nodes destination
      else state.nodes destination := by
  have sender : response.source = source := (takeFirstFromSound selected).1
  by_cases routed : response.destination = destination <;>
    by_cases allocated : state.allocated source <;>
      simp [next, handleReceive?, selected, Message.destination, routed, sender, allocated,
        handleAppendEntriesResponse?]
  all_goals split_ifs <;> simp_all

theorem nonAppend_step_state {holes : Nat} (assignment : Fin holes -> Nat)
    (state : State Node (TraceSmt.NatTerm holes)) (source destination : Node)
    (message : Message Node (TraceSmt.NatTerm holes)) (remaining : List (Message Node (TraceSmt.NatTerm holes)))
    (selected : takeFirstFrom source (state.network destination) = some (message, remaining))
    (nonAppend : match message with | .appendEntriesRequest _ => False | _ => True) :
    ((GuardedReceive.step state source destination).eval assignment).successor =
      next state (.receive source destination) := by
  cases message <;>
    simp_all only [GuardedReceive.step, TraceSmt.Guarded.eval_map, GuardedReceive.handle,
      TraceSmt.Guarded.eval, next]

end CCFRaft.ReceiveTraceGuards
