-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicReceiveDispatch
import MachineGenerated.SymbolicReceiveCases
import MachineGenerated.SymbolicReceiveFrame
import MachineGenerated.SymbolicTransitionQueue
import Shared.SymbolicTrace

set_option autoImplicit false
set_option maxHeartbeats 1000000

namespace CCFRaft.SymbolicReceive

open Symbolic SymbolicModel SymbolicTransition

def consumeKnown (bounds : BoundedState.Bounds) (entry : Expr (stateCodec bounds.transactionCount).ty)
    (destination : Expr nodeCodec.ty) (remaining : Expr queueCodec.ty) (source : Expr nodeCodec.ty)
    (value : Expr nodeStateCodec.option.ty) : Expr (stateCodec bounds.transactionCount).option.ty :=
  .ite (compact (allocated bounds.transactionCount entry source))
    (consume bounds entry destination remaining value)
    (.inr (writeQueue bounds.transactionCount entry destination remaining))

theorem consumeKnown_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (entry : Expr (stateCodec bounds.transactionCount).ty) (destination : Expr nodeCodec.ty)
    (remaining : Expr queueCodec.ty) (source : Expr nodeCodec.ty) (value : Expr nodeStateCodec.option.ty) :
    evalOptional bounds ρ (consumeKnown bounds entry destination remaining source value) =
      if (evalEntry bounds ρ entry).allocated (nodeCodec.decode ρ source) then
        (nodeStateCodec.option.decode ρ value).map
          (consumed (evalEntry bounds ρ entry) (nodeCodec.decode ρ destination) (queueCodec.decode ρ remaining))
      else some { evalEntry bounds ρ entry with
        network := updateQueue (evalEntry bounds ρ entry).network (nodeCodec.decode ρ destination)
          (queueCodec.decode ρ remaining) } := by
  simp only [consumeKnown, evalOptional_choose, compact_correct, allocated_correct bounds ρ entry source,
    consume_correct, evalOptional_some, writeQueue_correct]

def dispatch (bounds : BoundedState.Bounds) (entry : Expr (stateCodec bounds.transactionCount).ty)
    (destination : Expr nodeCodec.ty) (remaining : Expr queueCodec.ty) (message : Expr messageCodec.ty) :
    Expr (stateCodec bounds.transactionCount).option.ty :=
  let state := Local.unpack (readLocal bounds.transactionCount entry destination)
  messageCases message
    (receiveAppend bounds entry destination remaining)
    (fun r => consumeKnown bounds entry destination remaining r.snd.snd.snd.fst
      (appendResponse bounds.logCapacity state r))
    (fun r => respond voteResponseCodec bounds entry destination remaining
      (fun response => .inr (.inr (.inr (.inl response))))
      (voteRequest bounds.logCapacity state r))
    (fun r => consumeKnown bounds entry destination remaining r.snd.snd.fst (voteResponse state r))
    (fun r => respond preVoteResponseCodec bounds entry destination remaining
      (fun response => .inr (.inr (.inr (.inr (.inr (.inl response))))))
      (preVoteRequest bounds.logCapacity state r))
    (fun r => consumeKnown bounds entry destination remaining r.snd.snd.fst (preVoteResponse state r))
    (fun r => consume bounds entry destination remaining (proposal bounds entry destination r))

theorem dispatch_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (entry : Expr (stateCodec bounds.transactionCount).ty) (destination : Expr nodeCodec.ty)
    (remaining : Expr queueCodec.ty) (message : Expr messageCodec.ty)
    (stateBound : ((evalEntry bounds ρ entry).nodes (nodeCodec.decode ρ destination)).log.length ≤ bounds.logCapacity)
    (messageBound : BoundedState.MessageWithin bounds (messageCodec.decode ρ message)) :
    evalOptional bounds ρ (dispatch bounds entry destination remaining message) =
      dispatchModel (evalEntry bounds ρ entry) (nodeCodec.decode ρ destination) (queueCodec.decode ρ remaining)
        (messageCodec.decode ρ message) := by
  have localCorrect :
      (Local.unpack (readLocal bounds.transactionCount entry destination)).eval ρ =
        (evalEntry bounds ρ entry).nodes (nodeCodec.decode ρ destination) :=
    (Local.unpack_correct ρ _).trans (readLocal_correct bounds ρ entry destination)
  have logBound : (logCodec.decode ρ
      (Local.unpack (readLocal bounds.transactionCount entry destination)).log).length ≤ bounds.logCapacity := by
    change ((Local.unpack (readLocal bounds.transactionCount entry destination)).eval ρ).log.length ≤ _
    rw [localCorrect]
    exact stateBound
  unfold dispatch
  refine messageCases_correct
    (fun raw => ((stateCodec bounds.transactionCount).option.equiv raw).map
      (fun data : EntryData bounds.transactionCount => BoundedState.decode data.toData))
    ρ message (BoundedState.MessageWithin bounds)
    (dispatchModel (evalEntry bounds ρ entry) (nodeCodec.decode ρ destination) (queueCodec.decode ρ remaining))
    _ _ _ _ _ _ _ ?_ ?_ ?_ ?_ ?_ ?_ ?_ messageBound
  · intro request bounded
    exact receiveAppend_correct bounds ρ entry destination remaining request stateBound bounded.2.2.2.1
  · intro response _
    change evalOptional bounds ρ _ = _
    rw [consumeKnown_correct, appendResponse_correct ρ bounds.logCapacity _ response logBound, localCorrect]
    rfl
  · intro request _
    change evalOptional bounds ρ _ = _
    rw [respond_correct voteResponseCodec bounds ρ entry destination remaining _
      Message.requestVoteResponse (fun _ => rfl),
      voteRequest_correct ρ bounds.logCapacity _ request logBound, localCorrect]
    rfl
  · intro response _
    change evalOptional bounds ρ _ = _
    rw [consumeKnown_correct, voteResponse_correct, localCorrect]
    rfl
  · intro request _
    change evalOptional bounds ρ _ = _
    rw [respond_correct preVoteResponseCodec bounds ρ entry destination remaining _
      Message.requestPreVoteResponse (fun _ => rfl),
      preVoteRequest_correct ρ bounds.logCapacity _ request logBound, localCorrect]
    rfl
  · intro response _
    change evalOptional bounds ρ _ = _
    rw [consumeKnown_correct, preVoteResponse_correct, localCorrect]
    rfl
  · intro request _
    change evalOptional bounds ρ _ = _
    rw [consume_correct, proposal_correct bounds ρ entry destination request stateBound]
    rfl

theorem handleReceive_dispatch (state : State Node Nat) (source destination : Node) :
    handleReceive? state source destination =
      (takeFirstFrom source (state.network destination)).elim none
        (fun pair => if pair.1.destination = destination then dispatchModel state destination pair.2 pair.1 else none) := by
  cases selected : takeFirstFrom source (state.network destination) with
  | none => simp [handleReceive?, selected]
  | some pair =>
    rcases pair with ⟨message, remaining⟩
    simp only [handleReceive?, selected, Option.elim]
    have same : (destination != destination) = false := by simp
    by_cases dest : message.destination = destination
    · simp only [dest, same, Bool.false_eq_true, ↓reduceIte]
      cases message with
      | appendEntriesRequest request =>
        simp only [dispatchModel]
        cases returnToFollowerState? (state.nodes destination) request with
        | some node => rfl
        | none =>
          cases handleAppendEntriesRequest? (state.nodes destination) request <;>
            rfl
      | appendEntriesResponse response =>
        simp only [dispatchModel]
        by_cases allocated : state.allocated response.source <;> simp only [allocated, ↓reduceIte]
        · cases handleAppendEntriesResponse? (state.nodes destination) response <;> rfl
      | requestVoteRequest request =>
        simp only [dispatchModel]
        cases handleRequestVoteRequest? (state.nodes destination) request <;> rfl
      | requestVoteResponse response =>
        simp only [dispatchModel]
        by_cases allocated : state.allocated response.source <;> simp only [allocated, ↓reduceIte]
        · cases handleRequestVoteResponse? (state.nodes destination) response <;> rfl
      | requestPreVote request =>
        simp only [dispatchModel]
        cases handleRequestPreVote? (state.nodes destination) request <;> rfl
      | requestPreVoteResponse response =>
        simp only [dispatchModel]
        by_cases allocated : state.allocated response.source <;> simp only [allocated, ↓reduceIte]
        · cases handleRequestPreVoteResponse? (state.nodes destination) response <;> rfl
      | proposeVoteRequest request =>
        simp only [dispatchModel]
        cases handleProposeVoteRequest? state destination request <;> rfl
    · simp [dest]

def handle (bounds : BoundedState.Bounds) (entry : Expr (stateCodec bounds.transactionCount).ty)
    (source destination : Expr nodeCodec.ty) : Expr (stateCodec bounds.transactionCount).option.ty :=
  chooseOption (messageCodec.prod queueCodec)
    (queueTakeFirstById bounds.queueCapacity source (entryQueue bounds.transactionCount entry destination))
    (.inl .unit) fun pair =>
      .ite (compact (.eq (messageDestination pair.fst) destination))
        (dispatch bounds entry destination pair.snd pair.fst) (.inl .unit)

theorem handle_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (entry : Expr (stateCodec bounds.transactionCount).ty) (source destination : Expr nodeCodec.ty)
    (bound : BoundedState.WithinBounds bounds (evalEntry bounds ρ entry)) :
    evalOptional bounds ρ (handle bounds entry source destination) =
      handleReceive? (evalEntry bounds ρ entry) (nodeCodec.decode ρ source) (nodeCodec.decode ρ destination) := by
  have queueBound : (queueCodec.decode ρ (entryQueue bounds.transactionCount entry destination)).length ≤
      bounds.queueCapacity := by
    rw [entryQueue_correct]
    exact (bound.2.1 (nodeCodec.decode ρ destination)).1
  have selectedCorrect := queueTakeFirstById_correct ρ bounds.queueCapacity source
    (entryQueue bounds.transactionCount entry destination) queueBound
  rw [entryQueue_correct] at selectedCorrect
  rw [handle, evalOptional_cases (messageCodec.prod queueCodec) bounds ρ _ _ _
    (fun pair => if pair.1.destination = nodeCodec.decode ρ destination then
      dispatchModel (evalEntry bounds ρ entry) (nodeCodec.decode ρ destination) pair.2 pair.1 else none) (by
      intro pair selected
      rw [selectedCorrect] at selected
      have member := takeFirst_member (nodeCodec.decode ρ source)
        ((evalEntry bounds ρ entry).network (nodeCodec.decode ρ destination))
        ((messageCodec.prod queueCodec).decode ρ pair).1
        ((messageCodec.prod queueCodec).decode ρ pair).2 selected
      have messages := List.forall_iff_forall_mem.mp (bound.2.1 (nodeCodec.decode ρ destination)).2
      have messageBound := messages _ member
      rw [evalOptional_choose]
      simp only [compact_correct, nodeCodec.equal_correct ρ, messageDestination_correct, evalOptional_none]
      rw [dispatch_correct bounds ρ entry destination pair.snd pair.fst
        (local_log_bound bounds _ _ bound) messageBound]
      rfl), selectedCorrect, evalOptional_none, handleReceive_dispatch]

def successor (bounds : BoundedState.Bounds) (entry : Expr (stateCodec bounds.transactionCount).ty)
    (source destination : Expr nodeCodec.ty) : Expr (stateCodec bounds.transactionCount).ty :=
  Expr.fromRight (handle bounds entry source destination) entry

theorem successor_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (entry : Expr (stateCodec bounds.transactionCount).ty) (source destination : Expr nodeCodec.ty)
    (bound : BoundedState.WithinBounds bounds (evalEntry bounds ρ entry)) :
    evalEntry bounds ρ (successor bounds entry source destination) =
      next (evalEntry bounds ρ entry) (.receive (nodeCodec.decode ρ source) (nodeCodec.decode ρ destination)) := by
  have result : evalEntry bounds ρ (successor bounds entry source destination) =
      (evalOptional bounds ρ (handle bounds entry source destination)).getD (evalEntry bounds ρ entry) := by
    cases selected : (handle bounds entry source destination).eval ρ <;>
      simp [successor, evalEntry, evalOptional, Codec.decode, Codec.option,
        Expr.fromRight_correct, Expr.eval, selected]
  rw [result, handle_correct bounds ρ entry source destination bound]
  rfl

def enabled (bounds : BoundedState.Bounds) (entry : Expr (stateCodec bounds.transactionCount).ty)
    (source destination : Expr nodeCodec.ty) : Expr .bool :=
  (allocated bounds.transactionCount entry destination).and (isSome (handle bounds entry source destination))

theorem enabled_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (entry : Expr (stateCodec bounds.transactionCount).ty) (source destination : Expr nodeCodec.ty)
    (bound : BoundedState.WithinBounds bounds (evalEntry bounds ρ entry)) :
    (enabled bounds entry source destination).eval ρ = true ↔
      Enabled (evalEntry bounds ρ entry) (.receive (nodeCodec.decode ρ source) (nodeCodec.decode ρ destination)) := by
  have present : ((stateCodec bounds.transactionCount).option.decode ρ
      (handle bounds entry source destination)).isSome =
        (handleReceive? (evalEntry bounds ρ entry) (nodeCodec.decode ρ source) (nodeCodec.decode ρ destination)).isSome := by
    rw [← handle_correct bounds ρ entry source destination bound]
    simp [evalOptional]
  simp only [enabled, eval_and, Bool.and_eq_true, allocated_correct bounds ρ,
    isSome_correct (stateCodec bounds.transactionCount) ρ, present, Enabled]

def step (bounds : BoundedState.Bounds) (entry : Expr (stateCodec bounds.transactionCount).ty)
    (source destination : Node) : Symbolic.Trace.Step (stateCodec bounds.transactionCount).ty :=
  let entry := compact entry
  let s := nodeCodec.literal source
  let d := nodeCodec.literal destination
  let received := handle bounds entry s d
  let next := Expr.fromRight received entry
  let canReceive := (allocated bounds.transactionCount entry d).and (isSome received)
  { enabled := canReceive.and (postWithin bounds next s d),
    successor := next }

theorem step_accepted_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (entry : Expr (stateCodec bounds.transactionCount).ty) (source destination : Node)
    (bound : BoundedState.WithinBounds bounds (evalEntry bounds ρ entry)) :
    (step bounds entry source destination).enabled.eval ρ = true ↔
      Enabled (evalEntry bounds ρ entry) (.receive source destination) ∧
        BoundedState.WithinBounds bounds (next (evalEntry bounds ρ entry) (.receive source destination)) := by
  have normalized : BoundedState.WithinBounds bounds (evalEntry bounds ρ (compact entry)) := by
    simpa only [evalEntry_compact] using bound
  change ((enabled bounds (compact entry) (nodeCodec.literal source) (nodeCodec.literal destination)).and
    (postWithin bounds (successor bounds (compact entry) (nodeCodec.literal source) (nodeCodec.literal destination))
      (nodeCodec.literal source) (nodeCodec.literal destination))).eval ρ = true ↔ _
  simp only [compact_correct, eval_and, Bool.and_eq_true,
    enabled_correct bounds ρ (compact entry) _ _ normalized, postWithin_correct bounds ρ,
    evalEntry_compact, successor_correct bounds ρ (compact entry) _ _ normalized, Codec.decode_literal]
  rw [← next_bounds_iff bounds (evalEntry bounds ρ entry) source destination bound]

theorem step_next_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (entry : Expr (stateCodec bounds.transactionCount).ty) (source destination : Node)
    (bound : BoundedState.WithinBounds bounds (evalEntry bounds ρ entry)) :
    evalEntry bounds ρ (step bounds entry source destination).successor =
      next (evalEntry bounds ρ entry) (.receive source destination) := by
  have normalized : BoundedState.WithinBounds bounds (evalEntry bounds ρ (compact entry)) := by
    simpa only [evalEntry_compact] using bound
  simpa only [step, successor, Codec.decode_literal, evalEntry_compact] using
    successor_correct bounds ρ (compact entry) (nodeCodec.literal source) (nodeCodec.literal destination) normalized

end CCFRaft.SymbolicReceive
