-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicReceiveDispatch

set_option autoImplicit false

namespace CCFRaft.SymbolicReceive

open Symbolic SymbolicModel SymbolicTransition

theorem append_reply_destination (state : NodeState Node Nat) (request : AppendEntriesRequest Node Nat)
    (result : NodeState Node Nat × AppendEntriesResponse Node)
    (h : handleAppendEntriesRequest? state request = some result) :
    result.2.destination = request.source := by
  simp only [handleAppendEntriesRequest?, rejectAppendEntriesRequest?, acceptAppendEntriesRequest?,
    appendEntriesAlreadyDone?, noConflictAppendEntriesRequest?, conflictAppendEntriesRequest?] at h
  repeat' first | contradiction | split at h
  all_goals
    cases h
    first
    | rfl
    | rename_i selected
      split at selected <;> cases selected
  all_goals simp only [Prod.snd, failureResponse]
  all_goals first | rfl | (split_ifs <;> rfl)

theorem vote_reply_destination (state : NodeState Node Nat) (request : RequestVoteRequest Node)
    (result : NodeState Node Nat × RequestVoteResponse Node)
    (h : handleRequestVoteRequest? state request = some result) :
    result.2.destination = request.source := by
  unfold handleRequestVoteRequest? at h
  split at h <;> cases h <;> rfl

theorem preVote_reply_destination (state : NodeState Node Nat) (request : RequestPreVote Node)
    (result : NodeState Node Nat × RequestPreVoteResponse Node)
    (h : handleRequestPreVote? state request = some result) :
    result.2.destination = request.source := by
  unfold handleRequestPreVote? at h
  split at h <;> cases h <;> rfl

theorem takeFirst_source (source : Node) (queue : List (Message Node Nat)) :
    ∀ result, takeFirstFrom source queue = some result → result.1.source = source := by
  fun_induction takeFirstFrom source queue <;> intro result h <;> cases h <;> simp_all

theorem receive_network_frame (state after : State Node Nat) (source destination : Node)
    (h : handleReceive? state source destination = some after) :
    ∀ node, node ≠ source → node ≠ destination → after.network node = state.network node := by
  unfold handleReceive? at h
  repeat' first | contradiction | split at h
  all_goals
    cases h
    have selected := takeFirst_source source (state.network destination) _ (by assumption)
    first
    | have target := append_reply_destination _ _ _ (by assumption)
    | have target := vote_reply_destination _ _ _ (by assumption)
    | have target := preVote_reply_destination _ _ _ (by assumption)
    | skip
    intro node notSource notDestination
    simp_all [reply, CCFRaft.enqueue, updateQueue, Function.update_apply, Message.source,
      Message.destination, Ne.symm notSource, Ne.symm notDestination] <;>
      split_ifs <;> simp_all [Function.update_apply, Ne.symm notSource, Ne.symm notDestination]

theorem receive_frame (state after : State Node Nat) (source destination : Node)
    (h : handleReceive? state source destination = some after) :
    (∀ node, node ≠ destination → after.node? node = state.node? node) ∧
      after.submittedTxIds = state.submittedTxIds := by
  unfold handleReceive? at h
  repeat' first | contradiction | split at h
  all_goals
    cases h
    constructor
    · intro node different
      simp [State.node?, updateNode, NodeStore.node?, NodeStore.set, different, Ne.symm different]
    · rfl

theorem next_frame (state : State Node Nat) (source destination : Node) :
    (∀ node, node ≠ destination →
      (next state (.receive source destination)).node? node = state.node? node) ∧
      (next state (.receive source destination)).submittedTxIds = state.submittedTxIds := by
  cases h : handleReceive? state source destination with
  | none => simp [next, h]
  | some after => simpa only [next, h, Option.getD_some] using receive_frame state after source destination h

theorem next_network_frame (state : State Node Nat) (source destination : Node) :
    ∀ node, node ≠ source → node ≠ destination →
      (next state (.receive source destination)).network node = state.network node := by
  cases h : handleReceive? state source destination with
  | none => simp [next, h]
  | some after => simpa only [next, h, Option.getD_some] using
      receive_network_frame state after source destination h

theorem next_bounds_iff (bounds : BoundedState.Bounds) (state : State Node Nat)
    (source destination : Node) (bound : BoundedState.WithinBounds bounds state) :
    BoundedState.WithinBounds bounds (next state (.receive source destination)) ↔
      BoundedState.OptionalLocalWithin bounds ((next state (.receive source destination)).node? destination) ∧
      (((next state (.receive source destination)).network source).length ≤ bounds.queueCapacity ∧
        ((next state (.receive source destination)).network source).Forall (BoundedState.MessageWithin bounds)) ∧
      (((next state (.receive source destination)).network destination).length ≤ bounds.queueCapacity ∧
        ((next state (.receive source destination)).network destination).Forall (BoundedState.MessageWithin bounds)) := by
  constructor
  · intro h
    exact ⟨h.1 destination, h.2.1 source, h.2.1 destination⟩
  · rintro ⟨localBound, sourceBound, destinationBound⟩
    have frame := next_frame state source destination
    refine ⟨?_, ?_, ?_⟩
    · intro node
      by_cases same : node = destination
      · simpa only [same] using localBound
      · rw [frame.1 node same]
        exact bound.1 node
    · intro node
      by_cases atSource : node = source
      · simpa only [atSource] using sourceBound
      by_cases atDestination : node = destination
      · simpa only [atDestination] using destinationBound
      rw [next_network_frame state source destination node atSource atDestination]
      exact bound.2.1 node
    · rw [frame.2]
      exact bound.2.2

def postWithin (bounds : BoundedState.Bounds)
    (entry : Expr (stateCodec bounds.transactionCount).ty) (source destination : Expr nodeCodec.ty) : Expr .bool :=
  .and (optionalLocalWithin bounds (tableSelect entry.fst destination))
    (.and (queueWithin bounds (entryQueue bounds.transactionCount entry source))
      (queueWithin bounds (entryQueue bounds.transactionCount entry destination)))

theorem postWithin_correct (bounds : BoundedState.Bounds) (ρ : Assignment)
    (entry : Expr (stateCodec bounds.transactionCount).ty) (source destination : Expr nodeCodec.ty) :
    (postWithin bounds entry source destination).eval ρ = true ↔
      BoundedState.OptionalLocalWithin bounds ((evalEntry bounds ρ entry).node? (nodeCodec.decode ρ destination)) ∧
      (((evalEntry bounds ρ entry).network (nodeCodec.decode ρ source)).length ≤ bounds.queueCapacity ∧
        ((evalEntry bounds ρ entry).network (nodeCodec.decode ρ source)).Forall (BoundedState.MessageWithin bounds)) ∧
      (((evalEntry bounds ρ entry).network (nodeCodec.decode ρ destination)).length ≤ bounds.queueCapacity ∧
        ((evalEntry bounds ρ entry).network (nodeCodec.decode ρ destination)).Forall (BoundedState.MessageWithin bounds)) := by
  simp only [postWithin, eval_and, Bool.and_eq_true, optionalLocalWithin_correct bounds ρ,
    nodeTableSelect_correct localCodec.option ρ, queueWithin_correct bounds ρ, entryQueue_correct bounds ρ]
  apply and_congr
  · simp only [evalEntry, State.node?, BoundedState.decode, BoundedState.Data.node?_decodeNodes]
    change BoundedState.OptionalLocalDataWithin bounds _ ↔
      BoundedState.OptionalLocalWithin bounds
        ((((nodeTableCodec localCodec.option).decode ρ entry.fst).get (nodeCodec.decode ρ destination)).map
          BoundedState.decodeLocal)
    cases ((nodeTableCodec localCodec.option).decode ρ entry.fst).get (nodeCodec.decode ρ destination) <;> rfl
  · rfl

end CCFRaft.SymbolicReceive
