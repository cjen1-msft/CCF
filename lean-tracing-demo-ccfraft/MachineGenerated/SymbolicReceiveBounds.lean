-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicReceiveAppend

set_option autoImplicit false

namespace CCFRaft.SymbolicReceive

theorem takeFirst_member (source : Node) (queue : List (Message Node Nat))
    (message : Message Node Nat) (remaining : List (Message Node Nat))
    (selected : takeFirstFrom source queue = some (message, remaining)) :
    message ∈ queue := by
  induction queue generalizing remaining with
  | nil => simp [takeFirstFrom] at selected
  | cons head tail ih =>
    simp only [takeFirstFrom] at selected
    split at selected
    · cases selected; simp
    · cases h : takeFirstFrom source tail with
      | none => simp [h] at selected
      | some result =>
        simp only [h, Option.some.injEq, Prod.mk.injEq] at selected
        rcases result with ⟨found, rest⟩
        obtain ⟨rfl, rfl⟩ := selected
        exact List.mem_cons_of_mem _ (ih _ h)

theorem append_result_log_bound (capacity : Nat) (state : NodeState Node Nat)
    (request : AppendEntriesRequest Node Nat) (result : NodeState Node Nat × AppendEntriesResponse Node)
    (stateBound : state.log.length ≤ capacity) (requestBound : request.entries.length ≤ capacity)
    (handled : handleAppendEntriesRequest? state request = some result) :
    result.1.log.length ≤ capacity * 2 := by
  have done (s : NodeState Node Nat) (r : NodeState Node Nat × AppendEntriesResponse Node)
      (sb : s.log.length ≤ capacity) (h : appendEntriesAlreadyDone? s request = some r) :
      r.1.log.length ≤ capacity * 2 := by
    unfold appendEntriesAlreadyDone? at h
    split at h
    · cases h; simp only; omega
    · contradiction
  have extension (s : NodeState Node Nat) (r : NodeState Node Nat × AppendEntriesResponse Node)
      (sb : s.log.length ≤ capacity) (h : noConflictAppendEntriesRequest? s request = some r) :
      r.1.log.length ≤ capacity * 2 := by
    unfold noConflictAppendEntriesRequest? at h
    split at h
    · cases h
      simp only [List.length_append, List.length_take]
      exact le_trans (Nat.add_le_add (le_trans (Nat.min_le_right _ _) sb) requestBound) (by omega)
    · contradiction
  have conflict (s truncated : NodeState Node Nat) (sb : s.log.length ≤ capacity)
      (h : conflictAppendEntriesRequest? s request = some truncated) : truncated.log.length ≤ capacity := by
    unfold conflictAppendEntriesRequest? at h
    split at h
    · cases h
      simpa only [List.length_take] using le_trans (Nat.min_le_right request.prevLogIndex s.log.length) sb
    · contradiction
  unfold handleAppendEntriesRequest? at handled
  cases rejected : rejectAppendEntriesRequest? state request with
  | some rejectedResult =>
    simp only [rejected, Option.some.injEq] at handled
    subst result
    unfold rejectAppendEntriesRequest? at rejected
    split at rejected
    · cases rejected; simp only; omega
    · contradiction
  | none =>
    simp only [rejected] at handled
    unfold acceptAppendEntriesRequest? at handled
    split at handled
    · cases applied : appendEntriesAlreadyDone? state request with
      | some r =>
        simp only [applied, Option.some.injEq] at handled
        subst result
        exact done state r stateBound applied
      | none =>
        simp only [applied] at handled
        cases extended : noConflictAppendEntriesRequest? state request with
        | some r =>
          simp only [extended, Option.some.injEq] at handled
          subst result
          exact extension state r stateBound extended
        | none =>
          simp only [extended] at handled
          cases truncated : conflictAppendEntriesRequest? state request with
          | none => simp [truncated] at handled
          | some s =>
            simp only [truncated] at handled
            have sb := conflict state s stateBound truncated
            cases retry : appendEntriesAlreadyDone? s request with
            | some r =>
              simp only [retry, Option.some.injEq] at handled
              subst result
              exact done s r sb retry
            | none =>
              simp only [retry] at handled
              exact extension s result sb handled
    · contradiction

end CCFRaft.SymbolicReceive
