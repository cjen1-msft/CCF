module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Init.Data.List.Pairwise

namespace ConsensusCoverage.CensusQueue

/-- An admitted one-copy step cannot send a value retained in its pending
queue. For every outgoing envelope, both network membership tests can be
read from the physical action and outputs without any residual queue. -/
public theorem outgoing_membership {before after pending outgoing removed : List α}
    (pre : ∀ e, e ∈ before ↔ e ∈ removed ∨ e ∈ pending)
    (post : ∀ e, e ∈ after ↔ e ∈ pending ∨ e ∈ outgoing)
    (oneCopy : (pending ++ outgoing).Nodup) {e : α} (sent : e ∈ outgoing) :
    (e ∈ before ↔ e ∈ removed) ∧ e ∈ after := by
  have fresh : e ∉ pending := fun retained =>
    (List.pairwise_append.mp oneCopy).2.2 e retained e sent rfl
  exact ⟨(pre e).trans (or_iff_left fresh), (post e).mpr (.inr sent)⟩

/-- A retained envelope never satisfies the `after`-but-not-`before`
guard. This direction does not require the one-copy bound. -/
public theorem retained_not_new [DecidableEq α] {before after pending : List α}
    (retained : ∀ e ∈ pending, e ∈ before) (guard : α → Bool) :
    pending.any (fun e => decide (e ∈ after) && !decide (e ∈ before) && guard e) = false := by
  apply Bool.eq_false_iff.mpr
  intro yes
  obtain ⟨e, hp, test⟩ := List.any_eq_true.mp yes
  simp [retained e hp] at test

end ConsensusCoverage.CensusQueue
