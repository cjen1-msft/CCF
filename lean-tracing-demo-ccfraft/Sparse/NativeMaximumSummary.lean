-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.LogMatchSummary

set_option autoImplicit false

namespace CCFRaft.NativeMaximumSummary

open Sparse.LogMatchSummary

private def candidates (eligible : Nat -> Prop) [DecidablePred eligible]
    (bound : Nat) : Finset Nat :=
  (Finset.range (bound + 1)).filter eligible

private theorem candidate_mem (eligible : Nat -> Prop) [DecidablePred eligible]
    (bound candidate : Nat) :
    candidate ∈ candidates eligible bound <->
      candidate <= bound /\ eligible candidate := by
  simp [candidates]

private theorem fold_eq_sup (eligible : Nat -> Prop) [DecidablePred eligible]
    (bound : Nat) :
    (List.range (bound + 1)).foldl
        (fun best candidate => if eligible candidate then max best candidate else best) 0 =
      (candidates eligible bound).sup id := by
  let predicate := fun candidate => decide (eligible candidate)
  have filtered :
      (List.range (bound + 1)).foldl
          (fun best candidate => if eligible candidate then max best candidate else best) 0 =
        ((List.range (bound + 1)).filter predicate).foldl max 0 := by
    rw [List.foldl_filter]
    simp only [predicate, decide_eq_true_eq]
  rw [filtered, List.foldl_eq_foldr]
  have folded := List.foldr_sup_eq_sup_toFinset
    ((List.range (bound + 1)).filter predicate)
  have same :
      ((List.range (bound + 1)).filter predicate).toFinset =
        candidates eligible bound := by
    ext candidate
    simp [candidates, predicate]
  rw [same] at folded
  simpa using folded

theorem storage_summary_congr (left right : Nat -> Prop) (length cap best : Nat)
    (same : forall position, position < min cap length ->
      (left position <-> right position)) :
    StorageSummary length cap best left <->
      StorageSummary length cap best right := by
  constructor
  · rintro ⟨bound, selected, excluded⟩
    refine ⟨bound, ?_, ?_⟩
    · intro positive
      exact (same (best - 1) (by omega)).mp (selected positive)
    · intro position after within hit
      exact excluded position after within ((same position within).mpr hit)
  · rintro ⟨bound, selected, excluded⟩
    refine ⟨bound, ?_, ?_⟩
    · intro positive
      exact (same (best - 1) (by omega)).mpr (selected positive)
    · intro position after within hit
      exact excluded position after within ((same position within).mp hit)

theorem storage_summary_unique (eligible : Nat -> Prop) (length cap left right : Nat)
    (leftSummary : StorageSummary length cap left eligible)
    (rightSummary : StorageSummary length cap right eligible) :
    left = right := by
  apply Nat.le_antisymm
  · by_contra larger
    have rightLtLeft : right < left := by omega
    have leftPositive : 0 < left := by omega
    have after : right <= left - 1 := by omega
    have within : left - 1 < min cap length := by
      have bound := leftSummary.1
      omega
    exact rightSummary.2.2 (left - 1) after within
      (leftSummary.2.1 leftPositive)
  · by_contra larger
    have leftLtRight : left < right := by omega
    have rightPositive : 0 < right := by omega
    have after : left <= right - 1 := by omega
    have within : right - 1 < min cap length := by
      have bound := rightSummary.1
      omega
    exact leftSummary.2.2 (right - 1) after within
      (rightSummary.2.1 rightPositive)

theorem bounded_maximum_summary (eligible : Nat -> Prop) [DecidablePred eligible]
    (length cap : Nat) :
    let best :=
      (List.range (min cap length + 1)).foldl
        (fun best candidate => if eligible candidate then max best candidate else best) 0
    StorageSummary length cap best (fun position => eligible (position + 1)) := by
  let bound := min cap length
  let best :=
    (List.range (bound + 1)).foldl
      (fun best candidate => if eligible candidate then max best candidate else best) 0
  have bestSup : best = (candidates eligible bound).sup id := by
    exact fold_eq_sup eligible bound
  have bestBound : best <= bound := by
    rw [bestSup]
    exact Finset.sup_le fun candidate member =>
      (candidate_mem eligible bound candidate).mp member |>.1
  have selected : 0 < best -> eligible best := by
    intro positive
    have nonempty : (candidates eligible bound).Nonempty := by
      by_contra empty
      have absent := Finset.not_nonempty_iff_eq_empty.mp empty
      rw [bestSup, absent, Finset.sup_empty] at positive
      exact Nat.not_lt_zero _ positive
    have member : (candidates eligible bound).sup id ∈ candidates eligible bound := by
      simpa using Finset.sup_mem_of_nonempty (f := id) nonempty
    rw [<- bestSup] at member
    exact (candidate_mem eligible bound best).mp member |>.2
  have dominates (candidate : Nat) (within : candidate <= bound)
      (hit : eligible candidate) : candidate <= best := by
    rw [bestSup]
    exact Finset.le_sup (f := id)
      ((candidate_mem eligible bound candidate).mpr ⟨within, hit⟩)
  change StorageSummary length cap best (fun position => eligible (position + 1))
  refine ⟨by simpa [bound] using bestBound, ?_, ?_⟩
  · intro positive
    have shifted : best - 1 + 1 = best := by omega
    rw [shifted]
    exact selected positive
  · intro position after within hit
    have candidateWithin : position + 1 <= bound := by
      simpa [bound] using within
    have candidateDominates := dominates (position + 1) candidateWithin hit
    omega

theorem bounded_maximum_iff_storage_summary
    (eligible : Nat -> Prop) [DecidablePred eligible]
    (length cap best : Nat) :
    ((List.range (min cap length + 1)).foldl
        (fun best candidate => if eligible candidate then max best candidate else best) 0 =
      best) <->
      StorageSummary length cap best (fun position => eligible (position + 1)) := by
  let result :=
    (List.range (min cap length + 1)).foldl
      (fun best candidate => if eligible candidate then max best candidate else best) 0
  have resultSummary :
      StorageSummary length cap result (fun position => eligible (position + 1)) := by
    exact bounded_maximum_summary eligible length cap
  constructor
  · intro equal
    rw [<- equal]
    exact resultSummary
  · intro summary
    exact storage_summary_unique (fun position => eligible (position + 1))
      length cap result best resultSummary summary

end CCFRaft.NativeMaximumSummary

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeMaximumSummary).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
