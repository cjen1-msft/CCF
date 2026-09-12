-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.LogMatchSummary
import Sparse.NativeLogRangeEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def maxMatchCandidate {context : List Ty} (selected : Term context .int)
    (eligible : Term (.int :: context) .bool) : Term (.int :: context) .bool :=
  let position : Term (.int :: context) .int := .bound .here
  all [
    implies
      (.equal (.add position (.integer 1)) (selected.weaken .int))
      eligible,
    implies (.le (selected.weaken .int) position) (.not eligible)]

def maxMatchTerm {context : List Ty}
    (length cap selected : Term context .int)
    (eligible : Term (.int :: context) .bool) : Term context .bool :=
  let limit := logRangeMinTerm cap length
  all [
    .le (.integer 0) selected,
    .le selected limit,
    boundedForall limit (maxMatchCandidate selected eligible)]

theorem max_match_candidate_eval {context : List Ty}
    (assignment : Assignment) (locals : Locals context)
    (selected : Term context .int) (eligible : Term (.int :: context) .bool)
    (position : Int) :
    (maxMatchCandidate selected eligible).eval
        assignment (locals.cons position) = true <->
      (position + 1 = selected.eval assignment locals ->
        eligible.eval assignment (locals.cons position) = true) /\
      (selected.eval assignment locals <= position ->
        eligible.eval assignment (locals.cons position) = false) := by
  simp only [maxMatchCandidate, all, List.foldr_cons, List.foldr_nil, Term.eval,
    Bool.and_eq_true, and_true]
  apply and_congr
  · rw [implies_eval]
    simp [Term.eval, Term.weaken_eval, Locals.cons]
  · rw [implies_eval]
    simp [Term.eval, Term.weaken_eval, Locals.cons]

theorem max_match_term_eval {context : List Ty}
    (assignment : Assignment) (locals : Locals context)
    (length cap selected : Term context .int)
    (eligible : Term (.int :: context) .bool) :
    (maxMatchTerm length cap selected eligible).eval assignment locals = true <->
      0 <= selected.eval assignment locals /\
      selected.eval assignment locals <=
        min (cap.eval assignment locals) (length.eval assignment locals) /\
      forall position : Int,
        0 <= position ->
        position < min (cap.eval assignment locals) (length.eval assignment locals) ->
          (position + 1 = selected.eval assignment locals ->
            eligible.eval assignment (locals.cons position) = true) /\
          (selected.eval assignment locals <= position ->
            eligible.eval assignment (locals.cons position) = false) := by
  simp only [maxMatchTerm, all, List.foldr_cons, List.foldr_nil, Term.eval,
    Bool.and_eq_true, decide_eq_true_eq, and_true, log_range_min_term_eval]
  apply and_congr_right'
  apply and_congr_right'
  rw [bounded_forall_eval]
  simp only [log_range_min_term_eval]
  apply forall_congr'
  intro position
  apply imp_congr_right
  intro _
  apply imp_congr_right
  intro _
  exact max_match_candidate_eval assignment locals selected eligible position

theorem max_match_term_correct {context : List Ty}
    (assignment : Assignment) (locals : Locals context)
    (length cap selected : Term context .int)
    (eligible : Term (.int :: context) .bool)
    (lengthNat capNat best : Nat) (eligibleModel : Nat -> Prop)
    (sameLength : length.eval assignment locals = (lengthNat : Int))
    (sameCap : cap.eval assignment locals = (capNat : Int))
    (sameSelected : selected.eval assignment locals = (best : Int))
    (sameEligible : forall position, position < min capNat lengthNat ->
      (eligible.eval assignment (locals.cons (position : Int)) = true <->
        eligibleModel position)) :
    (maxMatchTerm length cap selected eligible).eval assignment locals = true <->
      Sparse.LogMatchSummary.StorageSummary lengthNat capNat best eligibleModel := by
  rw [max_match_term_eval]
  constructor
  · rintro ⟨nonnegative, bound, positions⟩
    have bestBound : best <= min capNat lengthNat := by
      rw [sameSelected, sameCap, sameLength] at bound
      exact Int.ofNat_le.mp (by simpa only [Nat.cast_min] using bound)
    refine ⟨bestBound, ?_, ?_⟩
    · intro positive
      have live : best - 1 < min capNat lengthNat := by omega
      have selectedCase := (positions (best - 1 : Nat) (by omega)
        (by rw [sameCap, sameLength]; simpa only [Nat.cast_min] using Int.ofNat_lt.mpr live)).1
      apply (sameEligible (best - 1) live).mp
      apply selectedCase
      rw [sameSelected]
      omega
    · intro position after live
      have excluded := (positions (position : Int) (by omega)
        (by rw [sameCap, sameLength]; simpa only [Nat.cast_min] using Int.ofNat_lt.mpr live)).2
      have rejected := excluded (by rw [sameSelected]; exact Int.ofNat_le.mpr after)
      intro accepted
      have encoded := (sameEligible position live).mpr accepted
      rw [encoded] at rejected
      contradiction
  · rintro ⟨bestBound, selectedCase, excluded⟩
    refine ⟨by rw [sameSelected]; exact Int.natCast_nonneg best,
      by rw [sameSelected, sameCap, sameLength];
         simpa only [Nat.cast_min] using Int.ofNat_le.mpr bestBound,
      fun position nonnegative within => ?_⟩
    have natural : (position.toNat : Int) = position :=
      Int.toNat_of_nonneg nonnegative
    have live : position.toNat < min capNat lengthNat := by
      rw [sameCap, sameLength] at within
      apply Int.ofNat_lt.mp
      simpa only [Nat.cast_min] using natural.trans_lt within
    constructor
    · intro selected
      have positive : 0 < best := by
        rw [sameSelected] at selected
        omega
      have samePosition : position.toNat = best - 1 := by
        rw [sameSelected] at selected
        omega
      rw [<- natural, sameEligible position.toNat live, samePosition]
      exact selectedCase positive
    · intro after
      apply Bool.eq_false_iff.mpr
      intro accepted
      apply excluded position.toNat
      · rw [sameSelected] at after
        exact Int.ofNat_le.mp (by simpa [natural] using after)
      · exact live
      · exact (sameEligible position.toNat live).mp (by simpa [natural] using accepted)

theorem max_match_term_selected_nat {context : List Ty}
    (assignment : Assignment) (locals : Locals context)
    (length cap selected : Term context .int)
    (eligible : Term (.int :: context) .bool)
    (accepted :
      (maxMatchTerm length cap selected eligible).eval assignment locals = true) :
    exists best : Nat, selected.eval assignment locals = (best : Int) := by
  have nonnegative :=
    (max_match_term_eval assignment locals length cap selected eligible).mp accepted |>.1
  exact ⟨(selected.eval assignment locals).toNat,
    (Int.toNat_of_nonneg nonnegative).symm⟩

theorem max_match_term_sound {context : List Ty}
    (assignment : Assignment) (locals : Locals context)
    (length cap selected : Term context .int)
    (eligible : Term (.int :: context) .bool)
    (lengthNat capNat : Nat) (eligibleModel : Nat -> Prop)
    (sameLength : length.eval assignment locals = (lengthNat : Int))
    (sameCap : cap.eval assignment locals = (capNat : Int))
    (sameEligible : forall position, position < min capNat lengthNat ->
      (eligible.eval assignment (locals.cons (position : Int)) = true <->
        eligibleModel position))
    (accepted :
      (maxMatchTerm length cap selected eligible).eval assignment locals = true) :
    exists best : Nat,
      selected.eval assignment locals = (best : Int) /\
      Sparse.LogMatchSummary.StorageSummary lengthNat capNat best eligibleModel := by
  obtain ⟨best, sameSelected⟩ :=
    max_match_term_selected_nat assignment locals length cap selected eligible accepted
  exact ⟨best, sameSelected,
    (max_match_term_correct assignment locals length cap selected eligible
      lengthNat capNat best eligibleModel sameLength sameCap sameSelected
      sameEligible).mp accepted⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
