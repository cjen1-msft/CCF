-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayFirstMatch
import Sparse.NativeSignatureEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def firstMatchValue : Option Nat -> Int
  | none => -1
  | some index => index

def firstMatchCandidate {context : List Ty} (limit selected : Term context .int)
    (predicate : Term (.int :: context) .bool) : Term (.int :: context) .bool :=
  implies
    (all [
      .le (.integer 0) (.bound .here),
      lt (.bound .here) (limit.weaken .int)])
    (all [
      implies (.equal (selected.weaken .int) (.bound .here)) predicate,
      implies
        (.or (.equal (selected.weaken .int) (.integer (-1)))
          (lt (.bound .here) (selected.weaken .int)))
        (.not predicate)])

def firstMatchTerm {context : List Ty} (limit selected : Term context .int)
    (predicate : Term (.int :: context) .bool) : Term context .bool :=
  all [
    .or (.equal selected (.integer (-1)))
      (all [.le (.integer 0) selected, lt selected limit]),
    .forall_ .int (firstMatchCandidate limit selected predicate)]

theorem first_match_candidate_eval {context : List Ty}
    (assignment : Assignment) (locals : Locals context)
    (limit selected : Term context .int) (predicate : Term (.int :: context) .bool)
    (candidate : Int) :
    (firstMatchCandidate limit selected predicate).eval assignment (locals.cons candidate) = true <->
      0 <= candidate -> candidate < limit.eval assignment locals ->
        (selected.eval assignment locals = candidate ->
          predicate.eval assignment (locals.cons candidate) = true) /\
        ((selected.eval assignment locals = -1 \/
            candidate < selected.eval assignment locals) ->
          predicate.eval assignment (locals.cons candidate) = false) := by
  rw [firstMatchCandidate, implies_eval]
  constructor
  · intro accepted nonnegative within
    have live :
        (all [
          .le (.integer 0) (.bound .here),
          lt (.bound .here) (limit.weaken .int)]).eval
            assignment (locals.cons candidate) = true := by
      simp [all, Term.eval, Locals.cons, Term.weaken_eval, lt, nonnegative, within]
    have consequences := accepted live
    simp only [all, List.foldr_cons, List.foldr_nil, Term.eval, Bool.and_eq_true,
      and_true] at consequences
    have selectedCase := consequences.1
    have earlierCase := consequences.2
    have selectedImp := (implies_eval
      (.equal (selected.weaken .int) (.bound .here)) predicate
      assignment (locals.cons candidate)).mp selectedCase
    have earlierImp := (implies_eval
      (.or (.equal (selected.weaken .int) (.integer (-1)))
        (lt (.bound .here) (selected.weaken .int)))
      (.not predicate) assignment (locals.cons candidate)).mp earlierCase
    constructor
    · simpa [Term.eval, Term.weaken_eval, Locals.cons] using selectedImp
    · simpa [Term.eval, Term.weaken_eval, Locals.cons, lt] using earlierImp
  · intro expected live
    have separated := live
    simp only [all, List.foldr_cons, List.foldr_nil, Term.eval, Bool.and_eq_true,
      and_true] at separated
    have nonnegative : 0 <= candidate := by
      have lower := separated.1
      simpa only [Term.eval, decide_eq_true_eq] using lower
    have within : candidate < limit.eval assignment locals := by
      have upper := separated.2
      simpa only [lt, Term.eval, Term.weaken_eval, Bool.not_eq_true',
        decide_eq_false_iff_not, not_le] using upper
    obtain ⟨selectedCase, earlierCase⟩ := expected nonnegative within
    simp only [all, List.foldr_cons, List.foldr_nil, Term.eval, Bool.and_eq_true,
      and_true]
    constructor
    · apply (implies_eval
        (.equal (selected.weaken .int) (.bound .here)) predicate
        assignment (locals.cons candidate)).mpr
      simpa [Term.eval, Term.weaken_eval, Locals.cons] using selectedCase
    · apply (implies_eval
        (.or (.equal (selected.weaken .int) (.integer (-1)))
          (lt (.bound .here) (selected.weaken .int)))
        (.not predicate) assignment (locals.cons candidate)).mpr
      simpa [Term.eval, Term.weaken_eval, Locals.cons, lt] using earlierCase

theorem first_match_term_eval {context : List Ty}
    (assignment : Assignment) (locals : Locals context)
    (limit selected : Term context .int) (predicate : Term (.int :: context) .bool) :
    (firstMatchTerm limit selected predicate).eval assignment locals = true <->
      (selected.eval assignment locals = -1 \/
        0 <= selected.eval assignment locals /\
          selected.eval assignment locals < limit.eval assignment locals) /\
      forall candidate : Int,
        0 <= candidate -> candidate < limit.eval assignment locals ->
          (selected.eval assignment locals = candidate ->
            predicate.eval assignment (locals.cons candidate) = true) /\
          ((selected.eval assignment locals = -1 \/
              candidate < selected.eval assignment locals) ->
            predicate.eval assignment (locals.cons candidate) = false) := by
  simp only [firstMatchTerm, all, List.foldr_cons, List.foldr_nil, Term.eval,
    Bool.and_eq_true, Bool.or_eq_true, decide_eq_true_eq, and_true, lt,
    Bool.not_eq_true', decide_eq_false_iff_not, not_le]
  apply and_congr_right'
  constructor
  · intro candidates candidate
    exact (first_match_candidate_eval assignment locals limit selected predicate candidate).mp
      (candidates candidate)
  · intro candidates candidate
    exact (first_match_candidate_eval assignment locals limit selected predicate candidate).mpr
      (candidates candidate)

theorem first_match_term_correct {context : List Ty} {N T : Type}
    (assignment : Assignment) (locals : Locals context)
    (limit selected : Term context .int) (predicate : Term (.int :: context) .bool)
    (log : NativeArrayCheckQuorum.Log N T) (test : Nat -> Entry N T -> Bool)
    (selectedIndex : Option Nat)
    (sameLimit : limit.eval assignment locals = (log.length : Int))
    (sameSelected : selected.eval assignment locals = firstMatchValue selectedIndex)
    (samePredicate : forall index, index < log.length ->
      predicate.eval assignment (locals.cons (index : Int)) = test index (log.entries index)) :
    (firstMatchTerm limit selected predicate).eval assignment locals = true <->
      NativeArrayFirstMatch.FirstMatch log test selectedIndex := by
  rw [first_match_term_eval]
  cases selectedIndex with
  | none =>
    simp only [firstMatchValue] at sameSelected
    constructor
    · rintro ⟨_, candidates⟩ index live
      have consequences := candidates (index : Int) (by omega)
        (by rw [sameLimit]; exact Int.ofNat_lt.mpr live)
      have missed := consequences.2 (Or.inl sameSelected)
      rw [samePredicate index live] at missed
      exact missed
    · intro absent
      refine ⟨Or.inl sameSelected, fun candidate nonnegative within => ?_⟩
      have natural : (candidate.toNat : Int) = candidate := Int.toNat_of_nonneg nonnegative
      have live : candidate.toNat < log.length := by
        rw [sameLimit] at within
        exact Int.ofNat_lt.mp (natural.trans_lt within)
      constructor
      · intro impossible
        have candidateNegative : candidate = -1 := impossible.symm.trans sameSelected
        rw [candidateNegative] at nonnegative
        omega
      · intro _
        rw [<- natural, samePredicate candidate.toNat live]
        exact absent candidate.toNat live
  | some index =>
    simp only [firstMatchValue] at sameSelected
    constructor
    · rintro ⟨bounds, candidates⟩
      have live : index < log.length := by
        rcases bounds with impossible | ⟨_, within⟩
        · have indexNegative : (index : Int) = -1 := sameSelected.symm.trans impossible
          have indexNonnegative : (0 : Int) <= index := Int.natCast_nonneg index
          omega
        · rw [sameSelected, sameLimit] at within
          exact Int.ofNat_lt.mp within
      have selectedCase := candidates (index : Int) (by omega)
        (by rw [sameLimit]; exact Int.ofNat_lt.mpr live)
      have hit := selectedCase.1 sameSelected
      rw [samePredicate index live] at hit
      refine ⟨live, hit, ?_⟩
      intro earlier before
      have earlierLive : earlier < log.length := Nat.lt_trans before live
      have earlierCase := candidates (earlier : Int) (by omega)
        (by rw [sameLimit]; exact Int.ofNat_lt.mpr earlierLive)
      have missed := earlierCase.2 (Or.inr (by
        rw [sameSelected]
        exact Int.ofNat_lt.mpr before))
      rw [samePredicate earlier earlierLive] at missed
      exact missed
    · rintro ⟨live, hit, earlier⟩
      refine ⟨Or.inr ⟨by rw [sameSelected]; exact Int.natCast_nonneg index,
          by rw [sameSelected, sameLimit]; exact Int.ofNat_lt.mpr live⟩,
        fun candidate nonnegative within => ?_⟩
      have natural : (candidate.toNat : Int) = candidate := Int.toNat_of_nonneg nonnegative
      have candidateLive : candidate.toNat < log.length := by
        rw [sameLimit] at within
        exact Int.ofNat_lt.mp (natural.trans_lt within)
      constructor
      · intro same
        have sameIndex : candidate.toNat = index := by
          have cast : (candidate.toNat : Int) = (index : Int) := by
            rw [natural, <- same, sameSelected]
          exact Int.ofNat_inj.mp cast
        rw [<- natural, samePredicate candidate.toNat candidateLive, sameIndex]
        exact hit
      · intro before
        rcases before with impossible | before
        · have indexNegative : (index : Int) = -1 := sameSelected.symm.trans impossible
          have indexNonnegative : (0 : Int) <= index := Int.natCast_nonneg index
          omega
        · have earlierIndex : candidate.toNat < index := by
            rw [sameSelected] at before
            exact Int.ofNat_lt.mp (natural.trans_lt before)
          rw [<- natural, samePredicate candidate.toNat candidateLive]
          exact earlier candidate.toNat earlierIndex

theorem first_match_term_rejects_below_sentinel {context : List Ty}
    (assignment : Assignment) (locals : Locals context)
    (limit selected : Term context .int) (predicate : Term (.int :: context) .bool)
    (below : selected.eval assignment locals < -1) :
    (firstMatchTerm limit selected predicate).eval assignment locals = false := by
  apply Bool.eq_false_iff.mpr
  intro accepted
  have bounds := (first_match_term_eval assignment locals limit selected predicate).mp accepted |>.1
  rcases bounds with sentinel | ⟨nonnegative, _⟩
  · rw [sentinel] at below
    exact (Int.lt_irrefl (-1)) below
  · have negative : selected.eval assignment locals < 0 :=
      lt_trans below (by norm_num)
    exact (not_lt_of_ge nonnegative) negative

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
