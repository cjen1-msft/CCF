-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Model
import MachineGenerated.ReceiveTraceValues

set_option autoImplicit false

namespace CCFRaft.ReceiveTraceReplication

open TraceSmt ReceiveTraceValues

def lookupTerm {holes : Nat} (log : List (Entry Node (NatTerm holes)))
    (index : Scalar holes) (length : NatTerm holes) (positions : Nat -> NatTerm holes)
    (terms : Nat -> Nat -> NatTerm holes) : Scalar holes :=
  -- A truncated index still has a tracked zero owned by the truncating action.
  let selected := (Expr.and (.equal index.expression (positions index.actual))
    (.not (.lessThan length (positions index.actual)))).ite
      (terms index.actual (termAt log index.actual)) (.literal 0)
  { actual := termAt log index.actual
    expression := (List.range (log.length + 1)).foldl (fun previous candidate =>
      (Expr.and (.equal index.expression (positions candidate))
        (.not (.lessThan length (positions candidate)))).ite
          (terms candidate (termAt log candidate)) previous) selected }

theorem lookupTerm_correct {holes : Nat} (assignment : Fin holes -> Nat)
    (log : List (Entry Node (NatTerm holes))) (index : Scalar holes)
    (length : NatTerm holes) (positions : Nat -> NatTerm holes) (terms : Nat -> Nat -> NatTerm holes)
    (indexCorrect : index.Correct assignment) (lengthCorrect : length.eval assignment = log.length)
    (positionsCorrect : ∀ index, (positions index).eval assignment = index)
    (termsCorrect : ∀ index term, (terms index term).eval assignment = term) :
    (lookupTerm log index length positions terms).Correct assignment := by
  have indexValue := indexCorrect
  unfold Scalar.Correct at indexValue
  have outside (bounded : ¬ index.actual ≤ log.length) : termAt log index.actual = 0 := by
    have positive : index.actual ≠ 0 := by omega
    have missing : log[index.actual - 1]? = none := by
      apply List.getElem?_eq_none
      omega
    simp [termAt, entryAt?, positive, missing]
  have selectedCorrect :
      ((Expr.and (.equal index.expression (positions index.actual))
        (.not (.lessThan length (positions index.actual)))).ite
          (terms index.actual (termAt log index.actual)) (.literal 0)).eval assignment =
        termAt log index.actual := by
    by_cases bounded : index.actual ≤ log.length <;>
      simp [Expr.ite_eval, Expr.Holds, indexValue, positionsCorrect, lengthCorrect,
        termsCorrect, NatTerm.eval, bounded, outside]
  have evaluated (indices : List Nat) (previous : NatTerm holes)
      (previousCorrect : previous.eval assignment = termAt log index.actual) :
      (indices.foldl (fun previous candidate =>
        (Expr.and (.equal index.expression (positions candidate))
          (.not (.lessThan length (positions candidate)))).ite
            (terms candidate (termAt log candidate)) previous) previous).eval assignment =
        termAt log index.actual := by
    induction indices generalizing previous with
    | nil => exact previousCorrect
    | cons candidate rest ih =>
        apply ih
        by_cases hit : index.actual = candidate <;>
          simp [Expr.ite_eval, Expr.Holds, indexValue, lengthCorrect, positionsCorrect,
            termsCorrect, previousCorrect, hit]
  exact evaluated _ _ selectedCorrect

def lastMatching {holes : Nat} (count : Nat) (condition : Nat -> Condition holes)
    (positions : Nat -> Scalar holes) : Scalar holes :=
  (List.range count).foldl (fun previous index =>
    choose (condition index) (positions index) previous) (literal 0)

theorem lastMatching_correct {holes : Nat} (assignment : Fin holes -> Nat)
    (count : Nat) (condition : Nat -> Condition holes) (positions : Nat -> Scalar holes)
    (conditionsCorrect : ∀ index, index < count → (condition index).Correct assignment)
    (positionsCorrect : ∀ index, (positions index).Correct assignment) :
    (lastMatching count condition positions).Correct assignment := by
  have fold (indices : List Nat) (inside : ∀ index ∈ indices, index < count)
      (previous : Scalar holes) (correct : previous.Correct assignment) :
      (indices.foldl (fun previous index => choose (condition index) (positions index) previous) previous).Correct assignment := by
    induction indices generalizing previous with
    | nil => exact correct
    | cons index rest ih =>
        apply ih (fun value member => inside value (List.mem_cons_of_mem _ member))
        exact choose_correct assignment _ _ _ (conditionsCorrect index (inside index (by simp))) (positionsCorrect index) correct
  exact fold _ (fun index member => List.mem_range.mp member) _ rfl

theorem lastMatching_actual {holes : Nat} (count : Nat)
    (condition : Nat -> Condition holes) (positions : Nat -> Scalar holes)
    (positionsActual : ∀ index, (positions index).actual = index) :
    (lastMatching count condition positions).actual =
      (List.range count).foldl (fun previous index =>
        if (condition index).actual then max previous index else previous) 0 := by
  have bounded (count : Nat) :
      (List.range count).foldl (fun previous index =>
        if (condition index).actual then max previous index else previous) 0 ≤ count := by
    apply (ControlTraceConfigurations.maximum_le _ (fun index => (condition index).actual = true) id 0 count).2
    constructor
    · omega
    · intro index member _
      change index ≤ count
      exact Nat.le_of_lt (List.mem_range.mp member)
  induction count with
  | zero => rfl
  | succ count ih =>
      have step : lastMatching (count + 1) condition positions =
          choose (condition count) (positions count) (lastMatching count condition positions) := by
        simp only [lastMatching, List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil]
      rw [step]
      change (if (condition count).actual then (positions count).actual
        else (lastMatching count condition positions).actual) = _
      simp only [positionsActual, ih, List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil]
      split_ifs
      · exact (max_eq_right (bounded count)).symm
      · rfl

theorem maximum_bounded_range (count limit : Nat) (condition : Nat -> Prop) [DecidablePred condition] :
    (List.range (count + 1)).foldl
        (fun previous index => if index ≤ limit ∧ condition index then max previous index else previous) 0 =
      (List.range (min limit count + 1)).foldl
        (fun previous index => if condition index then max previous index else previous) 0 := by
  induction count with
  | zero => simp
  | succ count ih =>
      conv_lhs =>
        rw [@List.range_succ (count + 1), List.foldl_append]
        simp only [List.foldl_cons, List.foldl_nil]
      simp only [ih]
      by_cases included : count + 1 ≤ limit
      · have old : min limit count = count := Nat.min_eq_right (by omega)
        have current : min limit (count + 1) = count + 1 := Nat.min_eq_right included
        simp [included, old, current, List.range_succ, List.foldl_append]
      · have old : min limit count = limit := Nat.min_eq_left (by omega)
        have current : min limit (count + 1) = limit := Nat.min_eq_left (by omega)
        simp [included, old, current]

def highestPossible {holes : Nat} (log : List (Entry Node (NatTerm holes)))
    (limit term : Scalar holes) (length : NatTerm holes) (positions : Nat -> NatTerm holes)
    (terms : Nat -> Nat -> NatTerm holes) : Scalar holes :=
  lastMatching (log.length + 1)
    (fun index =>
      { actual := decide (0 < index ∧ index ≤ limit.actual ∧ termAt log index ≤ term.actual)
        expression := .and (.lessThan (.literal 0) (positions index))
          (.and (.not (.lessThan limit.expression (positions index)))
            (.and (.not (.lessThan length (positions index)))
              (.not (.lessThan term.expression (terms index (termAt log index)))))) })
    (fun index => ⟨index, positions index⟩)

theorem highestPossible_correct {holes : Nat} (assignment : Fin holes -> Nat)
    (log : List (Entry Node (NatTerm holes))) (limit term : Scalar holes)
    (length : NatTerm holes) (positions : Nat -> NatTerm holes) (terms : Nat -> Nat -> NatTerm holes)
    (limitCorrect : limit.Correct assignment) (termCorrect : term.Correct assignment)
    (lengthCorrect : length.eval assignment = log.length)
    (positionsCorrect : ∀ index, (positions index).eval assignment = index)
    (termsCorrect : ∀ index term, (terms index term).eval assignment = term) :
    (highestPossible log limit term length positions terms).Correct assignment := by
  apply lastMatching_correct
  · intro index bounded
    have within : index ≤ log.length := by omega
    simp_all [Scalar.Correct, Condition.Correct, Expr.Holds, NatTerm.eval]
  · exact positionsCorrect

theorem highestPossible_actual {holes : Nat}
    (log : List (Entry Node (NatTerm holes))) (limit term : Scalar holes)
    (length : NatTerm holes) (positions : Nat -> NatTerm holes) (terms : Nat -> Nat -> NatTerm holes) :
    (highestPossible log limit term length positions terms).actual =
      findHighestPossibleMatch log limit.actual term.actual := by
  rw [highestPossible, lastMatching_actual _ _ _ (fun _ => rfl)]
  simpa [findHighestPossibleMatch, and_assoc, and_left_comm, and_comm] using
    maximum_bounded_range log.length limit.actual (fun index => 0 < index ∧ termAt log index ≤ term.actual)

def signedFrontier {holes : Nat} (log : List (Entry Node (NatTerm holes))) (limit : Scalar holes)
    (length : NatTerm holes) (positions : Nat -> NatTerm holes) : Scalar holes :=
  lastMatching (log.length + 1)
    (fun index => ⟨decide (index ≤ limit.actual ∧ isSignatureAt log index = true),
      .and (.boolean (isSignatureAt log index))
        (.and (.not (.lessThan limit.expression (positions index)))
          (.not (.lessThan length (positions index))))⟩)
    (fun index => ⟨index, positions index⟩)

theorem signedFrontier_correct {holes : Nat} (assignment : Fin holes -> Nat)
    (log : List (Entry Node (NatTerm holes))) (limit : Scalar holes)
    (length : NatTerm holes) (positions : Nat -> NatTerm holes)
    (limitCorrect : limit.Correct assignment) (lengthCorrect : length.eval assignment = log.length)
    (positionsCorrect : ∀ index, (positions index).eval assignment = index) :
    (signedFrontier log limit length positions).Correct assignment := by
  apply lastMatching_correct
  · intro index bounded
    have within : index ≤ log.length := by omega
    simp_all [Condition.Correct, Scalar.Correct, Expr.Holds, NatTerm.eval, and_comm]
  · exact positionsCorrect

theorem signedFrontier_actual {holes : Nat} (log : List (Entry Node (NatTerm holes))) (limit : Scalar holes)
    (length : NatTerm holes) (positions : Nat -> NatTerm holes) :
    (signedFrontier log limit length positions).actual = maxCommittableIndexUpTo log limit.actual := by
  rw [signedFrontier, lastMatching_actual _ _ _ (fun _ => rfl)]
  simp only [decide_eq_true_eq]
  rw [maximum_bounded_range]
  simp only [maxCommittableIndexUpTo, maxCommittableIndex, List.length_take]
  have signature (index : Nat) (within : index ≤ limit.actual) :
      isSignatureAt (log.take limit.actual) index = isSignatureAt log index := by
    by_cases zero : index = 0
    · simp [isSignatureAt, entryAt?, zero]
    · have less : index - 1 < limit.actual := by omega
      simp [isSignatureAt, entryAt?, zero, List.getElem?_take, less]
  have equal (indices : List Nat) (bounded : ∀ index ∈ indices, index ≤ limit.actual) (initial : Nat) :
      indices.foldl (fun previous index => if isSignatureAt log index then max previous index else previous) initial =
        indices.foldl (fun previous index =>
          if isSignatureAt (log.take limit.actual) index then max previous index else previous) initial := by
    induction indices generalizing initial with
    | nil => rfl
    | cons index rest ih =>
        simp only [List.foldl_cons, signature index (bounded index (by simp))]
        exact ih (fun index member => bounded index (by simp [member])) _
  apply equal
  intro index member
  have := List.mem_range.mp member
  omega

end CCFRaft.ReceiveTraceReplication
