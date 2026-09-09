-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.Smt

set_option autoImplicit false

/-!
# Executable guarded choices

Callers remain responsible for assigning distinct `(group, slot)` pairs to
branch-specific named values, or for inlining those values, so that
`Formula.prepare` does not see conflicting bindings.
-/

namespace TraceSmt

universe u v

/-- Boolean implication expressed using the existing tiny expression language. -/
def Expr.implies {holes : Nat}
    (left right : Expr holes) : Expr holes :=
  .not (.and left (.not right))

@[simp]
theorem Expr.implies_holds {holes : Nat}
    (assignment : Fin holes -> Nat)
    (left right : Expr holes) :
    (left.implies right).Holds assignment <->
      (left.Holds assignment -> right.Holds assignment) := by
  simp [Expr.implies, Expr.Holds]

/-- Detect constant guards without evaluating unknowns or named definitions. -/
def Expr.constant? {holes : Nat} : Expr holes -> Option Bool
  | .boolean value => some value
  | .equal left right =>
      if left = right then some true else
        match left, right with
        | .literal a, .literal b => some (decide (a = b))
        | _, _ => none
  | .lessThan (.literal left) (.literal right) => some (decide (left < right))
  | .lessThan _ _ => none
  | .not value => value.constant?.map (! ·)
  | .and left right =>
      match left.constant?, right.constant? with
      | some false, _ | _, some false => some false
      | some true, some true => some true
      | _, _ => none

theorem Expr.constant?_correct {holes : Nat}
    (assignment : Fin holes -> Nat)
    (expression : Expr holes)
    (value : Bool)
    (known : expression.constant? = some value) :
    expression.Holds assignment <-> value = true := by
  induction expression generalizing value with
  | boolean result => simpa [constant?, Expr.Holds] using known
  | equal left right =>
      by_cases same : left = right
      · subst right
        simpa [constant?, Expr.Holds] using known
      · cases left <;> cases right <;>
          simp_all [constant?, Expr.Holds, NatTerm.eval]
  | lessThan left right =>
      cases value <;> cases left <;> cases right <;>
        simp_all [constant?, Expr.Holds, NatTerm.eval]
  | not inner ih =>
      cases result : inner.constant? with
      | none => simp [constant?, result] at known
      | some flag =>
          have correct := ih flag result
          cases flag <;> simp_all [constant?, Expr.Holds]
  | and left right leftCorrect rightCorrect =>
      cases leftValue : left.constant? with
      | none =>
          cases rightValue : right.constant? with
          | none => simp [constant?, leftValue, rightValue] at known
          | some flag => cases flag <;> simp_all [constant?, Expr.Holds]
      | some flag =>
          cases flag <;>
            cases rightValue : right.constant? with
            | none => simp_all [constant?, Expr.Holds]
            | some flag => cases flag <;> simp_all [constant?, Expr.Holds]

/-- A finite executable choice tree guarded by symbolic expressions. -/
inductive Guarded (holes : Nat) (α : Type u) where
  | pure (value : α)
  | branch
      (condition : Expr holes)
      (thenTree elseTree : Guarded holes α)

namespace Guarded

/-- Eliminate branches whose condition has a known Boolean value. -/
def branchSmart {holes : Nat} {α : Type u}
    (condition : Expr holes)
    (thenTree elseTree : Guarded holes α) : Guarded holes α :=
  match condition.constant? with
  | some true => thenTree
  | some false => elseTree
  | _ => .branch condition thenTree elseTree

/-- Evaluate one guarded tree under a concrete unknown assignment. -/
def eval {holes : Nat} {α : Type u}
    (assignment : Fin holes -> Nat) : Guarded holes α -> α
  | .pure value => value
  | .branch condition thenTree elseTree =>
      if condition.Holds assignment then
        thenTree.eval assignment
      else
        elseTree.eval assignment

@[simp]
theorem eval_branchSmart {holes : Nat} {α : Type u}
    (assignment : Fin holes -> Nat)
    (condition : Expr holes)
    (thenTree elseTree : Guarded holes α) :
    (branchSmart condition thenTree elseTree).eval assignment =
      if condition.Holds assignment then
        thenTree.eval assignment
      else
        elseTree.eval assignment := by
  cases known : condition.constant? with
  | none => simp [branchSmart, known, eval]
  | some value =>
      have correct := Expr.constant?_correct assignment condition value known
      cases value <;> simp_all [branchSmart]

/-- Apply a pure function to every leaf. -/
def map {holes : Nat} {α : Type u} {β : Type v}
    (function : α -> β) : Guarded holes α -> Guarded holes β
  | .pure value => .pure (function value)
  | .branch condition thenTree elseTree =>
      .branch condition (thenTree.map function) (elseTree.map function)

/-- Replace every leaf with another guarded choice tree. -/
def bind {holes : Nat} {α : Type u} {β : Type v}
    (tree : Guarded holes α)
    (function : α -> Guarded holes β) : Guarded holes β :=
  match tree with
  | .pure value => function value
  | .branch condition thenTree elseTree =>
      .branch condition
        (thenTree.bind function)
        (elseTree.bind function)

/-- Require the predicate at exactly the leaf selected by each branch path. -/
def test {holes : Nat} {α : Type u}
    (tree : Guarded holes α)
    (predicate : α -> Expr holes) : Expr holes :=
  match tree with
  | .pure value => predicate value
  | .branch condition thenTree elseTree =>
      .and
        (condition.implies (thenTree.test predicate))
        ((Expr.not condition).implies (elseTree.test predicate))

@[simp]
theorem eval_map {holes : Nat} {α : Type u} {β : Type v}
    (assignment : Fin holes -> Nat)
    (function : α -> β)
    (tree : Guarded holes α) :
    (tree.map function).eval assignment =
      function (tree.eval assignment) := by
  induction tree with
  | pure => rfl
  | branch condition thenTree elseTree thenCorrect elseCorrect =>
      simp only [map, eval]
      split <;> simp_all

@[simp]
theorem eval_bind {holes : Nat} {α : Type u} {β : Type v}
    (assignment : Fin holes -> Nat)
    (tree : Guarded holes α)
    (function : α -> Guarded holes β) :
    (tree.bind function).eval assignment =
      (function (tree.eval assignment)).eval assignment := by
  induction tree with
  | pure => rfl
  | branch condition thenTree elseTree thenCorrect elseCorrect =>
      simp only [bind, eval]
      split <;> simp_all

@[simp]
theorem test_holds {holes : Nat} {α : Type u}
    (assignment : Fin holes -> Nat)
    (tree : Guarded holes α)
    (predicate : α -> Expr holes) :
    (tree.test predicate).Holds assignment <->
      (predicate (tree.eval assignment)).Holds assignment := by
  induction tree with
  | pure => rfl
  | branch condition thenTree elseTree thenCorrect elseCorrect =>
      simp only [test, Expr.Holds, Expr.implies_holds, eval]
      by_cases holds : condition.Holds assignment
      · simp [holds, thenCorrect]
      · simp [holds, elseCorrect]

/--
Symbolically test whether a value equals any queue element. The supplied
equality expression determines the concrete equality interpreted by proofs.
-/
def contains {holes : Nat} {α : Type u}
    (equal : α -> α -> Expr holes)
    (value : α) : List α -> Guarded holes Bool
  | [] => .pure false
  | head :: tail =>
      branchSmart
        (equal value head) (.pure true) (contains equal value tail)

/-- Keep an existing queue element, or append a new value exactly once. -/
def enqueueNoDup {holes : Nat} {α : Type u}
    (equal : α -> α -> Expr holes)
    (value : α)
    (queue : List α) : Guarded holes (List α) :=
  (contains equal value queue).map fun found =>
    if found then queue else queue ++ [value]

@[simp]
theorem eval_contains {holes : Nat} {α : Type u} {β : Type v}
    [DecidableEq β]
    (assignment : Fin holes -> Nat)
    (decode : α -> β)
    (equal : α -> α -> Expr holes)
    (correct : forall left right,
      (equal left right).Holds assignment <-> decode left = decode right)
    (value : α)
    (queue : List α) :
    (contains equal value queue).eval assignment =
      decide (decode value ∈ queue.map decode) := by
  induction queue with
  | nil => rfl
  | cons head tail ih =>
      apply Bool.eq_iff_iff.mpr
      rw [decide_eq_true_iff]
      simp [contains, eval_branchSmart, eval, ih, correct]

/--
Evaluating guarded no-duplicate enqueue and decoding its leaves is exactly the
ordinary concrete list operation.
-/
theorem eval_enqueueNoDup_map {holes : Nat} {α : Type u} {β : Type v}
    [DecidableEq β]
    (assignment : Fin holes -> Nat)
    (decode : α -> β)
    (equal : α -> α -> Expr holes)
    (correct : forall left right,
      (equal left right).Holds assignment <-> decode left = decode right)
    (value : α)
    (queue : List α) :
    ((enqueueNoDup equal value queue).eval assignment).map decode =
      if decode value ∈ queue.map decode then
        queue.map decode
      else
        queue.map decode ++ [decode value] := by
  rw [enqueueNoDup, eval_map,
    eval_contains assignment decode equal correct]
  by_cases present : decode value ∈ queue.map decode
  · simp [present]
  · simp [present]

end Guarded

end TraceSmt
