-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.SymbolicSharing

set_option autoImplicit false

namespace Symbolic.Expr

private structure Evaluated (assignment : Assignment) {s : Ty} (original : Expr s) where
  value : s.Value
  correct : value = original.eval assignment

private abbrev EvaluationEntry (assignment : Assignment) :=
  (s : Ty) × (original : Expr s) × Evaluated assignment original

private abbrev EvaluationCache (assignment : Assignment) :=
  Std.HashMap UInt64 (List (EvaluationEntry assignment))

private def findEvaluated (assignment : Assignment) {s : Ty} (original : Expr s) :
    List (EvaluationEntry assignment) → Option (Evaluated assignment original)
  | [] => none
  | ⟨t, prior, result⟩ :: rest =>
    match withPtrEqDecEq t s (fun _ => inferInstance) with
    | .isTrue sameType =>
      let candidate : Expr s := sameType ▸ prior
      let cached : Evaluated assignment candidate := by subst s; exact result
      match candidate.sharedDecEq original with
      | .isTrue same => some (same ▸ cached)
      | .isFalse _ => findEvaluated assignment original rest
    | .isFalse _ => findEvaluated assignment original rest

private def evaluateCached (assignment : Assignment) :
    {s : Ty} → (original : Expr s) →
      StateM (EvaluationCache assignment) (Evaluated assignment original)
  | _, original => do
    let key := original.memoKey
    if let some result := findEvaluated assignment original ((← get)[key]?.getD []) then
      return result
    let result : Evaluated assignment original ← (match original with
      | .nat value => pure ⟨value, rfl⟩
      | .bool value => pure ⟨value, rfl⟩
      | .unit => pure ⟨(), rfl⟩
      | .unknown index => pure ⟨assignment index, rfl⟩
      | .nil => pure ⟨[], rfl⟩
      | .named _ _ original => do
        let value ← evaluateCached assignment original
        pure ⟨value.value, value.correct⟩
      | .fst (.pair left _) => do
        let value ← evaluateCached assignment left
        pure ⟨value.value, value.correct⟩
      | .snd (.pair _ right) => do
        let value ← evaluateCached assignment right
        pure ⟨value.value, value.correct⟩
      | .isLeft (.inl _) => pure ⟨true, rfl⟩
      | .isLeft (.inr _) => pure ⟨false, rfl⟩
      | .leftD (.inl left) _ => do
        let value ← evaluateCached assignment left
        pure ⟨value.value, value.correct⟩
      | .leftD (.inr _) fallback => do
        let value ← evaluateCached assignment fallback
        pure ⟨value.value, value.correct⟩
      | .rightD (.inr right) _ => do
        let value ← evaluateCached assignment right
        pure ⟨value.value, value.correct⟩
      | .rightD (.inl _) fallback => do
        let value ← evaluateCached assignment fallback
        pure ⟨value.value, value.correct⟩
      | .add left right => do
        let a ← evaluateCached assignment left
        let b ← evaluateCached assignment right
        pure ⟨a.value + b.value, by simp only [eval, a.correct, b.correct]⟩
      | .sub left right => do
        let a ← evaluateCached assignment left
        let b ← evaluateCached assignment right
        pure ⟨a.value - b.value, by simp only [eval, a.correct, b.correct]⟩
      | .lt left right => do
        let a ← evaluateCached assignment left
        let b ← evaluateCached assignment right
        pure ⟨decide (a.value < b.value), by simp only [eval, a.correct, b.correct]⟩
      | .eq left right => do
        let a ← evaluateCached assignment left
        let b ← evaluateCached assignment right
        pure ⟨decide (a.value = b.value), by simp only [eval, a.correct, b.correct]⟩
      | .not original => do
        let value ← evaluateCached assignment original
        pure ⟨!value.value, by simp only [eval, value.correct]⟩
      | .and left right => do
        let a ← evaluateCached assignment left
        match known : a.value with
        | false =>
          pure ⟨false, by simp [eval, ← a.correct, known]⟩
        | true =>
          let b ← evaluateCached assignment right
          pure ⟨b.value, by simpa [eval, ← a.correct, known] using b.correct⟩
      | .ite condition left right => do
        let c ← evaluateCached assignment condition
        match known : c.value with
        | true =>
          let a ← evaluateCached assignment left
          pure ⟨a.value, by simpa [eval, ← c.correct, known] using a.correct⟩
        | false =>
          let b ← evaluateCached assignment right
          pure ⟨b.value, by simpa [eval, ← c.correct, known] using b.correct⟩
      | .pair left right => do
        let a ← evaluateCached assignment left
        let b ← evaluateCached assignment right
        pure ⟨(a.value, b.value), by simp only [eval, a.correct, b.correct]⟩
      | .fst original => do
        let value ← evaluateCached assignment original
        pure ⟨value.value.1, by simp only [eval, value.correct]⟩
      | .snd original => do
        let value ← evaluateCached assignment original
        pure ⟨value.value.2, by simp only [eval, value.correct]⟩
      | .inl original => do
        let value ← evaluateCached assignment original
        pure ⟨.inl value.value, by simp only [eval, value.correct]⟩
      | .inr original => do
        let value ← evaluateCached assignment original
        pure ⟨.inr value.value, by simp only [eval, value.correct]⟩
      | .isLeft original => do
        let value ← evaluateCached assignment original
        pure ⟨(match value.value with | .inl _ => true | .inr _ => false), by
          simp only [eval, value.correct]
          cases original.eval assignment <;> rfl⟩
      | .leftD original fallback => do
        let value ← evaluateCached assignment original
        match known : value.value with
        | .inl left =>
          pure ⟨left, by simp only [eval, ← value.correct, known]⟩
        | .inr _ =>
          let other ← evaluateCached assignment fallback
          pure ⟨other.value, by simpa only [eval, ← value.correct, known] using other.correct⟩
      | .rightD original fallback => do
        let value ← evaluateCached assignment original
        match known : value.value with
        | .inr right =>
          pure ⟨right, by simp only [eval, ← value.correct, known]⟩
        | .inl _ =>
          let other ← evaluateCached assignment fallback
          pure ⟨other.value, by simpa only [eval, ← value.correct, known] using other.correct⟩
      | .cons head tail => do
        let a ← evaluateCached assignment head
        let b ← evaluateCached assignment tail
        pure ⟨a.value :: b.value, by simp only [eval, a.correct, b.correct]⟩
      | .append left right => do
        let a ← evaluateCached assignment left
        let b ← evaluateCached assignment right
        pure ⟨a.value ++ b.value, by simp only [eval, a.correct, b.correct]⟩
      | .length original => do
        let value ← evaluateCached assignment original
        pure ⟨value.value.length, by simp only [eval, value.correct]⟩
      | .take count original => do
        let n ← evaluateCached assignment count
        let value ← evaluateCached assignment original
        pure ⟨value.value.take n.value, by simp only [eval, n.correct, value.correct]⟩
      | .drop count original => do
        let n ← evaluateCached assignment count
        let value ← evaluateCached assignment original
        pure ⟨value.value.drop n.value, by simp only [eval, n.correct, value.correct]⟩
      | .get? original index => do
        let value ← evaluateCached assignment original
        let n ← evaluateCached assignment index
        pure ⟨(match value.value[n.value]? with | none => .inl () | some item => .inr item), by
          simp only [eval, n.correct, value.correct]
          cases (original.eval assignment)[index.eval assignment]? <;> rfl⟩
      | .set original index replacement => do
        let value ← evaluateCached assignment original
        let n ← evaluateCached assignment index
        let next ← evaluateCached assignment replacement
        pure ⟨value.value.set n.value next.value, by
          simp only [eval, n.correct, value.correct, next.correct]⟩
      | .contains original member => do
        let value ← evaluateCached assignment original
        let candidate ← evaluateCached assignment member
        pure ⟨decide (candidate.value ∈ value.value), by
          simp only [eval, value.correct, candidate.correct]⟩)
    modify fun cache => cache.insert key (⟨_, original, result⟩ :: cache[key]?.getD [])
    return result
termination_by _ original => sizeOf original

structure EvaluationState (assignment : Assignment) where
  entries : EvaluationCache assignment := {}

def EvaluationState.size {assignment : Assignment} (state : EvaluationState assignment) : Nat :=
  state.entries.fold (fun count _ bucket => count + bucket.length) 0

def evalMemoM (assignment : Assignment) {s : Ty} (original : Expr s) :
    StateM (EvaluationState assignment) s.Value := do
  let state ← get
  let (result, entries) := (evaluateCached assignment original).run state.entries
  MonadStateOf.set ({ entries } : EvaluationState assignment)
  return result.value

theorem evalMemoM_correct (assignment : Assignment) {s : Ty}
    (original : Expr s) (state : EvaluationState assignment) :
    ((evalMemoM assignment original).run state).1 = original.eval assignment :=
  ((evaluateCached assignment original).run state.entries).1.correct

/-- Evaluate shared expressions with a cache scoped to this assignment. -/
def evalMemo (assignment : Assignment) {s : Ty} (original : Expr s) : s.Value :=
  ((evalMemoM assignment original).run {}).1

theorem evalMemo_correct (assignment : Assignment) {s : Ty} (original : Expr s) :
    original.evalMemo assignment = original.eval assignment :=
  evalMemoM_correct assignment original {}

end Symbolic.Expr
