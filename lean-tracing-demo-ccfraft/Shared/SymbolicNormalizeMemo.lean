-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.SymbolicNormalize
import Shared.SymbolicSharing

set_option autoImplicit false

namespace Symbolic.Expr

private structure Equivalent {s : Ty} (original : Expr s) where
  value : Expr s
  correct : ∀ assignment, value.eval assignment = original.eval assignment

private abbrev Entry := (s : Ty) × (original : Expr s) × Equivalent original
private abbrev Cache := Std.HashMap UInt64 (List Entry)

private def findEquivalent {s : Ty} (original : Expr s) :
    List Entry → Option (Equivalent original)
  | [] => none
  | ⟨t, prior, result⟩ :: rest =>
      match withPtrEqDecEq t s (fun _ => inferInstance) with
      | .isTrue sameType =>
        let candidate : Expr s := sameType ▸ prior
        let cached : Equivalent candidate := by subst s; exact result
        match candidate.sharedDecEq original with
        | .isTrue same => some (same ▸ cached)
        | .isFalse _ => findEquivalent original rest
      | .isFalse _ => findEquivalent original rest

private def memoize {s : Ty} (original : Expr s)
    (compute : Unit → StateM Cache (Equivalent original)) :
    StateM Cache (Equivalent original) := do
  let key := original.memoKey
  if let some result := findEquivalent original ((← get)[key]?.getD []) then
    return result
  let result ← compute ()
  modify fun cache => cache.insert key (⟨_, original, result⟩ :: cache[key]?.getD [])
  return result

private def firstCached {a b : Ty} (original : Expr (.pair a b)) :
    StateM Cache (Equivalent original.fst) :=
  memoize original.fst fun _ => do
    match original with
    | .pair left _ => pure ⟨left, fun _ => rfl⟩
    | .ite condition left right =>
        let a ← firstCached left
        let b ← firstCached right
        pure ⟨choose condition a.value b.value, fun assignment => by
          simp only [choose_correct, a.correct, b.correct, eval]
          split <;> rfl⟩
    | value => pure ⟨value.fst, fun _ => rfl⟩
termination_by sizeOf original

private def secondCached {a b : Ty} (original : Expr (.pair a b)) :
    StateM Cache (Equivalent original.snd) :=
  memoize original.snd fun _ => do
    match original with
    | .pair _ right => pure ⟨right, fun _ => rfl⟩
    | .ite condition left right =>
        let a ← secondCached left
        let b ← secondCached right
        pure ⟨choose condition a.value b.value, fun assignment => by
          simp only [choose_correct, a.correct, b.correct, eval]
          split <;> rfl⟩
    | value => pure ⟨value.snd, fun _ => rfl⟩
termination_by sizeOf original

private def testLeftCached {a b : Ty} (original : Expr (.sum a b)) :
    StateM Cache (Equivalent original.isLeft) :=
  memoize original.isLeft fun _ => do
    match original with
    | .inl _ => pure ⟨.bool true, fun _ => rfl⟩
    | .inr _ => pure ⟨.bool false, fun _ => rfl⟩
    | .ite condition left right =>
        let a ← testLeftCached left
        let b ← testLeftCached right
        pure ⟨choose condition a.value b.value, fun assignment => by
          simp only [choose_correct, a.correct, b.correct, eval]
          split <;> rfl⟩
    | value => pure ⟨value.isLeft, fun _ => rfl⟩
termination_by sizeOf original

private def fromLeftCached {a b : Ty} (original : Expr (.sum a b)) (fallback : Expr a) :
    StateM Cache (Equivalent (original.leftD fallback)) :=
  memoize (original.leftD fallback) fun _ => do
    match original with
    | .inl value => pure ⟨value, fun _ => rfl⟩
    | .inr _ => pure ⟨fallback, fun _ => rfl⟩
    | .ite condition left right =>
        let a ← fromLeftCached left fallback
        let b ← fromLeftCached right fallback
        pure ⟨choose condition a.value b.value, fun assignment => by
          simp only [choose_correct, a.correct, b.correct, eval]
          split <;> rfl⟩
    | value => pure ⟨value.leftD fallback, fun _ => rfl⟩
termination_by sizeOf original

private def fromRightCached {a b : Ty} (original : Expr (.sum a b)) (fallback : Expr b) :
    StateM Cache (Equivalent (original.rightD fallback)) :=
  memoize (original.rightD fallback) fun _ => do
    match original with
    | .inl _ => pure ⟨fallback, fun _ => rfl⟩
    | .inr value => pure ⟨value, fun _ => rfl⟩
    | .ite condition left right =>
        let a ← fromRightCached left fallback
        let b ← fromRightCached right fallback
        pure ⟨choose condition a.value b.value, fun assignment => by
          simp only [choose_correct, a.correct, b.correct, eval]
          split <;> rfl⟩
    | value => pure ⟨value.rightD fallback, fun _ => rfl⟩
termination_by sizeOf original

private def sizeCached {a : Ty} (original : Expr (.seq a)) :
    StateM Cache (Equivalent original.length) :=
  memoize original.length fun _ => do
    match original with
    | .nil => pure ⟨.nat 0, fun _ => rfl⟩
    | .cons _ tail =>
        let rest ← sizeCached tail
        pure ⟨plus (.nat 1) rest.value, fun assignment => by
          simp [plus_correct, rest.correct, eval, Nat.add_comm]⟩
    | .append left right =>
        let a ← sizeCached left
        let b ← sizeCached right
        pure ⟨plus a.value b.value, fun assignment => by
          simp [plus_correct, a.correct, b.correct, eval]⟩
    | .take count values =>
        let length ← sizeCached values
        pure ⟨choose (count.le length.value) count length.value, fun assignment => by
          simp [choose_correct, eval_le, length.correct, eval, Nat.min_def]⟩
    | .drop count values =>
        let length ← sizeCached values
        pure ⟨minus length.value count, fun assignment => by
          simp [minus_correct, length.correct, eval]⟩
    | .ite condition left right =>
        let a ← sizeCached left
        let b ← sizeCached right
        pure ⟨choose condition a.value b.value, fun assignment => by
          simp only [choose_correct, a.correct, b.correct, eval]
          split <;> rfl⟩
    | value => pure ⟨value.length, fun _ => rfl⟩
termination_by sizeOf original

private def selectCached {a : Ty} (original : Expr (.seq a)) (index : Expr .nat) :
    StateM Cache (Equivalent (original.get? index)) :=
  memoize (original.get? index) fun _ => do
    match original with
    | .nil => pure ⟨.inl .unit, fun _ => rfl⟩
    | .cons head tail =>
        let rest ← selectCached tail (minus index (.nat 1))
        pure ⟨choose (.eq index (.nat 0)) (.inr head) rest.value, fun assignment => by
          simp only [choose_correct, rest.correct, eval, minus_correct]
          cases chosen : index.eval assignment <;> simp⟩
    | .take count values =>
        let selected ← selectCached values index
        pure ⟨choose (.lt index count) selected.value (.inl .unit), fun assignment => by
          simp only [choose_correct, selected.correct, eval]
          by_cases bounded : index.eval assignment < count.eval assignment <;> simp [bounded]⟩
    | .drop count values =>
        let selected ← selectCached values (plus count index)
        pure ⟨selected.value, fun assignment => by
          simp [selected.correct, plus_correct, eval, List.getElem?_drop]⟩
    | .ite condition left right =>
        let a ← selectCached left index
        let b ← selectCached right index
        pure ⟨choose condition a.value b.value, fun assignment => by
          simp only [choose_correct, a.correct, b.correct, eval]
          split <;> rfl⟩
    | value => pure ⟨value.get? index, fun _ => rfl⟩
termination_by sizeOf original

private def normalizeCached : {s : Ty} → (original : Expr s) →
    StateM Cache (Equivalent original)
  | _, original => memoize original fun _ => do
      match original with
        | .nat value => pure ⟨.nat value, fun _ => rfl⟩
        | .bool value => pure ⟨.bool value, fun _ => rfl⟩
        | .unit => pure ⟨.unit, fun _ => rfl⟩
        | .unknown index => pure ⟨.unknown index, fun _ => rfl⟩
        | .nil => pure ⟨.nil, fun _ => rfl⟩
        | .named group slot value => pure ⟨.named group slot value, fun _ => rfl⟩
        | .fst (.pair left _) => do
            let value ← normalizeCached left
            pure ⟨value.value, fun assignment => by simpa [eval] using value.correct assignment⟩
        | .snd (.pair _ right) => do
            let value ← normalizeCached right
            pure ⟨value.value, fun assignment => by simpa [eval] using value.correct assignment⟩
        | .isLeft (.inl _) => pure ⟨.bool true, fun _ => rfl⟩
        | .isLeft (.inr _) => pure ⟨.bool false, fun _ => rfl⟩
        | .leftD (.inl left) _ => do
            let value ← normalizeCached left
            pure ⟨value.value, fun assignment => by simpa [eval] using value.correct assignment⟩
        | .leftD (.inr _) fallback => do
            let value ← normalizeCached fallback
            pure ⟨value.value, fun assignment => by simpa [eval] using value.correct assignment⟩
        | .rightD (.inr right) _ => do
            let value ← normalizeCached right
            pure ⟨value.value, fun assignment => by simpa [eval] using value.correct assignment⟩
        | .rightD (.inl _) fallback => do
            let value ← normalizeCached fallback
            pure ⟨value.value, fun assignment => by simpa [eval] using value.correct assignment⟩
        | .add left right => do
            let a ← normalizeCached left
            let b ← normalizeCached right
            pure ⟨plus a.value b.value, fun assignment => by
              simp only [plus_correct, a.correct, b.correct, eval]⟩
        | .sub left right => do
            let a ← normalizeCached left
            let b ← normalizeCached right
            pure ⟨minus a.value b.value, fun assignment => by
              simp only [minus_correct, a.correct, b.correct, eval]⟩
        | .lt left right => do
            let a ← normalizeCached left
            let b ← normalizeCached right
            pure ⟨.lt a.value b.value, fun assignment => by
              simp only [eval, a.correct, b.correct]⟩
        | .eq left right => do
            let a ← normalizeCached left
            let b ← normalizeCached right
            pure ⟨equal a.value b.value, fun assignment => by
              simp only [equal_correct, a.correct, b.correct, eval]⟩
        | .not original => do
            let value ← normalizeCached original
            pure ⟨.not value.value, fun assignment => by simp only [eval, value.correct]⟩
        | .and left right => do
            let a ← normalizeCached left
            match known : a.value with
            | .bool false =>
                pure ⟨.bool false, fun assignment => by
                  have leftFalse : left.eval assignment = false := by
                    rw [← a.correct, known]; rfl
                  simp [eval, leftFalse]⟩
            | _ =>
                let b ← normalizeCached right
                pure ⟨both a.value b.value, fun assignment => by
                  simp only [both_correct, a.correct, b.correct, eval]⟩
        | .ite condition left right => do
            let c ← normalizeCached condition
            match known : c.value with
            | .bool true =>
                let a ← normalizeCached left
                pure ⟨a.value, fun assignment => by
                  have chosen : condition.eval assignment = true := by
                    rw [← c.correct, known]; rfl
                  simp [eval, chosen, a.correct]⟩
            | .bool false =>
                let b ← normalizeCached right
                pure ⟨b.value, fun assignment => by
                  have chosen : condition.eval assignment = false := by
                    rw [← c.correct, known]; rfl
                  simp [eval, chosen, b.correct]⟩
            | _ =>
                let a ← normalizeCached left
                let b ← normalizeCached right
                pure ⟨.ite c.value a.value b.value, fun assignment => by
                  simp only [eval, c.correct, a.correct, b.correct]⟩
        | .pair left right => do
            let a ← normalizeCached left
            let b ← normalizeCached right
            pure ⟨.pair a.value b.value, fun assignment => by
              simp only [eval, a.correct, b.correct]⟩
        | .fst original => do
            let value ← normalizeCached original
            let projected ← firstCached value.value
            pure ⟨projected.value, fun assignment => by
              simp only [projected.correct, eval, value.correct]⟩
        | .snd original => do
            let value ← normalizeCached original
            let projected ← secondCached value.value
            pure ⟨projected.value, fun assignment => by
              simp only [projected.correct, eval, value.correct]⟩
        | .inl original => do
            let value ← normalizeCached original
            pure ⟨.inl value.value, fun assignment => by simp only [eval, value.correct]⟩
        | .inr original => do
            let value ← normalizeCached original
            pure ⟨.inr value.value, fun assignment => by simp only [eval, value.correct]⟩
        | .isLeft original => do
            let value ← normalizeCached original
            let projected ← testLeftCached value.value
            pure ⟨projected.value, fun assignment => by
              simp only [projected.correct, eval, value.correct]⟩
        | .leftD original fallback => do
            let value ← normalizeCached original
            let other ← normalizeCached fallback
            let projected ← fromLeftCached value.value other.value
            pure ⟨projected.value, fun assignment => by
              simp only [projected.correct, eval, value.correct, other.correct]⟩
        | .rightD original fallback => do
            let value ← normalizeCached original
            let other ← normalizeCached fallback
            let projected ← fromRightCached value.value other.value
            pure ⟨projected.value, fun assignment => by
              simp only [projected.correct, eval, value.correct, other.correct]⟩
        | .cons head tail => do
            let a ← normalizeCached head
            let b ← normalizeCached tail
            pure ⟨.cons a.value b.value, fun assignment => by
              simp only [eval, a.correct, b.correct]⟩
        | .append left right => do
            let a ← normalizeCached left
            let b ← normalizeCached right
            pure ⟨.append a.value b.value, fun assignment => by
              simp only [eval, a.correct, b.correct]⟩
        | .length original => do
            let value ← normalizeCached original
            let length ← sizeCached value.value
            pure ⟨length.value, fun assignment => by simp only [length.correct, eval, value.correct]⟩
        | .take count original => do
            let n ← normalizeCached count
            let value ← normalizeCached original
            pure ⟨.take n.value value.value, fun assignment => by
              simp only [eval, n.correct, value.correct]⟩
        | .drop count original => do
            let n ← normalizeCached count
            let value ← normalizeCached original
            pure ⟨.drop n.value value.value, fun assignment => by
              simp only [eval, n.correct, value.correct]⟩
        | .get? original index => do
            let value ← normalizeCached original
            let n ← normalizeCached index
            let selected ← selectCached value.value n.value
            pure ⟨selected.value, fun assignment => by
              simp only [selected.correct, eval, n.correct, value.correct]⟩
        | .set original index replacement => do
            let value ← normalizeCached original
            let n ← normalizeCached index
            let next ← normalizeCached replacement
            pure ⟨.set value.value n.value next.value, fun assignment => by
              simp only [eval, n.correct, value.correct, next.correct]⟩
        | .contains original member => do
            let value ← normalizeCached original
            let candidate ← normalizeCached member
            pure ⟨.contains value.value candidate.value, fun assignment => by
              simp only [eval, value.correct, candidate.correct]⟩
termination_by _ original => sizeOf original

structure NormalizationState where
  entries : Cache := {}

def normalizeMemoM {s : Ty} (original : Expr s) :
    StateM NormalizationState (Expr s) := do
  let state ← get
  let (result, entries) := (normalizeCached original).run state.entries
  MonadStateOf.set ({ entries } : NormalizationState)
  return result.value

theorem normalizeMemoM_correct {s : Ty} (assignment : Assignment)
    (original : Expr s) (state : NormalizationState) :
    ((normalizeMemoM original).run state).1.eval assignment = original.eval assignment :=
  ((normalizeCached original).run state.entries).1.correct assignment

/-- Normalize shared nodes once and skip payloads discarded by constructors. -/
def normalizeMemo {s : Ty} (original : Expr s) : Expr s :=
  ((normalizeMemoM original).run {}).1

theorem normalizeMemo_correct {s : Ty} (assignment : Assignment) (original : Expr s) :
    original.normalizeMemo.eval assignment = original.eval assignment :=
  normalizeMemoM_correct assignment original {}

end Symbolic.Expr
