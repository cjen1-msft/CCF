-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.SymbolicNormalizeMemo

set_option autoImplicit false

namespace Symbolic

private structure Renamed {s : Ty} (original : Expr s) where
  value : Expr s
  correct : ∀ assignment, value.eval assignment = original.eval assignment

/-- Cache misses and name allocations; leaf caches are scoped to one field. -/
structure NamingStats where
  choiceVisits : Nat := 0
  leafVisits : Nat := 0
  names : Nat := 0
  deriving Repr

private abbrev NamingEntry := (s : Ty) × (original : Expr s) × Renamed original
private abbrev NamingCache := Std.HashMap UInt64 (List NamingEntry)

private structure NamingState where
  nextSlot : Nat := 0
  normalization : Expr.NormalizationState := {}
  stats : NamingStats := {}
  choices : NamingCache := {}
  leaves : NamingCache := {}

private def findRenamed {s : Ty} (original : Expr s) :
    List NamingEntry → Option (Renamed original)
  | [] => none
  | ⟨t, prior, result⟩ :: rest =>
      match t.sharedDecEq s with
      | .isTrue sameType =>
          let candidate : Expr s := sameType ▸ prior
          let cached : Renamed candidate := by subst s; exact result
          match candidate.sharedDecEq original with
          | .isTrue same => some (same ▸ cached)
          | .isFalse _ => findRenamed original rest
      | .isFalse _ => findRenamed original rest

private def memoize (leaf : Bool) {s : Ty} (original : Expr s)
    (compute : Unit → StateM NamingState (Renamed original)) :
    StateM NamingState (Renamed original) := do
  let key := original.memoKey
  let state ← get
  let cache := if leaf then state.leaves else state.choices
  if let some result := findRenamed original (cache[key]?.getD []) then
    return result
  modify fun state =>
    if leaf then { state with stats.leafVisits := state.stats.leafVisits + 1 }
    else { state with stats.choiceVisits := state.stats.choiceVisits + 1 }
  let result ← compute ()
  modify fun state =>
    let cache := if leaf then state.leaves else state.choices
    let updated := cache.insert key (⟨_, original, result⟩ :: cache[key]?.getD [])
    if leaf then { state with leaves := updated } else { state with choices := updated }
  return result

private def underGuard (condition value : Expr .bool) (assumed : Bool) :
    { result : Expr .bool // ∀ assignment, condition.eval assignment = assumed →
      result.eval assignment = value.eval assignment } :=
  match condition.sharedDecEq value with
  | .isTrue same => ⟨.bool assumed, fun assignment guard => by
      rw [← same, guard]; rfl⟩
  | .isFalse _ =>
    match condition.not.sharedDecEq value with
    | .isTrue same => ⟨.bool (!assumed), fun assignment guard => by
        rw [← same]; simp [Expr.eval, guard]⟩
    | .isFalse _ => ⟨value, fun _ _ => rfl⟩

private def booleanChoice (condition left right : Expr .bool) :
    Renamed (.ite condition left right) :=
  match left, right with
  | .bool true, .bool false => ⟨condition, fun assignment => by simp [Expr.eval]⟩
  | .bool false, .bool true => ⟨condition.not, fun assignment => by
      simp only [Expr.eval]
      cases condition.eval assignment <;> rfl⟩
  | a, b => ⟨.ite condition a b, fun _ => rfl⟩

private def reduceChoice : {s : Ty} → (condition : Expr .bool) →
    (left right : Expr s) → Renamed (.ite condition left right)
  | .bool, condition, left, right =>
      let a := underGuard condition left true
      let b := underGuard condition right false
      let result := booleanChoice condition a.val b.val
      ⟨result.value, fun assignment => by
        rw [result.correct]
        cases guard : condition.eval assignment <;>
          simp [Expr.eval, guard, a.property assignment, b.property assignment]⟩
  | _, condition, left, right =>
      ⟨.ite condition left right, fun _ => rfl⟩

private def reduceChoices {s : Ty} (original : Expr s) :
    StateM NamingState (Renamed original) :=
  memoize false original fun _ => do
    match original with
    | .ite condition left right =>
        let a ← reduceChoices left
        let b ← reduceChoices right
        match a.value.sharedDecEq b.value with
        | .isTrue same => return ⟨a.value, fun assignment => by
            simp only [Expr.eval]
            split
            · exact a.correct assignment
            · rw [same]; exact b.correct assignment⟩
        | .isFalse _ =>
            let result := reduceChoice condition a.value b.value
            return ⟨result.value, fun assignment => by
              rw [result.correct]
              simp only [Expr.eval, a.correct, b.correct]⟩
    | value => return ⟨value, fun _ => rfl⟩
termination_by sizeOf original

private def compact {s : Ty} (original : Expr s) :
    StateM NamingState (Renamed original) := do
  let state ← get
  let result := original.normalizeMemoM.run state.normalization
  set { state with normalization := result.2 }
  return ⟨result.1, fun assignment =>
    Expr.normalizeMemoM_correct assignment original state.normalization⟩

private def nameLeafCached {s : Ty} (group : Nat) (before after : Expr s) :
    StateM NamingState (Renamed after) :=
  memoize true after fun _ => do
    match before.sharedDecEq after with
    | .isTrue same => return ⟨before, fun _ => congrArg (Expr.eval _) same⟩
    | .isFalse _ =>
      match after with
      | .ite condition left right =>
          let a ← nameLeafCached group before left
          let b ← nameLeafCached group before right
          match a.value.sharedDecEq b.value with
          | .isTrue same =>
              return ⟨a.value, fun assignment => by
                simp only [Expr.eval]
                split
                · exact a.correct assignment
                · rw [same]; exact b.correct assignment⟩
          | .isFalse _ =>
              return ⟨.ite condition a.value b.value, fun assignment => by
                simp only [Expr.eval, a.correct, b.correct]⟩
      | value =>
          let slot := (← get).nextSlot
          modify fun state =>
            { state with
              nextSlot := slot + 1
              stats := { state.stats with names := state.stats.names + 1 } }
          return ⟨.named group slot value, fun _ => rfl⟩
termination_by sizeOf after

private def nameLeaf {s : Ty} (group : Nat) (before after : Expr s) :
    StateM NamingState (Renamed after) := do
  -- Only recursive alternatives of this field share writer definitions.
  modify fun state => { state with leaves := {} }
  nameLeafCached group before after

private def withNormalized {s : Ty} (before after : Expr s)
    (rename : (before after : Expr s) → StateM NamingState (Renamed after)) :
    StateM NamingState (Renamed after) := do
  let prior ← compact before
  let current ← compact after
  let a ← reduceChoices prior.value
  let b ← reduceChoices current.value
  let result ← match a.value.sharedDecEq b.value with
    | .isTrue same => pure (⟨a.value, fun _ => congrArg (Expr.eval _) same⟩ :
        Renamed b.value)
    | .isFalse _ => rename a.value b.value
  return ⟨result.value, fun assignment =>
    (result.correct assignment).trans <|
      (b.correct assignment).trans (current.correct assignment)⟩

private def nameFields (group : Nat) : {s : Ty} → (before after : Expr s) →
    StateM NamingState (Renamed after)
  | .pair _ _, before, after => withNormalized before after fun prior current => do
      let left ← nameFields group prior.fst current.fst
      let right ← nameFields group prior.snd current.snd
      return ⟨.pair left.value right.value, fun assignment => by
        simp only [Expr.eval, left.correct, right.correct]⟩
  | .sum a b, before, after => withNormalized before after fun prior current => do
      let tag ← withNormalized prior.isLeft current.isLeft (nameLeaf group)
      let leftBefore := prior.leftD (defaultExpr a)
      let rightBefore := prior.rightD (defaultExpr b)
      -- Inactive payloads retain their old value, not a new writer.
      let left ← nameFields group leftBefore (current.leftD leftBefore)
      let right ← nameFields group rightBefore (current.rightD rightBefore)
      return ⟨.ite tag.value (.inl left.value) (.inr right.value), fun assignment => by
        simp only [Expr.eval, tag.correct, left.correct, right.correct]
        cases current.eval assignment <;> rfl⟩
  | .unit, _, after => pure ⟨.unit, fun _ => Subsingleton.elim _ _⟩
  | .nat, before, after => withNormalized before after (nameLeaf group)
  | .bool, before, after => withNormalized before after (nameLeaf group)
  | .seq _, before, after => withNormalized before after (nameLeaf group)
termination_by s _ _ => sizeOf s

/-- Only changed leaves receive names; slots are threaded through all branches. -/
def nameChanged {s : Ty} (group : Nat) (before after : Expr s) : Expr s :=
  ((nameFields group before after).run {}).1.value

def nameChangedWithStats {s : Ty} (group : Nat) (before after : Expr s) :
    Expr s × NamingStats :=
  let result := (nameFields group before after).run {}
  (result.1.value, result.2.stats)

theorem nameChangedWithStats_correct {s : Ty} (assignment : Assignment)
    (group : Nat) (before after : Expr s) :
    (nameChangedWithStats group before after).1.eval assignment = after.eval assignment :=
  ((nameFields group before after).run {}).1.correct assignment

theorem nameChanged_correct {s : Ty} (assignment : Assignment)
    (group : Nat) (before after : Expr s) :
    (nameChanged group before after).eval assignment = after.eval assignment :=
  ((nameFields group before after).run {}).1.correct assignment

end Symbolic
