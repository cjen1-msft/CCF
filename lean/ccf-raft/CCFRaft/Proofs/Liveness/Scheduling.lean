module

public import CCFRaft.Proofs.Liveness.Trace
public import CCFRaft.Liveness.Assumptions

@[expose] public section

/-!
# Scheduled obligations

An obligation that persists keeps the execution going, and its action fires
again and again.
-/

namespace CCFRaft.Liveness.Scheduled

variable {W : Type} [HasTime W] {trace : Trace W Event} {bound : Option Real}
  {Due : W -> Prop} {Fires : CCF.Execution.Step W Event -> Prop}
  (scheduled : Scheduled trace bound Due Fires)

include scheduled

/-- Dropping the deadline. -/
theorem untimed : Scheduled trace none Due Fires :=
  fun index point found due =>
    (scheduled index point found due).mono fun _ _ _ held => ⟨trivial, held.2⟩

/-- An obligation that holds at every recorded state from a recorded index fires
there or later. -/
theorem fires {index : Nat} {point : W} (found : trace.stateAt index = some point)
    (due
      : forall later point,
          index <= later -> trace.stateAt later = some point -> Due point)
    : exists later step,
        index <= later /\ trace.stepAt later = some step /\ Fires step := by
  obtain ⟨later, laterPoint, le, laterFound, _, outcome⟩ :=
    scheduled index point found (due index point (Nat.le_refl _) found)
  rcases outcome with resolved | ⟨step, stepped, fired⟩
  · exact absurd (due later laterPoint le laterFound) resolved
  · exact ⟨later, step, le, stepped, fired⟩

/-- An obligation that persists from a recorded index keeps the execution going. -/
theorem recorded {start : Nat} {first : W} (found : trace.stateAt start = some first)
    (due
      : forall index point,
          start <= index -> trace.stateAt index = some point -> Due point)
    {index : Nat} (le : start <= index)
    : exists point, trace.stateAt index = some point := by
  induction index, le using Nat.le_induction with
  | base => exact ⟨first, found⟩
  | succ index le ih =>
      obtain ⟨point, indexFound⟩ := ih
      obtain ⟨later, step, after, stepped, _⟩ :=
        scheduled.fires indexFound fun later point after laterFound =>
          due later point (Nat.le_trans le after) laterFound
      exact Trace.stateAt_of_le (Nat.succ_le_succ after) (Trace.stateAt_succ_of_stepAt stepped)

/-- An obligation that persists from a recorded index fires infinitely often. -/
theorem often {start : Nat} {first : W} (found : trace.stateAt start = some first)
    (due
      : forall index point,
          start <= index -> trace.stateAt index = some point -> Due point)
    (cutoff : Nat)
    : exists index step,
        cutoff <= index /\ trace.stepAt index = some step /\ Fires step := by
  obtain ⟨point, pointFound⟩ := scheduled.recorded found due (Nat.le_max_right cutoff start)
  obtain ⟨index, step, after, stepped, fired⟩ :=
    scheduled.fires pointFound fun later point le laterFound =>
      due later point (Nat.le_trans (Nat.le_max_right _ _) le) laterFound
  exact ⟨index, step, Nat.le_trans (Nat.le_max_left _ _) after, stepped, fired⟩

end CCFRaft.Liveness.Scheduled
