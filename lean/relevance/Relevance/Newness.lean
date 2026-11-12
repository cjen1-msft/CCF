module

public import CCF.TransitionSystem

/-!
# New instances along runs (rule F1)

Generic facts behind rule F1 ("the instance `x` of a clause with premise `P` is new at a step
`s -> t` when `P t` holds and `P s` does not"); nothing here is specific to a model.

* `exists_new`: along any run `f 0, f 1, ..., f k` from a state where `P` is false to one where it
  is true, some step makes `P` new.
* `new_unique`: if `P` stays true along the run, that step is unique.
* `reachable_new`: in a transition system where `P` is false initially, every reachable state
  where `P` holds was reached through a step, from a reachable state, that makes `P` new.
-/

@[expose] public section

namespace Relevance

theorem exists_new {σ : Type _} (P : σ → Prop) (f : Nat → σ) :
    ∀ {k : Nat}, ¬ P (f 0) → P (f k) → ∃ i < k, ¬ P (f i) ∧ P (f (i + 1))
  | 0, h0, hk => absurd hk h0
  | k + 1, h0, hk => by
    by_cases h : P (f k)
    · obtain ⟨i, lt, new⟩ := exists_new P f h0 h
      exact ⟨i, Nat.lt_succ_of_lt lt, new⟩
    · exact ⟨k, Nat.lt_succ_self k, h, hk⟩

theorem stays {σ : Type _} (P : σ → Prop) (f : Nat → σ) {k : Nat}
    (mono : ∀ i < k, P (f i) → P (f (i + 1))) {i j : Nat} (le : i ≤ j) (lt : j ≤ k)
    (h : P (f i)) : P (f j) := by
  obtain ⟨d, rfl⟩ := Nat.exists_eq_add_of_le le
  induction d with
  | zero => exact h
  | succ d ih =>
    exact mono (i + d) (Nat.lt_of_succ_le lt) (ih (Nat.le_add_right _ _) (Nat.le_of_succ_le lt))

theorem new_unique {σ : Type _} (P : σ → Prop) (f : Nat → σ) {k : Nat}
    (mono : ∀ i < k, P (f i) → P (f (i + 1))) {i j : Nat} (hi : i < k) (hj : j < k)
    (newi : ¬ P (f i) ∧ P (f (i + 1))) (newj : ¬ P (f j) ∧ P (f (j + 1))) : i = j := by
  rcases Nat.lt_trichotomy i j with lt | eq | gt
  · exact absurd (stays P f mono lt (Nat.le_of_lt hj) newi.2) newj.1
  · exact eq
  · exact absurd (stays P f mono gt (Nat.le_of_lt hi) newj.2) newi.1

theorem reachable_new (system : CCF.TransitionSystem) (P : system.State → Prop)
    (init : ∀ s, system.init s → ¬ P s) {t : system.State} (reachable : system.Reachable t)
    (holds : P t) : ∃ s a t', system.Reachable s ∧ system.step s a = some t' ∧
      system.Reachable t' ∧ ¬ P s ∧ P t' := by
  induction reachable with
  | initial initialized => exact absurd holds (init _ initialized)
  | @step s t' a reachable transition ih =>
    by_cases h : P s
    · exact ih h
    · exact ⟨s, a, t', reachable, transition, .step reachable transition, h, holds⟩

end Relevance

end
