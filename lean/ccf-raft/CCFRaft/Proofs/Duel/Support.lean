module

public import CCFRaft.Proofs.Duel.Probability
public import Mathlib.MeasureTheory.Measure.Module

@[expose] public section

/-!
# Draws in the support

Almost every sample of `uniformDraws` lies in `[E / 2, E]` in every coordinate,
so an event need only be forced by margin rounds of draws in that support.
-/

namespace CCFRaft.Proofs.Duel

open CCFRaft.Liveness MeasureTheory Set

instance (E : Real) : IsFiniteMeasure (uniform E) := by
  unfold uniform
  have : Fact (volume (Icc (E / 2) E) < ⊤) := ⟨by simp⟩
  infer_instance

/-- A single draw lies in `[E / 2, E]` almost surely. -/
theorem ae_uniform_mem (E : Real) : ∀ᵐ x ∂(uniform E), x ∈ Icc (E / 2) E := by
  unfold uniform
  exact Measure.ae_smul_measure (ae_restrict_mem measurableSet_Icc) _

/-- Every draw of a sample lies in `[E / 2, E]` almost surely. -/
theorem ae_uniformDraws_mem (n rounds : Nat) (E : Real)
    : ∀ᵐ draws ∂(uniformDraws n rounds E), ∀ k i, draws k i ∈ Icc (E / 2) E := by
  rw [ae_all_iff]
  intro k
  rw [ae_all_iff]
  intro i
  have inner : ∀ᵐ draw ∂(Measure.pi fun _ : Fin n => uniform E), draw i ∈ Icc (E / 2) E :=
    (Measure.quasiMeasurePreserving_eval (fun _ : Fin n => uniform E) i).ae (ae_uniform_mem E)
  exact (Measure.quasiMeasurePreserving_eval
    (fun _ : Fin rounds => Measure.pi fun _ : Fin n => uniform E) k).ae inner

/-- `settle_of_margin` for an event forced only by margin rounds of draws in the
support. -/
theorem settle_of_margin_support {n rounds : Nat} {m E : Real} (hn : 0 < n) (hm : 0 ≤ m)
    (hmE : m < E / 2) {Good : Draws n rounds → Prop}
    (forces
      : ∀ draws,
          (∀ k i, draws k i ∈ Icc (E / 2) E) -> (∃ k, Margin (draws k) m) → Good draws)
    : ENNReal.ofReal (settleProbability n rounds m E)
      ≤ uniformDraws n rounds E {draws | Good draws} :=
  (settle_probability hn (by linarith) hm (by linarith) rounds).trans
    (measure_mono_ae
      ((ae_uniformDraws_mem n rounds E).mono
        fun draws support margin =>
          forces draws support margin))

end CCFRaft.Proofs.Duel
