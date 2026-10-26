module

public import CCFRaft.Proofs.Duel.Attempts

@[expose] public section

/-!
# Blocks of attempts

The union bound behind the finitely-many-overshoots form of the duel. The rounds are
cut into `blocks` blocks of `rounds` rounds. If every block has a round whose
relevant draws all keep the margin, the event holds. Each block fails with
probability at most `roundFailure ^ rounds` (`failed_bound` on the block's rounds),
so the event fails on a set of measure at most `blocks * roundFailure ^ rounds`
(`blocks_bound`). The event need not be measurable: the bound is on the outer measure
of its complement, so a measurable subset of the event has measure at least
`1 - blocks * roundFailure ^ rounds`.
-/

namespace CCFRaft.Proofs.Duel.Rounds

open MeasureTheory ProbabilityTheory Set
open CCFRaft.Liveness (Law roundFailure)

namespace Attempts

variable {margin : Real} {width K : Nat}

/-- The rounds of `attempts` from `offset` on, as rounds from zero. -/
def shift (attempts : Attempts margin width K) (offset : Nat)
    : Attempts margin width K where
  relevant k := attempts.relevant (offset + k)
  relevant_measurable k := attempts.relevant_measurable (offset + k)
  centres k := attempts.centres (offset + k)
  centres_measurable k := attempts.centres_measurable (offset + k)
  ordered k k' j j' sample lt :=
    attempts.ordered (offset + k) (offset + k') j j' sample (by omega)
  bounded k := attempts.bounded (offset + k)

end Attempts

theorem blocks_bound {E margin rho : Real} {law : Measure Real}
    {width blocks rounds K : Nat} {Good : Set Sample}
    (isLaw : Law E margin rho law)
    (attempts : Attempts margin width K)
    (forces
      : forall sample,
          (forall j, sample j ∈ Icc (E / 2) E)
          -> (forall b,
                b < blocks
                -> exists k,
                    k < rounds
                    /\ forall j,
                        attempts.relevant (b * rounds + k) j sample
                        -> forall i,
                            margin
                            < |sample j - attempts.centres (b * rounds + k) j sample i|)
          -> sample ∈ Good)
    : Measure.infinitePi (fun _ => law) Goodᶜ
      <= blocks * ENNReal.ofReal (roundFailure rho width K) ^ rounds := by
  have := isLaw.probability
  set mu := Measure.infinitePi fun _ : Nat => law
  set q := roundFailure rho width K
  let Support : Set Sample := {sample | forall j, sample j ∈ Icc (E / 2) E}
  have supportNull : mu Supportᶜ = 0 := by
    have : Supportᶜ = ⋃ j, (fun sample : Sample => sample j) ⁻¹' (Icc (E / 2) E)ᶜ := by
      ext
      simp [Support]
    rw [this]
    refine measure_iUnion_null fun j => ?_
    rw [← Measure.map_apply (measurable_pi_apply j) measurableSet_Icc.compl,
      Measure.infinitePi_map_eval]
    exact isLaw.support
  let block (b : Nat) := attempts.shift (b * rounds)
  let Spoiled : Set Sample := ⋃ b ∈ Finset.range blocks, (block b).Failed rounds
  have sub : Support ∩ Spoiledᶜ ⊆ Good := by
    rintro sample ⟨support, clean⟩
    refine forces sample support fun b lt => ?_
    have notFailed : sample ∉ (block b).Failed rounds := fun failed =>
      clean (mem_biUnion (Finset.mem_range.mpr lt) failed)
    simp only [Attempts.Failed, mem_iInter, Finset.mem_range, not_forall] at notFailed
    obtain ⟨k, kLt, notFail⟩ := notFailed
    refine ⟨k, kLt, fun j relevant i => ?_⟩
    by_contra close
    push Not at close
    exact notFail (mem_iUnion.mpr ⟨j, relevant, mem_iUnion.mpr ⟨i, close⟩⟩)
  calc
    mu Goodᶜ <= mu (Spoiled ∪ Supportᶜ) :=
      measure_mono
        fun sample bad => by
          by_cases inSupport : sample ∈ Support
          · by_cases spoiled : sample ∈ Spoiled
            · exact Or.inl spoiled
            · exact absurd (sub ⟨inSupport, spoiled⟩) bad
          · exact Or.inr inSupport
    _ <= mu Spoiled + mu Supportᶜ := measure_union_le _ _
    _ = mu Spoiled := by rw [supportNull, add_zero]
    _ <= ∑ b ∈ Finset.range blocks, mu ((block b).Failed rounds) :=
      measure_biUnion_finset_le _ _
    _ <= ∑ _b ∈ Finset.range blocks, ENNReal.ofReal q ^ rounds :=
      Finset.sum_le_sum fun b _ => (block b).failed_bound isLaw.concentrated rounds
    _ = _ := by simp

end CCFRaft.Proofs.Duel.Rounds
