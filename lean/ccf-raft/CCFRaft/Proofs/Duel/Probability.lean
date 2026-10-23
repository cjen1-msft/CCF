module

public import CCFRaft.Liveness.Assumptions.Duel
public import Mathlib.Topology.Instances.ENNReal.Lemmas
public import Mathlib.Tactic.FieldSimp
public import Mathlib.Tactic.Linarith
public import Mathlib.Tactic.Positivity
public import Mathlib.Tactic.Ring

@[expose] public section

/-!
# Timeout margins

Independent uniform timeout draws have the stated single-round and repeated-round lower bounds.
Translate each minimum-coordinate region of a smaller cube, leaving its minimum fixed and shifting the other coordinates.
An arbitrarily small extra shift makes the margin strict without needing to discard ties.
-/

namespace CCFRaft.Proofs.Duel

open CCFRaft.Liveness MeasureTheory Set
open scoped ENNReal NNReal Topology

/-- The timeout distribution has total mass one when its interval has positive length. -/
theorem uniform_isProbabilityMeasure {E : Real} (hE : 0 < E)
    : IsProbabilityMeasure (uniform E) := by
  constructor
  simp only [uniform, Measure.smul_apply, Measure.restrict_apply_univ,
    Real.volume_Icc]
  change ENNReal.ofReal (2 / E) * ENNReal.ofReal (E - E / 2) = 1
  rw [← ENNReal.ofReal_mul (by positivity), ← ENNReal.ofReal_one]
  congr 1
  field_simp
  ring

/-- A strict margin is a measurable event. -/
theorem measurableSet_margin (n : Nat) (m : Real)
    : MeasurableSet {draw : Fin n → Real | Margin draw m} := by
  simp only [Margin, ofPred_exists, ofPred_forall]
  refine MeasurableSet.iUnion fun i =>
    MeasurableSet.iInter fun j => MeasurableSet.iInter fun (_ : j ≠ i) => ?_
  exact measurableSet_lt (by fun_prop) (by fun_prop)

/-- The proposed single-round bound is between zero and one. -/
theorem marginProbability_mem_Icc (n : Nat) {m E : Real}
    (hE : 0 < E) (hm : 0 ≤ m) (hmE : 2 * m ≤ E)
    : marginProbability n m E ∈ Icc 0 1 := by
  have hlo : 0 ≤ 1 - 2 * m / E := by
    have := (div_le_one hE).2 hmE
    linarith
  have hhi : 1 - 2 * m / E ≤ 1 := by
    have : 0 ≤ 2 * m / E := by positivity
    linarith
  exact ⟨pow_nonneg hlo n, pow_le_one₀ hlo hhi⟩

private theorem uniform_pi_eq (n : Nat) {E : Real} (hE : 0 < E)
    : (Measure.pi fun _ : Fin n => uniform E)
      = ENNReal.ofReal (2 / E) ^ n
        • (volume : Measure (Fin n → Real)).restrict
            (Set.univ.pi fun _ => Icc (E / 2) E) := by
  let := uniform_isProbabilityMeasure hE
  apply Measure.pi_eq
  intro s hs
  simp only [Measure.smul_apply, smul_eq_mul,
    Measure.restrict_apply (MeasurableSet.univ_pi hs), ← Set.pi_inter_distrib,
    volume_pi_pi, uniform, Measure.nnreal_smul_coe_apply, Measure.restrict_apply (hs _)]
  simp [Finset.prod_mul_distrib, ENNReal.ofReal]

private theorem shifted_minimum_volume {n : Nat} (hn : 0 < n)
    (a b m t : Real) (hm : 0 ≤ m) (ht : m < t)
    : ENNReal.ofReal (b - t - a) ^ n
      ≤ volume
          ({draw : Fin n → Real | Margin draw m} ∩ Set.univ.pi fun _ => Icc a b) := by
  classical
  let : Nonempty (Fin n) := ⟨⟨0, hn⟩⟩
  let small : Set (Fin n → Real) := Set.univ.pi fun _ => Icc a (b - t)
  let region (i : Fin n) : Set (Fin n → Real) :=
    small ∩ {x | ∀ j, x i ≤ x j}
  let shift (i : Fin n) : Fin n → Real := fun j => if j = i then 0 else t
  let shifted (i : Fin n) : Set (Fin n → Real) :=
    (fun x => x - shift i) ⁻¹' region i
  have cover : small = ⋃ i, region i := by
    ext x
    constructor
    · intro hx
      obtain ⟨i, hi⟩ := Finite.exists_min x
      exact mem_iUnion.2 ⟨i, hx, hi⟩
    · intro hx
      obtain ⟨i, hi⟩ := mem_iUnion.1 hx
      exact hi.1
  have region_measurable (i : Fin n) : MeasurableSet (region i) := by
    refine (MeasurableSet.univ_pi fun _ => measurableSet_Icc).inter ?_
    simp only [ofPred_forall]
    refine MeasurableSet.iInter fun j => ?_
    exact measurableSet_le (measurable_pi_apply i) (measurable_pi_apply j)
  have shifted_measurable (i : Fin n) : MeasurableSet (shifted i) :=
    (region_measurable i).preimage (measurable_id.sub measurable_const)
  have lead (i : Fin n) {x : Fin n → Real} (hx : x ∈ shifted i) :
      ∀ j, j ≠ i → x i + m < x j := by
    intro j hji
    have hmin := hx.2 j
    change x i - (if i = i then 0 else t) ≤ x j - (if j = i then 0 else t) at hmin
    simp [hji] at hmin
    linarith
  have inside (i : Fin n) :
      shifted i ⊆ {draw | Margin draw m} ∩ Set.univ.pi (fun _ => Icc a b) := by
    intro x hx
    refine ⟨⟨i, lead i hx⟩, fun j _ => ?_⟩
    have hj := hx.1 j (mem_univ j)
    change a ≤ x j - (if j = i then 0 else t) ∧
      x j - (if j = i then 0 else t) ≤ b - t at hj
    by_cases hji : j = i
    · simp only [ite_eq_left hji, sub_zero] at hj
      exact ⟨hj.1, by linarith⟩
    · simp only [ite_eq_right hji] at hj
      constructor <;> linarith [hj.1, hj.2]
  have disjoint : Pairwise (Function.onFun Disjoint shifted) := by
    intro i j hij
    apply Set.disjoint_left.2
    intro x hxi hxj
    have hi := lead i hxi j hij.symm
    have hj := lead j hxj i hij
    linarith
  calc
    ENNReal.ofReal (b - t - a) ^ n = volume small := by
      simp only [small, volume_pi_pi, Real.volume_Icc, Finset.prod_const,
        Finset.card_univ, Fintype.card_fin]
    _ ≤ ∑ i, volume (region i) := by
      rw [cover]
      exact measure_iUnion_fintype_le _ _
    _ = ∑ i, volume (shifted i) := by
      apply Finset.sum_congr rfl
      intro i _
      exact ((measurePreserving_sub_right volume (shift i)).measure_preimage
        (region_measurable i).nullMeasurableSet).symm
    _ = volume (⋃ i, shifted i) := by
      rw [measure_iUnion disjoint shifted_measurable, tsum_fintype]
    _ ≤ _ := measure_mono (iUnion_subset inside)

private theorem minimum_volume {n : Nat} (hn : 0 < n) (a b m : Real) (hm : 0 ≤ m)
    : ENNReal.ofReal (b - m - a) ^ n
      ≤ volume
          ({draw : Fin n → Real | Margin draw m} ∩ Set.univ.pi fun _ => Icc a b) := by
  have continuous_bound :
      Continuous (fun t : Real => ENNReal.ofReal (b - t - a) ^ n) :=
    (ENNReal.continuous_pow n).comp
      (ENNReal.continuous_ofReal.comp ((continuous_const.sub continuous_id).sub continuous_const))
  apply le_of_tendsto (continuous_bound.continuousWithinAt (s := Ioi m)).tendsto
  filter_upwards [self_mem_nhdsWithin] with t ht
  exact shifted_minimum_volume hn a b m t hm ht

/-- The probability that one timeout undercuts every other timeout has the proposed lower bound. -/
theorem margin_probability {n : Nat} {m E : Real}
    (hn : 0 < n) (hE : 0 < E) (hm : 0 ≤ m) (hmE : 2 * m ≤ E)
    : ENNReal.ofReal (marginProbability n m E)
      ≤ (Measure.pi fun _ : Fin n => uniform E) {draw | Margin draw m} := by
  rw [uniform_pi_eq n hE, Measure.smul_apply, smul_eq_mul,
    Measure.restrict_apply (measurableSet_margin n m)]
  have hlength : 0 ≤ E - m - E / 2 := by linarith
  have hscale : 0 ≤ 2 / E := by positivity
  have factor : 1 - 2 * m / E = 2 / E * (E - m - E / 2) := by
    field_simp
    ring
  calc
    ENNReal.ofReal (marginProbability n m E)
        = ENNReal.ofReal (2 / E) ^ n * ENNReal.ofReal (E - m - E / 2) ^ n := by
      rw [marginProbability, factor, ENNReal.ofReal_pow (mul_nonneg hscale hlength),
        ENNReal.ofReal_mul hscale, mul_pow]
    _ ≤ _ := mul_le_mul_of_nonneg_left (minimum_volume hn (E / 2) E m hm) zero_le

/-- Independent rounds amplify the single-round margin bound to the stated settling probability. -/
theorem settle_probability {n : Nat} {m E : Real}
    (hn : 0 < n) (hE : 0 < E) (hm : 0 ≤ m) (hmE : 2 * m ≤ E) (rounds : Nat)
    : ENNReal.ofReal (settleProbability n rounds m E)
      ≤ uniformDraws n rounds E {draws | ∃ k, Margin (draws k) m} := by
  let := uniform_isProbabilityMeasure hE
  let μ := Measure.pi fun _ : Fin n => uniform E
  let good : Set (Draws n rounds) := {draws | ∃ k, Margin (draws k) m}
  have good_measurable : MeasurableSet good := by
    simp only [good, ofPred_exists]
    exact MeasurableSet.iUnion fun k =>
      (measurableSet_margin n m).preimage (measurable_pi_apply k)
  have : IsProbabilityMeasure (uniformDraws n rounds E) := by
    unfold uniformDraws
    infer_instance
  have failure :
      uniformDraws n rounds E goodᶜ = (1 - μ {draw | Margin draw m}) ^ rounds := by
    have complement : goodᶜ =
        Set.univ.pi (fun _ : Fin rounds => {draw : Fin n → Real | Margin draw m}ᶜ) := by
      ext draws
      simp [good, Set.mem_pi]
    rw [complement, uniformDraws, Measure.pi_pi]
    simp only [prob_compl_eq_one_sub (measurableSet_margin n m), Finset.prod_const,
      Finset.card_univ, Fintype.card_fin, μ]
  have hp := marginProbability_mem_Icc n hE hm hmE
  have hnonneg : 0 ≤ 1 - marginProbability n m E := sub_nonneg.2 hp.2
  have failure_bound : uniformDraws n rounds E goodᶜ ≤
      ENNReal.ofReal ((1 - marginProbability n m E) ^ rounds) := by
    rw [failure, ENNReal.ofReal_pow hnonneg, ENNReal.ofReal_sub _ hp.1,
      ENNReal.ofReal_one]
    exact pow_le_pow_left' (tsub_le_tsub_left (margin_probability hn hE hm hmE) 1) rounds
  calc
    ENNReal.ofReal (settleProbability n rounds m E)
        = 1 - ENNReal.ofReal ((1 - marginProbability n m E) ^ rounds) := by
      rw [settleProbability, ENNReal.ofReal_sub _ (pow_nonneg hnonneg rounds),
        ENNReal.ofReal_one]
    _ ≤ 1 - uniformDraws n rounds E goodᶜ := tsub_le_tsub_left failure_bound 1
    _ = uniformDraws n rounds E good := by
      rw [← prob_compl_eq_one_sub good_measurable.compl, compl_compl]

/-- Any event forced by every draw with a margin round has at least the settle
probability, whatever else it depends on. -/
theorem settle_of_margin {n rounds : Nat} {m E : Real} (hn : 0 < n) (hm : 0 ≤ m)
    (hmE : m < E / 2) {Good : Draws n rounds → Prop}
    (forces : ∀ draws, (∃ k, Margin (draws k) m) → Good draws)
    : ENNReal.ofReal (settleProbability n rounds m E)
      ≤ uniformDraws n rounds E {draws | Good draws} :=
  (settle_probability hn (by linarith) hm (by linarith) rounds).trans
    (measure_mono fun draws margin => forces draws margin)

end CCFRaft.Proofs.Duel
