module

public import CCFRaft.Proofs.Duel.Attempts
public import Mathlib.Topology.Instances.ENNReal.Lemmas
public import Mathlib.Tactic.FieldSimp
public import Mathlib.Tactic.Linarith
public import Mathlib.Tactic.Positivity
public import Mathlib.Tactic.Ring

@[expose] public section

/-!
# Remaining-time laws

NOT IMPORTED BY `Properties`. Two instances of `Liveness.Law`: the continuous uniform
law on `[E / 2, E]`, and CCF's integer-millisecond law. `restart_election_timeout`
(raft.h) draws `timeout_elapsed` with `uniform_int_distribution(0, E / 2)`, so the
remaining time is uniform over the `E / 2 + 1` integers of `[E / 2, E]`, in
milliseconds. The tick offset is a separate timer-model gap and is left out.
-/

namespace CCFRaft.Proofs.Duel.Rounds

open MeasureTheory Set
open CCFRaft.Liveness (uniform Law)
open scoped Classical

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

/-- The continuous uniform law puts at most `4 * margin / E` on an interval of
radius `margin`. -/
theorem uniform_law {E margin : Real} (positive : 0 < E) (nonnegative : 0 <= margin)
    : Law E margin (4 * margin / E) (uniform E) where
  probability := uniform_isProbabilityMeasure positive
  support := by
    simp only [uniform, Measure.smul_apply,
      Measure.restrict_apply measurableSet_Icc.compl, compl_inter_self, measure_empty,
      smul_zero]
  nonnegative := by positivity
  concentrated x := by
    simp only [uniform, Measure.smul_apply]
    change ENNReal.ofReal (2 / E) * _ <= _
    calc
      ENNReal.ofReal (2 / E)
            * volume.restrict (Icc (E / 2) E) (Icc (x - margin) (x + margin))
          <= ENNReal.ofReal (2 / E) * volume (Icc (x - margin) (x + margin)) := by
        gcongr
        exact Measure.restrict_le_self
      _ = ENNReal.ofReal (4 * margin / E) := by
        rw [Real.volume_Icc, ← ENNReal.ofReal_mul (by positivity)]
        congr 1
        field_simp
        ring

/-- CCF's law, in milliseconds with `E = 2 * half`: uniform over the integers
`half, half + 1, ..., 2 * half`. -/
noncomputable def ccfLaw (half : Nat) : Measure Real :=
  ∑ i ∈ Finset.range (half + 1),
    ((half + 1 : ENNReal)⁻¹) • Measure.dirac ((half : Real) + i)

theorem ccfLaw_apply (half : Nat) (set : Set Real)
    : ccfLaw half set
      = (half + 1 : ENNReal)⁻¹
        * ((Finset.range (half + 1)).filter
            fun i : Nat => (half : Real) + i ∈ set).card := by
  simp only [ccfLaw, Measure.coe_finsetSum, Finset.sum_apply, Measure.smul_apply,
    Measure.dirac_apply, smul_eq_mul]
  rw [Finset.card_filter, Nat.cast_sum, Finset.mul_sum]
  refine Finset.sum_congr rfl fun i _ => ?_
  by_cases member : (half : Real) + i ∈ set
  · simp [member]
  · simp [member]

/-- An interval of radius `margin` holds at most `2 * margin + 1` integers. -/
theorem card_window (half : Nat) (x : Real) {margin : Real} (nonnegative : 0 <= margin)
    : (((Finset.range (half + 1)).filter
          fun i : Nat =>
            (half : Real) + i ∈ Icc (x - margin) (x + margin)).card
        : Real)
      <= 2 * margin + 1 := by
  set chosen := (Finset.range (half + 1)).filter fun i : Nat =>
    (half : Real) + i ∈ Icc (x - margin) (x + margin)
  have injective : Set.InjOn (fun i : Nat => (i : Int)) (chosen : Set Nat) :=
    fun a _ b _ eq => Nat.cast_injective eq
  have maps
      : forall i, i ∈ chosen
          -> (i : Int) ∈ Finset.Icc ⌈x - margin - half⌉ ⌊x + margin - half⌋ := by
    intro i member
    obtain ⟨_, low, high⟩ := Finset.mem_filter.mp member
    rw [Finset.mem_Icc, Int.ceil_le, Int.le_floor]
    push_cast
    constructor <;> linarith
  have card := Finset.card_le_card_of_injOn _ maps injective
  rw [Int.card_Icc] at card
  by_cases empty : chosen.card = 0
  · rw [empty, Nat.cast_zero]
    linarith
  · have ceil := Int.le_ceil (x - margin - half)
    have floor := Int.floor_le (x + margin - half)
    have : (chosen.card : Int) <= ⌊x + margin - half⌋ + 1 - ⌈x - margin - half⌉ := by
      omega
    have real : (chosen.card : Real)
        <= ((⌊x + margin - half⌋ + 1 - ⌈x - margin - half⌉ : Int) : Real) := by
      exact_mod_cast this
    push_cast at real
    linarith

/-- CCF's integer law puts at most `(2 * margin + 1) / (half + 1)` on an interval of
radius `margin`, all in milliseconds. -/
theorem ccf_law (half : Nat) {margin : Real} (nonnegative : 0 <= margin)
    : Law (2 * half) margin ((2 * margin + 1) / (half + 1)) (ccfLaw half) where
  probability := by
    constructor
    rw [ccfLaw_apply]
    simp only [mem_univ, Finset.filter_true, Finset.card_range, Nat.cast_add, Nat.cast_one]
    exact ENNReal.inv_mul_cancel (by simp) (by simp)
  support := by
    rw [ccfLaw_apply]
    convert mul_zero ((half + 1 : ENNReal)⁻¹)
    simp only [Nat.cast_eq_zero, Finset.card_eq_zero, Finset.filter_eq_empty_iff]
    intro i member
    have : (i : Real) <= half := by exact_mod_cast Nat.lt_succ_iff.mp (Finset.mem_range.mp member)
    simp only [mem_compl_iff, mem_Icc, not_not]
    constructor <;> linarith
  nonnegative := by positivity
  concentrated x := by
    rw [ccfLaw_apply, div_eq_mul_inv, mul_comm, ENNReal.ofReal_mul (by positivity),
      ENNReal.ofReal_inv_of_pos (by positivity)]
    have total : ENNReal.ofReal ((half : Real) + 1) = (half + 1 : ENNReal) := by
      rw [ENNReal.ofReal_add (by positivity) zero_le_one, ENNReal.ofReal_natCast,
        ENNReal.ofReal_one]
    rw [total]
    have card := ENNReal.ofReal_le_ofReal (card_window half x nonnegative)
    rw [ENNReal.ofReal_natCast] at card
    gcongr
    convert card

end CCFRaft.Proofs.Duel.Rounds
