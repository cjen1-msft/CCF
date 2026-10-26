module

public import CCFRaft.Liveness.Assumptions.Duel
public import Mathlib.Probability.Independence.InfinitePi

@[expose] public section

/-!
# The attempts interface

NOT IMPORTED BY `Properties`. Part (c) of the duel, for any remaining-time `Law`.

The deterministic part of the duel supplies `Attempts`; `failed_bound` bounds the
probability that its first `n` rounds all fail. Whether a draw is relevant to
round `k`, and the deadlines it must avoid, are decided by the draws before it, so
an adaptive re-draw is just another relevant draw. Every relevant draw then lands
within `margin` of one of `width` known centres with probability at most
`width * rho` given everything before it, and a round with at most `K` relevant
draws fails with probability at most `K * width * rho` given everything before it.
Only Fubini on `Measure.infinitePi` is used: no stopping times or strong Markov
property.
-/

namespace CCFRaft.Proofs.Duel.Rounds

open MeasureTheory ProbabilityTheory Set
open CCFRaft.Liveness (uniform Law roundFailure)

/-- `Liveness.Sample`: the offset drawn by the `j`-th participant reset. -/
abbrev Sample := Nat -> Real

/-- The draws before `j`, as a point of a finite product. -/
def front (j : Nat) (sample : Sample) : Finset.range j -> Real :=
  fun i => sample i

set_option warn.classDefReducibility false in
/-- The sigma-algebra of the draws before `j`. -/
def revealed (j : Nat) : MeasurableSpace Sample :=
  MeasurableSpace.comap (front j) MeasurableSpace.pi

/-- Rounds of predictable relevant draws. A round fails when one of its relevant
draws lands within `margin` of one of its centres. -/
structure Attempts (margin : Real) (width K : Nat) where
  /-- Draw `j` is relevant to round `k`. -/
  relevant : Nat -> Nat -> Sample -> Prop
  relevant_measurable
    : forall k j, MeasurableSet[revealed j] {sample | relevant k j sample}
  /-- The deadlines a relevant draw must avoid: other potential winners' current
  deadlines, less the time of the reset. -/
  centres : Nat -> Nat -> Sample -> Fin width -> Real
  centres_measurable
    : forall k j i, Measurable[revealed j] fun sample => centres k j sample i
  /-- Rounds use disjoint, increasing draws. -/
  ordered
    : forall k k' j j' sample,
        k < k' -> relevant k j sample -> relevant k' j' sample -> j < j'
  /-- At most `K` relevant draws per round. -/
  bounded
    : forall k sample,
        exists draws : Finset Nat,
          draws.card <= K /\ forall j, relevant k j sample -> j ∈ draws

section Bound

variable {law : Measure Real} [IsProbabilityMeasure law]

theorem measurable_front (j : Nat) : Measurable (front j) :=
  measurable_pi_iff.mpr fun i => measurable_pi_apply (i : Nat)

theorem revealed_le (j : Nat) : revealed j <= MeasurableSpace.pi :=
  (measurable_front j).comap_le

theorem revealed_mono {i j : Nat} (le : i <= j) : revealed i <= revealed j := by
  refine Measurable.comap_le ?_
  have : front i
      = (fun (point : Finset.range j -> Real) (index : Finset.range i) =>
          point ⟨index, Finset.mem_range.mpr
            (lt_of_lt_of_le (Finset.mem_range.mp index.2) le)⟩) ∘ front j := rfl
  rw [this]
  exact (measurable_pi_iff.mpr fun _ => measurable_pi_apply _).comp
    (comap_measurable (front j))

theorem measurable_draw {i j : Nat} (lt : i < j)
    : Measurable[revealed j] fun sample : Sample => sample i := by
  have : (fun sample : Sample => sample i)
      = (fun point : Finset.range j -> Real =>
          point ⟨i, Finset.mem_range.mpr lt⟩) ∘ front j := rfl
  rw [this]
  exact (measurable_pi_apply _).comp (comap_measurable (front j))

/-- The prefix before `j` and draw `j` are independent. -/
theorem map_front_draw (j : Nat)
    : (Measure.infinitePi fun _ => law).map (fun sample => (front j sample, sample j))
      = ((Measure.infinitePi fun _ => law).map (front j)).prod law := by
  have independent := (iIndepFun_infinitePi (P := fun _ => law) (X := fun _ x => x)
    fun _ => measurable_id).indepFun_finset (Finset.range j) {j}
    (by simp) fun i => measurable_pi_apply i
  have select
      : Measurable fun point : ({j} : Finset Nat) -> Real =>
          point ⟨j, Finset.mem_singleton_self j⟩ :=
    measurable_pi_apply _
  have pair := independent.comp measurable_id select
  rw [(indepFun_iff_map_prod_eq_prod_map_map (measurable_front j).aemeasurable
    (measurable_pi_apply j).aemeasurable).mp pair, Measure.infinitePi_map_eval]

/-- One draw lands within `margin` of a revealed centre with conditional probability
at most `rho`. -/
theorem draw_close {margin rho : Real}
    (concentrated : forall x, law (Icc (x - margin) (x + margin)) <= ENNReal.ofReal rho)
    {j : Nat} {A : Set Sample} (revealedA : MeasurableSet[revealed j] A)
    {centre : Sample -> Real} (revealedCentre : Measurable[revealed j] centre)
    : Measure.infinitePi (fun _ => law)
        (A ∩ {sample | |sample j - centre sample| <= margin})
      <= ENNReal.ofReal rho * Measure.infinitePi (fun _ => law) A := by
  obtain ⟨A', measurableA, rfl⟩ := revealedA
  obtain ⟨c, measurableC, rfl⟩ := revealedCentre.exists_eq_measurable_comp
  set mu := Measure.infinitePi fun _ : Nat => law
  let T : Set ((Finset.range j -> Real) × Real) :=
    {point | point.1 ∈ A' /\ |point.2 - c point.1| <= margin}
  have measurableT : MeasurableSet T :=
    (measurable_fst measurableA).inter
      (measurableSet_le (continuous_abs.measurable.comp
          (measurable_snd.sub (measurableC.comp measurable_fst)))
        measurable_const)
  have preimage
      : front j ⁻¹' A' ∩ {sample | |sample j - (c ∘ front j) sample| <= margin}
        = (fun sample => (front j sample, sample j)) ⁻¹' T := rfl
  rw [preimage, ← Measure.map_apply ((measurable_front j).prodMk (measurable_pi_apply j))
    measurableT, map_front_draw, Measure.prod_apply measurableT,
    ← Measure.map_apply (measurable_front j) measurableA,
    ← lintegral_indicator_const measurableA]
  refine lintegral_mono fun point => ?_
  by_cases member : point ∈ A'
  · rw [indicator_of_mem member]
    refine le_trans (le_of_eq (congrArg law ?_)) (concentrated (c point))
    ext x
    simp only [T, mem_preimage, mem_Icc, abs_le]
    exact ⟨fun ⟨_, low, high⟩ => ⟨by linarith, by linarith⟩,
      fun ⟨low, high⟩ => ⟨member, by linarith, by linarith⟩⟩
  · rw [indicator_of_notMem member]
    simp [T, member]

end Bound

namespace Attempts

variable {margin : Real} {width K : Nat} (attempts : Attempts margin width K)

/-- Draw `j` is relevant to round `k` and lands within `margin` of a centre. -/
def Close (k j : Nat) : Set Sample :=
  {sample | attempts.relevant k j sample}
  ∩ ⋃ i, (fun sample => |sample j - attempts.centres k j sample i|) ⁻¹' Iic margin

/-- Round `k` fails. -/
def Fail (k : Nat) : Set Sample := ⋃ j, attempts.Close k j

/-- Round `k` fails on a draw before `j`. -/
def FailBefore (k j : Nat) : Set Sample := ⋃ j' ∈ Finset.range j, attempts.Close k j'

/-- Every round before `n` fails. -/
def Failed (n : Nat) : Set Sample := ⋂ k ∈ Finset.range n, attempts.Fail k

/-- Every round before `n` fails on a draw before `j`. -/
def FailedBefore (n j : Nat) : Set Sample := ⋂ k ∈ Finset.range n, attempts.FailBefore k j

theorem close_measurable {k i j : Nat} (le : i < j)
    : MeasurableSet[revealed j] (attempts.Close k i) := by
  refine MeasurableSet.inter (revealed_mono le.le _ (attempts.relevant_measurable k i))
    (MeasurableSet.iUnion fun index => ?_)
  exact (continuous_abs.measurable.comp ((measurable_draw le).sub
    ((attempts.centres_measurable k i index).mono (revealed_mono le.le) le_rfl)))
    measurableSet_Iic

theorem failedBefore_measurable (n j : Nat)
    : MeasurableSet[revealed j] (attempts.FailedBefore n j) :=
  MeasurableSet.biInter (Finset.range n).countable_toSet
    fun _ _ =>
      MeasurableSet.biUnion (Finset.range j).countable_toSet
        fun _ inRange =>
          attempts.close_measurable (Finset.mem_range.mp inRange)

theorem close_pi (k j : Nat) : MeasurableSet (attempts.Close k j) :=
  revealed_le (j + 1) _ (attempts.close_measurable (Nat.lt_succ_self j))

theorem failed_measurable (n : Nat) : MeasurableSet (attempts.Failed n) :=
  MeasurableSet.biInter (Finset.range n).countable_toSet
    fun _ _ =>
      MeasurableSet.iUnion fun _ => attempts.close_pi _ _

/-- Before a draw relevant to round `k`, the earlier rounds have used all their draws. -/
theorem failed_relevant (k j : Nat)
    : attempts.Failed k ∩ {sample | attempts.relevant k j sample}
      = attempts.FailedBefore k j ∩ {sample | attempts.relevant k j sample} := by
  ext sample
  simp only [Failed, FailedBefore, Fail, FailBefore, mem_inter_iff, mem_iInter, mem_iUnion,
    Finset.mem_range, mem_ofPred_eq]
  constructor
  · rintro ⟨fails, relevant⟩
    refine ⟨fun k' lt => ?_, relevant⟩
    obtain ⟨j', close⟩ := fails k' lt
    exact ⟨j', attempts.ordered k' k j' j sample lt close.1 relevant, close⟩
  · rintro ⟨fails, relevant⟩
    refine ⟨fun k' lt => ?_, relevant⟩
    obtain ⟨j', _, close⟩ := fails k' lt
    exact ⟨j', close⟩

variable {law : Measure Real} [IsProbabilityMeasure law]

omit [IsProbabilityMeasure law] in
/-- The relevant draws of one round, counted with multiplicity over a set. -/
theorem relevant_count (k : Nat) {A : Set Sample} (measurableA : MeasurableSet A)
    : ∑' j,
        Measure.infinitePi (fun _ => law) (A ∩ {sample | attempts.relevant k j sample})
      <= K * Measure.infinitePi (fun _ => law) A := by
  set mu := Measure.infinitePi fun _ : Nat => law
  have measurable
      : forall j, MeasurableSet (A ∩ {sample | attempts.relevant k j sample}) := fun j =>
    measurableA.inter (revealed_le j _ (attempts.relevant_measurable k j))
  calc
    ∑' j, mu (A ∩ {sample | attempts.relevant k j sample})
        = ∑' j,
            ∫⁻ sample,
              (A ∩ {sample | attempts.relevant k j sample}).indicator 1 sample ∂mu := by
      congr 1
      ext j
      rw [lintegral_indicator_one (measurable j)]
    _ = ∫⁻ sample,
          ∑' j, (A ∩ {sample | attempts.relevant k j sample}).indicator 1 sample ∂mu :=
      (lintegral_tsum
        fun j =>
          (measurable_one.indicator (measurable j)).aemeasurable).symm
    _ <= ∫⁻ sample, A.indicator (fun _ => (K : ENNReal)) sample ∂mu := by
      refine lintegral_mono fun sample => ?_
      by_cases member : sample ∈ A
      · obtain ⟨draws, card, covers⟩ := attempts.bounded k sample
        rw [indicator_of_mem member, tsum_eq_sum (s := draws) fun j notIn => ?_]
        · calc ∑ j ∈ draws, (A ∩ {sample | attempts.relevant k j sample}).indicator 1 sample
              <= ∑ _j ∈ draws, (1 : ENNReal) := Finset.sum_le_sum fun j _ => by
                by_cases inSet : sample ∈ A ∩ {sample | attempts.relevant k j sample}
                · simp [indicator_of_mem inSet]
                · simp [indicator_of_notMem inSet]
            _ <= K := by
              simp only [Finset.sum_const, nsmul_eq_mul, mul_one]
              exact_mod_cast card
        · exact indicator_of_notMem (fun inSet => notIn (covers j inSet.2)) _
      · rw [indicator_of_notMem member]
        simp [indicator_of_notMem (fun inSet : sample ∈ A ∩ _ => member inSet.1)]
    _ = K * mu A := lintegral_indicator_const measurableA _

theorem failed_succ (n : Nat)
    : attempts.Failed (n + 1) = attempts.Failed n ∩ attempts.Fail n := by
  ext sample
  simp only [Failed, mem_iInter, Finset.mem_range, mem_inter_iff]
  constructor
  · intro all
    exact ⟨fun k lt => all k (by omega), all n (by omega)⟩
  · rintro ⟨all, last⟩ k lt
    rcases Nat.lt_succ_iff_lt_or_eq.mp lt with lt | rfl
    · exact all k lt
    · exact last

variable {rho : Real}
  (concentrated : forall x, law (Icc (x - margin) (x + margin)) <= ENNReal.ofReal rho)
include concentrated

/-- A relevant draw of round `k` lands near a centre with probability at most
`width * rho`, given that the earlier rounds failed. -/
theorem close_bound (k j : Nat)
    : Measure.infinitePi (fun _ => law) (attempts.Failed k ∩ attempts.Close k j)
      <= ENNReal.ofReal (width * rho)
          * Measure.infinitePi (fun _ => law)
              (attempts.Failed k ∩ {sample | attempts.relevant k j sample}) := by
  have revealedA
      : MeasurableSet[revealed j]
          (attempts.FailedBefore k j ∩ {sample | attempts.relevant k j sample}) :=
    (attempts.failedBefore_measurable k j).inter (attempts.relevant_measurable k j)
  rw [Close, ← inter_assoc, attempts.failed_relevant, inter_iUnion]
  calc
    _ <= ∑ i : Fin width,
          Measure.infinitePi (fun _ => law)
            (attempts.FailedBefore k j
              ∩ {sample | attempts.relevant k j sample}
              ∩ (fun sample => |sample j - attempts.centres k j sample i|)
                ⁻¹' Iic margin) :=
      measure_iUnion_fintype_le _ _
    _ <= ∑ _i : Fin width,
          ENNReal.ofReal rho
          * Measure.infinitePi (fun _ => law)
              (attempts.FailedBefore k j ∩ {sample | attempts.relevant k j sample}) :=
      Finset.sum_le_sum
        fun i _ =>
          draw_close concentrated revealedA (attempts.centres_measurable k j i)
    _ = _ := by
      rw [Finset.sum_const, Finset.card_univ, Fintype.card_fin, nsmul_eq_mul,
        ENNReal.ofReal_mul (Nat.cast_nonneg _), ENNReal.ofReal_natCast, mul_assoc]

/-- Round `k` fails with probability at most `roundFailure` given the earlier ones. -/
theorem round_bound (k : Nat)
    : Measure.infinitePi (fun _ => law) (attempts.Failed (k + 1))
      <= ENNReal.ofReal (roundFailure rho width K)
          * Measure.infinitePi (fun _ => law) (attempts.Failed k) := by
  set mu := Measure.infinitePi fun _ : Nat => law
  calc
    mu (attempts.Failed (k + 1)) = mu (⋃ j, attempts.Failed k ∩ attempts.Close k j) := by
      rw [failed_succ, Fail, inter_iUnion]
    _ <= ∑' j, mu (attempts.Failed k ∩ attempts.Close k j) := measure_iUnion_le _
    _ <= ∑' j,
          ENNReal.ofReal (width * rho)
          * mu (attempts.Failed k ∩ {sample | attempts.relevant k j sample}) :=
      ENNReal.tsum_le_tsum fun j => attempts.close_bound concentrated k j
    _ = ENNReal.ofReal (width * rho)
        * ∑' j, mu (attempts.Failed k ∩ {sample | attempts.relevant k j sample}) :=
      ENNReal.tsum_mul_left
    _ <= ENNReal.ofReal (width * rho) * (K * mu (attempts.Failed k)) := by
      gcongr; exact attempts.relevant_count k (attempts.failed_measurable k)
    _ = _ := by
      rw [roundFailure, mul_assoc, ENNReal.ofReal_mul (Nat.cast_nonneg K),
        ENNReal.ofReal_natCast]
      ring

theorem failed_bound (n : Nat)
    : Measure.infinitePi (fun _ => law) (attempts.Failed n)
      <= ENNReal.ofReal (roundFailure rho width K) ^ n := by
  induction n with
  | zero => simp [Failed]
  | succ n ih =>
      calc
        _ <= ENNReal.ofReal (roundFailure rho width K)
              * Measure.infinitePi (fun _ => law) (attempts.Failed n) :=
          attempts.round_bound concentrated n
        _ <= ENNReal.ofReal (roundFailure rho width K)
              * ENNReal.ofReal (roundFailure rho width K) ^ n := by
          gcongr
        _ = _ := (pow_succ' _ _).symm

end Attempts

end CCFRaft.Proofs.Duel.Rounds
