module

public import CCFRaft.Liveness.Assumptions.Duel
public import Mathlib.Probability.ProductMeasure

@[expose] public section

/-!
# Draft: the attempts interface

DRAFT FOR REVIEW, NOT IMPORTED BY `Properties`; every proof is `sorry`.

The deterministic part of the duel supplies `Attempts`; `attempts_bound` turns it
into a probability. Whether a draw is relevant to round `k`, and the deadlines it
must avoid, are decided by the draws before it, so an adaptive re-draw is just
another relevant draw. Every relevant draw then lands within `margin` of one of
`width` known centres with probability at most `width * (4 * margin / E)` given
everything before it, and a round with at most `K` relevant draws fails with
probability at most `K * width * (4 * margin / E)` given everything before it.
-/

namespace CCFRaft.Proofs.Duel.Rounds

open MeasureTheory Set
open CCFRaft.Liveness (uniform)

/-- `Adaptive.Sample`: the offset drawn by the `j`-th participant reset. -/
abbrev Sample := Nat -> Real

set_option warn.classDefReducibility false in
/-- The draws before `j`. -/
def revealed (j : Nat) : MeasurableSpace Sample :=
  MeasurableSpace.comap (fun sample (i : Iio j) => sample i) MeasurableSpace.pi

/-- Rounds of predictable relevant draws. If every relevant draw of some round
keeps more than `margin` from its centres, the event holds. -/
structure Attempts (E margin : Real) (width rounds K : Nat) (Good : Set Sample) where
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
  forces
    : forall sample,
        (forall j, sample j ∈ Icc (E / 2) E)
        -> (exists k,
              k < rounds
              /\ forall j,
                  relevant k j sample
                  -> forall i, margin < |sample j - centres k j sample i|)
        -> sample ∈ Good

/-- One round fails with probability at most `q` given the earlier rounds. -/
noncomputable def roundFailure (E margin : Real) (width K : Nat) : Real :=
  K * width * (4 * margin / E)

/-- `Measure.infinitePi` is `Adaptive.sampleMeasure`. -/
theorem attempts_bound {E margin : Real} {width rounds K : Nat} {Good : Set Sample}
    (positive : 0 < E) (nonnegative : 0 <= margin)
    (attempts : Attempts E margin width rounds K Good)
    : ENNReal.ofReal (1 - roundFailure E margin width K ^ rounds)
      <= Measure.infinitePi (fun _ => uniform E) Good := by
  sorry

end CCFRaft.Proofs.Duel.Rounds
