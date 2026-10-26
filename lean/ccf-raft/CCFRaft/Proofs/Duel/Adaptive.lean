module

public import CCFRaft.Proofs.Duel.Support
public import CCFRaft.Liveness.Model.Policy
public import Mathlib.Probability.ProductMeasure

@[expose] public section

/-!
# The sample measure

NOT IMPORTED BY `Properties`. The policy model of the duel (`Liveness.Policy`,
`Liveness.run`) is in `Liveness/Model/Policy.lean`; the statement is in
`Duel.Resolve`. Here, the measure of independent uniform draws.
-/

namespace CCFRaft.Proofs.Duel.Adaptive

open CCFRaft.Liveness MeasureTheory Set

/-- Independent uniform offsets, one per reset. -/
noncomputable def sampleMeasure (E : Real) : Measure Sample :=
  Measure.infinitePi fun _ => uniform E

end CCFRaft.Proofs.Duel.Adaptive
