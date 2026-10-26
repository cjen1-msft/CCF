module

public import Mathlib.MeasureTheory.Measure.Lebesgue.Basic

@[expose] public section

/-!
# Duelling leaders

The random part of an election is the remaining time a node draws when it resets
its election timer (`raft.h`, `restart_election_timeout`).
`Properties.duelling_leaders_resolve` lets a measurable policy choose everything
else around the draws (`Liveness.Policy`, `Liveness.run`) and needs of the draw
only a `Law`: at most `rho` on any interval of radius `margin`. A round fails with
probability at most `roundFailure` given the earlier rounds.
-/

namespace CCFRaft.Liveness

/-- Continuous idealization of the remaining-time draw in
`raft.h`, `restart_election_timeout`, uniform on
`[electionTimeout / 2, electionTimeout]`. Concrete CCF uses integer milliseconds
and elapsed ticks; correspondence with these real-time offsets is not proved. -/
noncomputable def uniform (electionTimeout : Real) : MeasureTheory.Measure Real :=
  ((2 / electionTimeout).toNNReal : NNReal)
  • MeasureTheory.volume.restrict (Set.Icc (electionTimeout / 2) electionTimeout)

/-- What the duel needs of the remaining-time law: a probability measure on
`[E / 2, E]` that puts at most `rho` on any interval of radius `margin`.

The continuous uniform law on `[E / 2, E]` satisfies it with
`rho = 4 * margin / E` (`Rounds.uniform_law`). CCF's actual draw, the remaining
time uniform on the whole milliseconds `{E / 2, ..., E}` (`raft.h`
`restart_election_timeout`), satisfies it with
`rho = (2 * margin + 1) / (E / 2 + 1)` (`Rounds.ccf_law`), which at the duel's
`margin = 4 * maxDelay` is `(8 * maxDelay + 1) / (E / 2 + 1)`: an interval of width
`8 * maxDelay` holds at most `floor (8 * maxDelay) + 1` whole milliseconds. So the
statement covers CCF's discrete draw, not only a continuous idealisation. -/
structure Law (E margin rho : Real) (law : MeasureTheory.Measure Real) : Prop where
  probability : MeasureTheory.IsProbabilityMeasure law
  support : law (Set.Icc (E / 2) E)ᶜ = 0
  nonnegative : 0 <= rho
  concentrated : forall x, law (Set.Icc (x - margin) (x + margin)) <= ENNReal.ofReal rho

/-- A round with at most `K` relevant draws fails with probability at most this given
the earlier rounds: each draw fails it only by landing near one of `width` centres,
which has probability at most `rho` per centre (`Law`). -/
noncomputable def roundFailure (rho : Real) (width K : Nat) : Real :=
  K * width * rho

end CCFRaft.Liveness
