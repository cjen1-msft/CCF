module

public import CCFRaft.Liveness.Model
public import CCFRaft.Liveness.Assumptions.Window
public import Mathlib.MeasureTheory.Constructions.Pi
public import Mathlib.MeasureTheory.Measure.Lebesgue.Basic

@[expose] public section

/-!
# Duelling leaders

The random part of an election is the timeout draw. A sample `draws k i` is the
offset competitor `i` draws at its `k`-th timer reset; the rest of the execution
is chosen adversarially around the sample. `Properties.duelling_leaders_resolve`
bounds, under the product of uniform draws, the probability that a primary is
elected and commits a signature of its own term: the margin event `Margin` holds
with probability `(1 - 2 margin / E) ^ n` in each round, independently, and
whenever it holds the round ends the duel.
-/

namespace CCFRaft.Liveness

open Model.Node
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)
open HasTimers (deadline)

/-- One timeout draw per round per competitor: an offset in `[E / 2, E]`. -/
abbrev Draws (competitors rounds : Nat) := Fin rounds -> Fin competitors -> Real

/-- Continuous idealization of the remaining-time draw in
`raft.h`, `restart_election_timeout`, uniform on
`[electionTimeout / 2, electionTimeout]`. Concrete CCF uses integer milliseconds
and elapsed ticks; correspondence with these real-time offsets is not proved. -/
noncomputable def uniform (electionTimeout : Real) : MeasureTheory.Measure Real :=
  ((2 / electionTimeout).toNNReal : NNReal)
  • MeasureTheory.volume.restrict (Set.Icc (electionTimeout / 2) electionTimeout)

/-- Independent uniform draws, one per round per competitor. -/
noncomputable def uniformDraws (competitors rounds : Nat) (electionTimeout : Real)
    : MeasureTheory.Measure (Draws competitors rounds) :=
  MeasureTheory.Measure.pi
    fun _ => MeasureTheory.Measure.pi fun _ => uniform electionTimeout

/-- Some competitor's draw undercuts every other's by more than `margin`. -/
def Margin {competitors : Nat} (draw : Fin competitors -> Real) (margin : Real) : Prop :=
  exists i, forall j, j ≠ i -> draw i + margin < draw j

/-- A lower bound on the probability of `Margin` under `competitors` uniform
draws on `[E / 2, E]`: integrate over the smallest draw. Exact for `0 < competitors`. -/
noncomputable def marginProbability (competitors : Nat) (margin electionTimeout : Real)
    : Real :=
  (1 - 2 * margin / electionTimeout) ^ competitors

/-- A lower bound on the probability that some round of `rounds` has a margin. -/
noncomputable def settleProbability (competitors rounds : Nat)
    (margin electionTimeout : Real)
    : Real :=
  1 - (1 - marginProbability competitors margin electionTimeout) ^ rounds

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasTimers W]

/-- Index `index` is the `count`-th election-timer reset of `node` at or after
`start`, counting from zero. -/
def NthReset (trace : Trace W Event) (node : NodeID) (start count index : Nat) : Prop :=
  start <= index
  /\ (exists step, trace.stepAt index = some step /\ ElectionReset step node)
  /\ Set.ncard
        {earlier |
          start <= earlier
          /\ earlier < index
          /\ exists step, trace.stepAt earlier = some step /\ ElectionReset step node
        }
      = count

/-- The `k`-th reset of competitor `i` after `start` sets its deadline to the
reset's time plus `draws k i`. Later resets, and resets of other nodes, draw
freely within the timer model. -/
def TimerDraws {competitors rounds : Nat} (trace : Trace W Event)
    (candidates : Fin competitors -> NodeID) (draws : Draws competitors rounds)
    (start : Nat)
    : Prop :=
  forall i (k : Fin rounds) index step,
    NthReset trace (candidates i) start k index
    -> trace.stepAt index = some step
    -> deadline step.after (candidates i) = time step.before + draws k i

/-- At `point`, `leader` is the primary of `term` and its committed prefix holds
a signature of `term`: `leader`'s log is authoritative for `term`. -/
def SignedPrimary (point : W) (leader : NodeID) (term : Nat) : Prop :=
  exists state entry,
    CCF.MultiNodeTransitionSystem.nodeState (proto point) leader = some state
    /\ state.role = .primary
    /\ state.currentTerm = term
    /\ entry ∈ state.committedLog
    /\ entry.term = term
    /\ entry.content = .signature

/-- Within the window some primary commits a signature of its own term: the duel
is over. -/
def SignatureCommitted (trace : Trace W Event) (start : Nat) (duration : Real) : Prop :=
  exists index point leader term,
    Within trace start duration index
    /\ trace.stateAt index = some point
    /\ SignedPrimary point leader term

/-- Provisional: the lead a competitor's draw needs so that its pre-vote, vote,
and first heartbeat all land before any rival's timer fires. The proof of
`Properties.duelling_leaders_resolve` fixes the formula. -/
def duelMargin (bounds : Bounds) (maxDelay : Real) : Real :=
  bounds.heartbeatInterval + 5 * maxDelay

/-- Provisional: an upper bound on the real time one round of a duel takes, so
that a good period of `rounds * roundLength` contains `rounds` rounds. -/
def roundLength (bounds : Bounds) (maxDelay : Real) : Real :=
  2 * bounds.electionTimeout + 4 * maxDelay

end CCFRaft.Liveness
