module

public import CCFRaft.Proofs.Duel.RaceWon
public import CCFRaft.Liveness.Assumptions.Anchor
public import CCFRaft.Liveness.Assumptions.Window
public import CCFRaft.Liveness.Assumptions.Round

@[expose] public section

/-!
# One duel round: definitions

The definitions of the deterministic step of the duel; the lemmas are in
`Duel.Round`.

A round of term `term + 1` starts at a raise: at index `c` every participant, and
every packet between participants, is at most `term`, and step `c` moves a
participant past `term` (a candidacy of `term + 1`). Within `electionTimeout +
4 * maxDelay` (plus any overshoot `jump`) the run reaches either an anchored start
or the next round, of `term + 2`. If the round's draws keep a margin, it reaches an
anchored start.

The round runs in three phases.
- By `time c + maxDelay` every participant has adopted `term + 1`: the raiser's
  RequestVote reaches all of them.
- Candidacies of `term + 1` start before that, so any election of `term + 1`
  happens by `time c + 3 * maxDelay`. Its voters then settle on the first
  AppendEntries by `time c + 4 * maxDelay` (`round_elected`).
- Otherwise every participant's deadline is fixed by `time c + 2 * maxDelay`,
  and no participant of `term + 1` times out before `time c + electionTimeout / 2`.
  The first participant that can still win a pre-vote quorum and times out starts
  a race (`Racing.Race`). With a margin the race is won (`Racing.race_won`) and
  the winner's round is elected; without one, its pre-vote completes, or someone
  else raises, within two delays.
-/

namespace CCFRaft.Proofs.Duel.Round

open CCFRaft.Liveness
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)
open HasNetwork (pending)
open HasTimers (deadline)
open CCF.MultiNodeTransitionSystem (nodeState)
open CCFRaft.Proofs.Liveness (Admissible)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W]

/-! ## Definitions -/

omit [HasTimers W] in
/-- `index` is in the round of `term + 1` started at `c`: no participant has moved
past `term + 1` from `c` through `index`. -/
def Capped (trace : Trace W Liveness.Event) (participants : Finset NodeID)
    (c term index : Nat)
    : Prop :=
  c <= index
  /\ forall earlier point node state,
      c <= earlier
      -> earlier <= index
      -> trace.stateAt earlier = some point
      -> node ∈ participants
      -> nodeState (proto point) node = some state
      -> state.currentTerm <= term + 1

omit [HasTime W] [HasLive W] [HasNetwork W] in
open Classical in
/-- The resets of `node` into `term + 1` among the steps `c` to `index - 1`. -/
noncomputable def priorResets (trace : Trace W Liveness.Event) (c index : Nat)
    (node : NodeID) (term : Nat)
    : Nat :=
  ((Finset.Ico c index).filter
    fun earlier =>
      exists step state,
        trace.stepAt earlier = some step
        /\ ElectionReset step node
        /\ nodeState (proto step.after) node = some state
        /\ state.currentTerm = term + 1).card

omit [HasTime W] [HasLive W] [HasNetwork W] in
/-- The round keeps its margin: each of a participant's first two resets into
`term + 1` in the round puts its deadline more than `margin` from every other
participant's. -/
def RoundMargin (trace : Trace W Liveness.Event) (participants : Finset NodeID)
    (c term : Nat) (margin : Real)
    : Prop :=
  forall index step node state,
    Capped trace participants c term index
    -> trace.stepAt index = some step
    -> node ∈ participants
    -> ElectionReset step node
    -> nodeState (proto step.after) node = some state
    -> state.currentTerm = term + 1
    -> priorResets trace c index node term < 2
    -> forall other,
        other ∈ participants
        -> other ≠ node
        -> margin < |deadline step.after node - deadline step.after other|

/-- The round's length without overshoot. -/
def roundLength (electionTimeout maxDelay : Real) : Real :=
  electionTimeout + 4 * maxDelay

/-- Everything a round uses except how far the window reaches past the round start.
Timer firing is at the deadline; a step may overshoot a deadline by at most `jump`. -/
structure RoundBase [Config.InitialConfiguration] (nodes : List NodeID)
    (trace : Trace W Liveness.Event) (electionTimeout maxDelay jump : Real)
    (start : Nat) (duration : Real) (participants members : Finset NodeID) (c term : Nat)
    : Prop where
  admissible
    : Admissible (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) trace
  delay : trace.Valid (boundedDelayModel maxDelay)
  timers : trace.Valid (timerModel electionTimeout)
  diverges : TimeDiverges trace
  firing
    : forall node,
        node ∈ participants
        -> Scheduled trace (some 0) (fun point => TimeoutDue point node)
            (fun step => step.action = .local node (.timeout .election))
  overshoot
    : forall index step node,
        node ∈ participants
        -> Within trace start duration index
        -> trace.stepAt index = some step
        -> NoOvershoot (some jump) step node
  nonnegative : 0 <= maxDelay
  jumpNonnegative : 0 <= jump
  ratio : 4 * maxDelay < electionTimeout / 2
  round : RoundStart trace participants c term
  period : GoodPeriod trace start duration participants
  matching : Window.Matching trace start duration participants
  /-- No participant's retirement commits in the window. Under `Membership`, a
  live participant can become retired-committed only through the model's latch
  across a remove-then-re-add of the node; a rejoined CCF node starts afresh and
  a retired CCF node shuts down. Without this premise a round can fail: a voter
  whose log holds its own committed-elsewhere retirement confirmation above its
  commit index retires on the winner's first AppendEntries (role none, no
  primaryKnown), leaving no settled quorum; a winner retiring this way also
  nominates a successor after its win, breaking the quiet term. -/
  active : Window.AnchorActive trace start duration participants
  startLe : start <= c
  membership
    : forall point,
        trace.stateAt c = some point -> Membership participants members (proto point)
  subset : participants ⊆ members
  /-- Every participant's log holds a configuration at or below its commit index, so
  the participants can campaign from a signed configuration of `members`. Without it
  a round can stall: participants whose only configuration is unsigned never time out,
  and a candidate behind their logs never wins. -/
  configured
    : forall point,
        trace.stateAt c = some point -> ConfigurationCommitted participants (proto point)

/-- Everything a round uses: the base, with the window covering the whole round. -/
structure RoundSetup [Config.InitialConfiguration] (nodes : List NodeID)
    (trace : Trace W Liveness.Event) (electionTimeout maxDelay jump : Real)
    (start : Nat) (duration : Real) (participants members : Finset NodeID) (c term : Nat)
    : Prop
    extends RoundBase nodes trace electionTimeout maxDelay jump start duration
              participants members c term where
  covers
    : forall origin point,
        trace.stateAt start = some origin
        -> trace.stateAt c = some point
        -> time point + roundLength electionTimeout maxDelay + jump + 4 * maxDelay
            <= time origin + duration

end CCFRaft.Proofs.Duel.Round
