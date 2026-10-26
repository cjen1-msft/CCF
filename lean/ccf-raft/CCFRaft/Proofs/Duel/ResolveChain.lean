module

public import CCFRaft.Proofs.Duel.DuelRound
public import CCFRaft.Proofs.Duel.Relevance

@[expose] public section

/-!
# Chaining duel rounds

NOT IMPORTED BY `Properties`. The deterministic part of `Resolve`: from a round start
within the initial phase, rounds follow one another (`Round.duel_round`), each within
a round length plus any overshoot. If at most `overshoots` steps overshoot, and each
of `overshoots + 1` blocks of `rounds` rounds has a round that keeps its margin, some
such round has no overshoot and ends in an anchored start (`chain`).
-/

namespace CCFRaft.Proofs.Duel.Resolve

open CCFRaft.Liveness
open CCFRaft.Proofs.Duel.Adaptive (InRound FirstRound)
open CCFRaft.Proofs.Duel.Round (HandoffBy RoundMargin roundLength)
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open CCFRaft.Proofs.Liveness (Admissible)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W]

/-- The window: the initial phase, `(overshoots + 1) * rounds` round lengths, an
overshoot per block, and four delays for the last round's handoff. -/
def window (initial electionTimeout maxDelay jump : Real) (overshoots rounds : Nat)
    : Real :=
  initial
  + (overshoots + 1) * rounds * roundLength electionTimeout maxDelay
  + (overshoots + 1) * jump
  + 4 * maxDelay

/-- Everything the duel needs of one run, over the window from `start`. -/
structure Setup [Config.InitialConfiguration] (nodes : List NodeID)
    (trace : Trace W Liveness.Event) (initial electionTimeout maxDelay jump fresh : Real)
    (overshoots start : Nat) (duration : Real) (participants members : Finset NodeID)
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
  /-- At most `overshoots` steps of the window overshoot a deadline, each by at most
  `jump`. -/
  overshoot
    : exists bad : Finset Nat,
        bad.card <= overshoots
        /\ forall index step node,
            node ∈ participants
            -> Within trace start duration index
            -> trace.stepAt index = some step
            -> NoOvershoot (some (if index ∈ bad then jump else 0)) step node
  nonnegative : 0 <= maxDelay
  jumpNonnegative : 0 <= jump
  ratio : 4 * maxDelay < electionTimeout / 2
  /-- The initial phase: within `initial` of `start`, an anchored start or a round
  start (`Leadership.init` from a configured good period). -/
  initialPhase
    : HandoffBy trace participants start initial fresh
      \/ exists c term origin point,
          start <= c
          /\ trace.stateAt start = some origin
          /\ trace.stateAt c = some point
          /\ time point <= time origin + initial
          /\ RoundStart trace participants c term
  period : GoodPeriod trace start duration participants
  matching : Window.Matching trace start duration participants
  /-- As `Round.RoundSetup.active`. -/
  active : Window.AnchorActive trace start duration participants
  membership
    : forall point,
        trace.stateAt start = some point -> Membership participants members (proto point)
  subset : participants ⊆ members

/-- `c` starts round `k`, of `term + 1`, counting from the first round start at or
after `start`. -/
def RoundAt (trace : Trace W Liveness.Event) (participants : Finset NodeID)
    (start k c term : Nat)
    : Prop :=
  RoundStart trace participants c term /\ InRound trace participants start k c

/-- If every block of rounds has a round that keeps its margin, the run reaches an
anchored start in the window. -/
theorem chain [Config.InitialConfiguration] {nodes : List NodeID}
    {trace : Trace W Liveness.Event}
    {initial electionTimeout maxDelay jump fresh : Real} {overshoots rounds start : Nat}
    {participants members : Finset NodeID}
    (setup
      : Setup nodes trace initial electionTimeout maxDelay jump fresh overshoots start
          (window initial electionTimeout maxDelay jump overshoots rounds) participants
          members)
    (freshLe : fresh <= electionTimeout / 2 - 4 * maxDelay)
    (margined
      : forall block,
          block < overshoots + 1
          -> exists k,
              k < rounds
              /\ forall c term,
                  RoundAt trace participants start (block * rounds + k) c term
                  -> RoundMargin trace participants c term (4 * maxDelay))
    : HandoffBy trace participants start
        (window initial electionTimeout maxDelay jump overshoots rounds) fresh := by
  sorry

end CCFRaft.Proofs.Duel.Resolve
