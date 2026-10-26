module

public import CCFRaft.Proofs.Leadership.InitRaise
public import CCFRaft.Liveness.Assumptions.Round

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# A primary of the top term hands over or a round starts

NOT IMPORTED BY `Properties`.

INIT's branch with a primary. At `index` every participant is at or below `term`
and `leader` is its primary. Unless some participant moves past `term` within
`incumbentBound` (a round start), every participant settles under `leader`: each
receives one of its AppendEntries after `index`, which resets its timer, makes it
a follower of `term` and sets `primaryKnown`. That gives an anchored start with
the whole of `participants` as the anchor, within `incumbentBound` of `index`.
A participant's timer was last reset after `time index`, so it stays fresh for
`electionTimeout / 2 - incumbentBound` after the anchored start.
-/

namespace CCFRaft.Proofs.Leadership

open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Liveness (Admissible)
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)
open HasTimers (deadline)

/-- The span from a primary of the top term within which every participant has
settled under it, or a round has started. -/
def incumbentBound (heartbeat maxDelay : Real) : Real :=
  2 * (heartbeat + maxDelay) + maxDelay

variable [Config.InitialConfiguration]
  {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W]
  {trace : Trace W Liveness.Event} {nodes : List NodeID}
  (admissible
    : Admissible (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) trace)

include admissible

/-- A primary of the top term within the INIT span hands over within
`incumbentBound`, or a round starts by then. -/
theorem init_incumbent {electionTimeout maxDelay jump heartbeat duration fresh : Real}
    {start : Nat} {participants members : Finset NodeID}
    (delay : trace.Valid (boundedDelayModel maxDelay))
    (timers : trace.Valid (timerModel electionTimeout))
    (diverges : TimeDiverges trace)
    (heartbeats : trace.HeartbeatScheduling (some heartbeat))
    (nonnegative : 0 <= maxDelay) (heartbeatNonnegative : 0 <= heartbeat)
    (ratio : incumbentBound heartbeat maxDelay < electionTimeout / 2)
    (freshLe : fresh <= electionTimeout / 2 - incumbentBound heartbeat maxDelay)
    (long
      : initRaiseLength electionTimeout maxDelay jump + incumbentBound heartbeat maxDelay
        <= duration)
    (good : GoodPeriod trace start duration participants)
    (active : Window.AnchorActive trace start duration participants)
    (matching : Window.Matching trace start duration participants)
    (membership
      : forall first,
          trace.stateAt start = some first
          -> Membership participants members (proto first))
    (subset : participants ⊆ members)
    (configured
      : forall first,
          trace.stateAt start = some first
          -> ConfigurationCommitted participants (proto first))
    (roled
      : forall first node state,
          trace.stateAt start = some first
          -> node ∈ participants
          -> nodeState (proto first) node = some state
          -> Not (state.role = .none))
    (present : forall node, node ∈ participants -> node ∈ nodes)
    : forall index point leader state term,
        Within trace start (initRaiseLength electionTimeout maxDelay jump) index
        -> Low trace participants index term
        -> trace.stateAt index = some point
        -> leader ∈ participants
        -> nodeState (proto point) leader = some state
        -> state.currentTerm = term
        -> state.role = .primary
        -> HandoffBy trace participants index (incumbentBound heartbeat maxDelay) fresh
            \/ exists c after,
                index <= c
                /\ trace.stateAt c = some after
                /\ time after <= time point + incumbentBound heartbeat maxDelay
                /\ RoundStart trace participants c term := by
  sorry

end CCFRaft.Proofs.Leadership
