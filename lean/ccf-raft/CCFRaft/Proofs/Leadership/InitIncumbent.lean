module

public import CCFRaft.Proofs.Leadership.InitRaise
public import CCFRaft.Proofs.Leadership.InitEligible
public import CCFRaft.Proofs.Leadership.InitIncumbentHandoff
public import CCFRaft.Liveness.Assumptions.Round

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# A primary of the top term hands over or a round starts

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
  (admissible : Admissible Config.INITIAL_CONFIGURATION nodes trace)

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
    (roled
      : forall first node state,
          trace.stateAt start = some first
          -> node ∈ participants
          -> nodeState (proto first) node = some state
          -> Not (state.role = .none))
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
  classical
  intro index point leader state term initialWithin initialLow found leaderIn nodeFound stateTerm primary
  let bound := incumbentBound heartbeat maxDelay
  have boundEq : bound = 2 * (heartbeat + maxDelay) + maxDelay := rfl
  by_cases round : exists c after,
      index <= c /\ trace.stateAt c = some after
        /\ time after <= time point + bound /\ RoundStart trace participants c term
  · exact Or.inr round
  apply Or.inl
  have widen : forall {later}, Within trace index bound later ->
      Within trace start duration later := by
    intro later within
    refine ⟨initialWithin.1.trans within.1, fun first last firstFound lastFound => ?_⟩
    have initialTime := initialWithin.2 first point firstFound found
    have lastTime := within.2 point last found lastFound
    change initRaiseLength electionTimeout maxDelay jump + bound <= duration at long
    linarith
  have low : forall later, Within trace index bound later -> Low trace participants later term := by
    intro later within last node local_ lastFound member localFound
    have noEarlier : forall earlier, index <= earlier -> earlier < later ->
        Not (RoundStart trace participants earlier term) := by
      intro earlier lower upper starts
      obtain ⟨step, _, _, stepped, _, _, _⟩ := starts.raise
      have early := within.2 point last found lastFound
      have timeLe := admissible.time_le upper.le (admissible.before stepped) lastFound
      exact round ⟨earlier, step.before, lower, admissible.before stepped, by linarith, starts⟩
    exact Low.later admissible initialLow within.1 noEarlier last node local_ lastFound member localFound
  have short : GoodPeriod trace index bound participants := {
    participantsLive := fun i p n win => good.participantsLive i p n (widen win)
    quorum := fun i p n s win => good.quorum i p n s (widen win)
    noReconfiguration := fun i s n entries win => good.noReconfiguration i s n entries (widen win)
    noNominations := fun i s n win => good.noNominations i s n (widen win)
    noQuorumChecks := fun i s n win => good.noQuorumChecks i s n (widen win)
    lossless := fun i s p win => good.lossless i s p (widen win)
    isolated := fun i s e win => good.isolated i s e (widen win)
  }
  have activeShort : Window.AnchorActive trace index bound participants :=
    fun i p n s win => active i p n s (widen win)
  have matchingShort : Window.Matching trace index bound participants :=
    fun i s p r n win => matching i s p r n (widen win)
  have membershipShort : forall i p, Within trace index bound i ->
      trace.stateAt i = some p -> Membership participants members (proto p) :=
    fun i p win pf => Membership.window admissible good membership i p (widen win) pf
  have roledShort : forall i p n s, Within trace index bound i ->
      trace.stateAt i = some p -> n ∈ participants ->
      nodeState (proto p) n = some s -> Not (s.role = .none) := by
    intro i p n s win pf member sf
    exact roled_window admissible active member
      (fun f local_ ff nf => roled f n local_ ff member nf) (widen win) pf sf
  exact InitIncumbent.handoff_capped admissible delay timers diverges heartbeats
    nonnegative heartbeatNonnegative (by linarith) (by linarith) ratio freshLe
    short activeShort matchingShort membershipShort subset leaderIn roledShort low
    found nodeFound stateTerm primary

end CCFRaft.Proofs.Leadership
