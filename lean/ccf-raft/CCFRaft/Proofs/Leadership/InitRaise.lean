module

public import CCFRaft.Proofs.Leadership.InitTerms
public import CCFRaft.Proofs.Leadership.FirstReset
public import CCFRaft.Proofs.Leadership.InitRaiseFinish
public import CCFRaft.Liveness.Assumptions.Anchor

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Without a primary, the top term is raised

INIT's branch without a primary. At `start` every participant is at or below
`term` and one is at it, and in the window no participant is primary at `term`.
Then a participant moves past `term` within `initRaiseLength`, and the first such
step starts a round.

The argument runs in phases, from `T0 = time start`.
- AppendEntries requests of `term` were all sent before `start`, so they arrive
  by `T0 + d`.
- Some participant at `term` broadcasts a request of `term` (a pre-vote on its
  timeout, or a vote as a new candidate) by `T0 + d + E + J`: until then only
  in-flight packets reset its timer. By one delay later every participant is at
  `term` or past it.
- Vote requests of `term` from candidates created before then arrive one delay
  later still. After that, a participant's timer resets only on its own timeout,
  its log is frozen, and every participant times out within `E + J`, after which
  none knows a primary.
- The participant with the most up-to-date log then times out within `E + J`
  more. Every participant grants its pre-vote, and with `4d < E` the responses
  arrive before it can time out again, so it gathers a quorum and moves past
  `term`.
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

/-- The span from `start` within which the top term is raised. -/
def initRaiseLength (electionTimeout maxDelay jump : Real) : Real :=
  3 * electionTimeout + 3 * jump + 5 * maxDelay

variable [Config.InitialConfiguration]
  {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W]
  {trace : Trace W Liveness.Event} {nodes : List NodeID}
  (admissible : Admissible Config.INITIAL_CONFIGURATION nodes trace)

include admissible

/-- Without a primary of the top term, some participant moves past it within
`initRaiseLength`, and the first such step starts a round. -/
theorem init_raise {electionTimeout maxDelay jump duration : Real} {start : Nat}
    {participants members : Finset NodeID} {term : Nat}
    (delay : trace.Valid (boundedDelayModel maxDelay))
    (timers : trace.Valid (timerModel electionTimeout))
    (diverges : TimeDiverges trace)
    (firing
      : forall node,
          node ∈ participants
          -> Scheduled trace (some 0) (fun point => TimeoutDue point node)
              (fun step => step.action = .local node (.timeout .election)))
    (overshoot
      : forall index step node,
          node ∈ participants
          -> Within trace start duration index
          -> trace.stepAt index = some step
          -> NoOvershoot (some jump) step node)
    (nonnegative : 0 <= maxDelay) (jumpNonnegative : 0 <= jump)
    (ratio : 4 * maxDelay < electionTimeout)
    (long : initRaiseLength electionTimeout maxDelay jump <= duration)
    (good : GoodPeriod trace start duration participants)
    (subset : participants ⊆ members)
    (ready
      : forall index point node state,
          Within trace start duration index
          -> trace.stateAt index = some point
          -> node ∈ participants
          -> nodeState (proto point) node = some state
          -> state.activeMembers = members
              /\ (Not (state.role = .primary) -> canStartElection state node))
    (low : Low trace participants start term)
    (top
      : exists first node state,
          trace.stateAt start = some first
          /\ node ∈ participants
          /\ nodeState (proto first) node = some state
          /\ state.currentTerm = term)
    (noLeader
      : forall index point node state,
          Within trace start (initRaiseLength electionTimeout maxDelay jump) index
          -> Low trace participants index term
          -> trace.stateAt index = some point
          -> node ∈ participants
          -> nodeState (proto point) node = some state
          -> state.currentTerm = term
          -> Not (state.role = .primary))
    : exists c first point,
        start <= c
        /\ trace.stateAt start = some first
        /\ trace.stateAt c = some point
        /\ time point <= time first + initRaiseLength electionTimeout maxDelay jump
        /\ RoundStart trace participants c term := by
  classical
  obtain ⟨first, topNode, topState, firstFound, topIn, topFound, topTerm⟩ := top
  let L := initRaiseLength electionTimeout maxDelay jump
  have lengthEq : L = 3 * electionTimeout + 3 * jump + 5 * maxDelay := rfl
  have positive : 0 <= electionTimeout := by linarith
  have widen : forall {index}, Within trace start L index
      -> Within trace start duration index := by
    intro index within
    refine ⟨within.1, fun origin point originFound found => ?_⟩
    have early := within.2 origin point originFound found
    change L <= duration at long
    linarith
  have withinTime : forall index point, start <= index
      -> trace.stateAt index = some point -> time point <= time first + L
      -> Within trace start L index := by
    intro index point lower found early
    refine ⟨lower, fun first' point' firstFound' found' => ?_⟩
    rw [firstFound, Option.some.injEq] at firstFound'
    rw [found, Option.some.injEq] at found'
    subst first' point'
    exact early
  by_contra noRound
  have lowAll : forall index, Within trace start L index -> Low trace participants index term := by
    intro index within point node state found member nodeFound
    have noEarlier : forall earlier, start <= earlier -> earlier < index
        -> Not (RoundStart trace participants earlier term) := by
      intro earlier lower upper round
      obtain ⟨step, _, _, stepped, _, _, _⟩ := round.raise
      have timeLe := admissible.time_le upper.le (admissible.before stepped) found
      have bound := within.2 first point firstFound found
      exact noRound ⟨earlier, first, step.before, lower, firstFound,
        admissible.before stepped, by change time step.before <= time first + L; linarith, round⟩
    exact Low.later admissible low within.1 noEarlier point node state found member nodeFound
  have short : GoodPeriod trace start L participants := {
    participantsLive := fun i p n win => good.participantsLive i p n (widen win)
    quorum := fun i p n s win => good.quorum i p n s (widen win)
    noReconfiguration := fun i s n entries win => good.noReconfiguration i s n entries (widen win)
    noNominations := fun i s n win => good.noNominations i s n (widen win)
    noQuorumChecks := fun i s n win => good.noQuorumChecks i s n (widen win)
    lossless := fun i s p win => good.lossless i s p (widen win)
    isolated := fun i s e win => good.isolated i s e (widen win)
  }
  have readyShort := fun index point node state (within : Within trace start L index) =>
    ready index point node state (widen within)
  have readyCan := fun index point node state within found member nodeFound =>
    (readyShort index point node state within found member nodeFound).2
  have noLeaderShort := fun index point node state (within : Within trace start L index) =>
    noLeader index point node state within (lowAll index within)
  have overshootShort := fun index step node member (within : Within trace start L index) =>
    overshoot index step node member (widen within)
  obtain ⟨activityIndex, activityPoint, activityLower, activityFound, activityEarly, activity⟩ :=
    InitRaise.first_activity admissible delay timers diverges nonnegative
      (by linarith : maxDelay + electionTimeout + jump <= L) short firing overshootShort
      readyCan lowAll noLeaderShort firstFound topFound topTerm topIn (by linarith)
  have activityWithin := withinTime activityIndex activityPoint activityLower activityFound (by linarith)
  obtain ⟨converged, convergence, afterActivity, convergenceAt, convergenceNear, _, adopted⟩ :=
    InitRaise.activity_converges admissible delay diverges short subset readyShort noLeaderShort lowAll
      firstFound activityWithin activityFound activityEarly nonnegative
      (by linarith : time first + maxDelay + electionTimeout + jump + maxDelay <= time first + L)
      activity
  have convergenceFound := admissible.before convergenceAt
  have convergenceLower : start <= converged := by omega
  let resetLimit := time first + electionTimeout + jump + 3 * maxDelay
  obtain ⟨resetIndex, resetCross, afterConvergence, resetAt, resetNear, resetFar⟩ :=
    InitRaise.boundary admissible diverges convergenceFound
      (by dsimp [resetLimit]; linarith : time convergence.before <= resetLimit)
  have resetFound := admissible.before resetAt
  have resetLower : start <= resetIndex := by omega
  have resetWithin := withinTime resetIndex resetCross.before resetLower resetFound
    (by dsimp [resetLimit] at resetNear; linarith)
  have resetAdopted : forall node, node ∈ participants -> exists state,
      nodeState (proto resetCross.before) node = some state /\ state.currentTerm = term := by
    intro node member
    obtain ⟨state, stateFound, stateTerm⟩ := adopted node member
    exact InitRaise.top_stays admissible convergenceFound stateFound stateTerm member
      afterConvergence resetFound (lowAll resetIndex resetWithin)
  have resetsAfter : forall index step node, resetIndex <= index
      -> Within trace start L index -> trace.stepAt index = some step
      -> node ∈ participants -> ElectionReset step node
      -> step.action = .local node (.timeout .election) := by
    intro index step node lower within stepped member reset
    exact InitRaise.reset_is_timeout admissible delay short firstFound convergenceFound adopted
      readyCan noLeaderShort lowAll resetAt resetNear resetFar
      (by dsimp [resetLimit]; linarith) (by dsimp [resetLimit]; linarith)
      lower (by omega) within stepped member reset
  have oldAfter : forall index step packet request, resetIndex <= index
      -> Within trace start L index -> trace.stepAt index = some step
      -> step.action = .deliver packet -> packet.envelope.target ∈ participants
      -> packet.envelope.payload = .appendEntriesRequest request -> request.term < term := by
    intro index step packet request lower within stepped delivered member payload
    exact InitRaise.append_old_after admissible delay short firstFound readyCan noLeaderShort
      (lowAll index within) resetAt resetNear resetFar
      (by dsimp [resetLimit]; linarith) lower within stepped delivered member payload
  obtain ⟨clearedIndex, clearedCross, afterReset, clearedAt, clearedNear, _, cleared⟩ :=
    InitRaise.clear_by admissible timers diverges positive jumpNonnegative short firstFound
      resetLower resetFound resetNear
      (by dsimp [resetLimit]; linarith : resetLimit + electionTimeout + jump <= time first + L)
      resetAdopted firing overshootShort readyCan noLeaderShort lowAll resetsAfter oldAfter
  have clearedFound := admissible.before clearedAt
  have clearedLower : start <= clearedIndex := by omega
  obtain ⟨winner, winnerState, winnerIn, winnerFound, best⟩ :=
    InitRaise.best_log admissible clearedFound ⟨topNode, topIn⟩
      (fun node member => by
        obtain ⟨state, stateFound, _, _⟩ := cleared node member
        exact ⟨state, stateFound⟩)
  have winnerTerm : winnerState.currentTerm = term := by
    obtain ⟨state, stateFound, stateTerm, _⟩ := cleared winner winnerIn
    rw [winnerFound, Option.some.injEq] at stateFound
    subst state
    exact stateTerm
  exact InitRaise.win_after_clear admissible delay timers diverges nonnegative
    jumpNonnegative ratio short subset firstFound clearedLower clearedFound clearedNear
    (by dsimp [resetLimit]; linarith
      : resetLimit + electionTimeout + jump + electionTimeout + jump + 2 * maxDelay
        <= time first + L)
    winnerFound winnerTerm winnerIn cleared best firing overshootShort readyShort
    noLeaderShort lowAll
    (fun index step node lower within stepped member reset =>
      resetsAfter index step node (by omega) within stepped member reset)
    (fun index step packet request lower within stepped delivered member payload =>
      oldAfter index step packet request (by omega) within stepped delivered member
        payload)

end CCFRaft.Proofs.Leadership
