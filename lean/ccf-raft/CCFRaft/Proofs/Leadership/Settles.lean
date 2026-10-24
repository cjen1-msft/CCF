module

public import CCFRaft.Proofs.Leadership.Stable
public import CCFRaft.Proofs.Liveness.Delay
public import CCFRaft.Proofs.Liveness.Timers
public import CCFRaft.Liveness.Assumptions.Window

@[expose] public section

/-!
# A stable window from timing

The windowed analogue of `Proofs.Leadership.Stable`. Inside a good period the
primary's AppendEntries to a participant are not dropped, so bounded delay
delivers them within `maxDelay` of their send, as long as the recording reaches
that time. Each delivery that passes the participant's log check resets its
election timer, so no tracked participant of the term times out in the window,
and by `Quiet.step` the term stays quiet at every recorded state of the window.

`WindowMatching` and `WindowCovered` are the windowed forms of `Matching` and
`Covered`, proposed as premises of `Properties.signature_settles`.
-/

namespace CCFRaft.Proofs.Leadership

open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Replication
open CCFRaft.Proofs.StablePrimary
open CCFRaft.Proofs.Liveness (Admissible exists_exit pending_deadline)
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)
open HasNetwork (pending)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]

/-- `Matching` cut to the window and to participants: every AppendEntries request
from the primary delivered in the window to a participant of `term`, other than a
candidate or pre-vote candidate, passes the participant's log check. -/
def WindowMatching (trace : Trace W Liveness.Event) (start : Nat) (duration : Real)
    (leader : NodeID) (term : Nat) (participants : Finset NodeID)
    : Prop :=
  forall index step packet request state,
    Within trace start duration index
    -> trace.stepAt index = some step
    -> step.action = .deliver packet
    -> packet.envelope.source = leader
    -> packet.envelope.target ∈ participants
    -> packet.envelope.payload = .appendEntriesRequest request
    -> nodeState (proto step.before) packet.envelope.target = some state
    -> state.currentTerm = term
    -> Not (state.role = .candidate)
    -> Not (state.role = .preVoteCandidate)
    -> termAt state.log request.prevLogIndex = request.prevLogTerm

/-- `Covered` cut to the window: every node of `term` other than the primary that
times out in the window is a participant, and a replication peer of the primary
from `start` until then. -/
def WindowCovered (trace : Trace W Liveness.Event) (start : Nat) (duration : Real)
    (leader : NodeID) (term : Nat) (participants : Finset NodeID)
    : Prop :=
  forall index step node state,
    Within trace start duration index
    -> trace.stepAt index = some step
    -> step.action = .local node (.timeout .election)
    -> Not (node = leader)
    -> nodeState (proto step.before) node = some state
    -> state.currentTerm = term
    -> node ∈ participants
        /\ forall earlier earlierPoint leaderState,
            start <= earlier
            -> earlier <= index
            -> trace.stateAt earlier = some earlierPoint
            -> nodeState (proto earlierPoint) leader = some leaderState
            -> node ∈ eligiblePeers leaderState leader

section Trace

variable {system : CCF.TransitionSystem Model.State Model.Action}
  {trace : Trace W Liveness.Event} (admissible : Admissible system trace)

include admissible

/-- A recorded index between the start and a recorded index of the window is in
the window. -/
theorem within_of_le {start duration index earlier} {last : W}
    (within : Within trace start duration index)
    (lastFound : trace.stateAt index = some last) (afterStart : start <= earlier)
    (le : earlier <= index)
    : Within trace start duration earlier := by
  refine ⟨afterStart, fun first point firstFound found => ?_⟩
  have := admissible.time_le le found lastFound
  have := within.2 first last firstFound lastFound
  linarith

/-- In a good period, a packet the primary sends a participant in the window is
delivered no later than `maxDelay` after its send, if the recording reaches a
later state of the window past that time. -/
theorem delivered_within {maxDelay : Real}
    (bounded : trace.Valid (boundedDelayModel maxDelay)) (nonneg : 0 <= maxDelay)
    {start : Nat} {duration : Real} {participants : Finset NodeID}
    (good : GoodPeriod trace start duration participants)
    {sent : Nat} {packet : Packet} (sentAt : trace.SentAt sent packet)
    (afterStart : start <= sent) (source : packet.envelope.source ∈ participants)
    (target : packet.envelope.target ∈ participants)
    {index : Nat} {last : W} (lastFound : trace.stateAt index = some last)
    (within : Within trace start duration index)
    (late : packet.sentAt + maxDelay < time last)
    : exists later step,
        sent < later
        /\ later < index
        /\ trace.stepAt later = some step
        /\ time step.before <= packet.sentAt + maxDelay
        /\ step.action = .deliver packet := by
  obtain ⟨_, _, _, emitStepped, _, _, _, _, _, sentTime⟩ := admissible.sentAt_emitted sentAt
  obtain ⟨sendStep, sendStepped, member, _⟩ := sentAt
  rw [sendStepped, Option.some.injEq] at emitStepped
  subst emitStepped
  have targetLive : packet.envelope.target ∈ live last :=
    good.participantsLive index last _ within lastFound target
  have sentBefore : sent < index := by
    by_contra notBefore
    have := admissible.time_le (Nat.le_of_not_lt notBefore) lastFound
      (admissible.before sendStepped)
    linarith
  let Outstanding (position : Nat) : Prop :=
    exists point, trace.stateAt position = some point /\ packet ∈ pending point
  have lastOut : Not (Outstanding index) := by
    rintro ⟨point, found, pendingNow⟩
    rw [lastFound, Option.some.injEq] at found
    subst found
    have := pending_deadline bounded lastFound pendingNow targetLive
    linarith
  obtain ⟨exit, after, before, ⟨exitPoint, exitFound, exitMember⟩, outside⟩ :=
    exists_exit (holds := Outstanding) (Nat.succ_le_of_lt sentBefore)
      ⟨sendStep.after, Trace.stateAt_succ_of_stepAt sendStepped, member⟩ lastOut
  obtain ⟨step, stepped⟩ := Trace.stepAt_of_stateAt_lt before lastFound
  have exitBefore := admissible.before stepped
  rw [exitFound, Option.some.injEq] at exitBefore
  subst exitBefore
  have exitLive : packet.envelope.target ∈ live step.before :=
    admissible.live_anti before.le exitFound lastFound targetLive
  have consumed := admissible.consumed_of_left stepped exitMember fun stillPending =>
    outside ⟨step.after, Trace.stateAt_succ_of_stepAt stepped, stillPending⟩
  refine ⟨exit, step, by omega, before, stepped,
    pending_deadline bounded exitFound exitMember exitLive, ?_⟩
  cases action : step.action with
  | deliver delivered =>
      rw [action] at consumed
      simp only [Event.consumedPacket, Option.some.injEq] at consumed
      rw [consumed]
  | drop dropped =>
      rw [action] at consumed
      simp only [Event.consumedPacket, Option.some.injEq] at consumed
      subst consumed
      exact (good.lossless exit step dropped
        (within_of_le admissible within lastFound (by omega) before.le) stepped action
        ⟨source, target⟩).elim
  | _ =>
      rw [action] at consumed
      simp [Event.consumedPacket] at consumed

end Trace

section Recorded

variable [Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event}
  (admissible
    : Admissible (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) trace)

include admissible

/-- In a good period, while `leader` leads `term` and a tracked participant stays
within `term`, the participant's election timer is reset within
`heartbeatInterval + maxDelay` of every early enough recorded state of the window.
The facts about the leader and the participant are hypotheses, not `Quiet`, so
that the invariant they come from may constrain only some nodes. -/
theorem window_reset_follows {heartbeatInterval maxDelay : Real}
    (heartbeats : trace.HeartbeatScheduling (some heartbeatInterval))
    (bounded : trace.Valid (boundedDelayModel maxDelay)) (nonneg : 0 <= maxDelay)
    {start : Nat} {duration : Real} {leader node : NodeID} {term : Nat}
    {participants : Finset NodeID}
    (good : GoodPeriod trace start duration participants)
    (active : Window.StaysActive trace start duration leader)
    (matching : WindowMatching trace start duration leader term participants)
    (leaderIn : leader ∈ participants) (nodeIn : node ∈ participants)
    {index : Nat} {last : W} (lastFound : trace.stateAt index = some last)
    (within : Within trace start duration index)
    (leads
      : forall earlier point,
          start <= earlier
          -> earlier <= index
          -> trace.stateAt earlier = some point
          -> exists state,
              nodeState (proto point) leader = some state
              /\ state.role = .primary
              /\ state.currentTerm = term)
    (nodeTerm
      : forall earlier point state,
          start <= earlier
          -> earlier <= index
          -> trace.stateAt earlier = some point
          -> nodeState (proto point) node = some state
          -> state.currentTerm <= term)
    (tracked
      : forall earlier point leaderState,
          start <= earlier
          -> earlier <= index
          -> trace.stateAt earlier = some point
          -> nodeState (proto point) leader = some leaderState
          -> node ∈ eligiblePeers leaderState leader)
    : forall earlier point,
        start <= earlier
        -> earlier <= index
        -> trace.stateAt earlier = some point
        -> time point + (heartbeatInterval + maxDelay) < time last
        -> exists later reset,
            earlier < later
            /\ trace.stepAt later = some reset
            /\ time reset.before <= time point + (heartbeatInterval + maxDelay)
            /\ ElectionReset reset node := by
  have windowed
      : forall moment, start <= moment -> moment <= index
          -> Within trace start duration moment :=
    fun moment after le => within_of_le admissible within lastFound after le
  have due
      : forall moment point,
          start <= moment
          -> moment <= index
          -> trace.stateAt moment = some point
          -> PeerDue point leader node := by
    intro moment point after le recorded
    obtain ⟨state, found, primary, _⟩ := leads moment point after le recorded
    exact ⟨active.live moment point (windowed moment after le) recorded,
      good.participantsLive moment point node (windowed moment after le) recorded nodeIn,
      state, found, primary,
      active.notRetired moment point state (windowed moment after le) recorded found,
      tracked moment point state after le recorded found⟩
  intro earlier point afterStart le recorded early
  obtain ⟨later, laterPoint, after, laterFound, inTime, sends⟩ :=
    heartbeats leader node earlier point recorded (due earlier point afterStart le recorded)
  change time laterPoint <= time point + heartbeatInterval at inTime
  have beforeIndex : later < index := by
    by_contra notBefore
    have := admissible.time_le (Nat.le_of_not_lt notBefore) lastFound laterFound
    linarith
  rcases sends with stopped | ⟨sendStep, stepped, batchEnds, event⟩
  · exact (stopped (due later laterPoint (by omega) beforeIndex.le laterFound)).elim
  rw [admissible.before stepped, Option.some.injEq] at laterFound
  subst laterPoint
  obtain ⟨_, _, state, found, _, notRetired, _⟩ :=
    due later sendStep.before (by omega) beforeIndex.le (admissible.before stepped)
  have stateTerm : state.currentTerm = term := by
    obtain ⟨state', found', _, termEq⟩ :=
      leads later sendStep.before (by omega) beforeIndex.le (admissible.before stepped)
    rw [found, Option.some.injEq] at found'
    rw [found']
    exact termEq
  obtain ⟨_, _, _, pass, _⟩ := pass_step admissible stepped event found
  obtain ⟨batch, member⟩ := passBatches_nonempty pass.valid
  obtain ⟨packet, sent, envelope, sentTime⟩ :=
    pass_sends admissible stepped event found notRetired member
  have source : packet.envelope.source = leader := by simp [envelope, batchEnvelope]
  have target : packet.envelope.target = node := by simp [envelope, batchEnvelope]
  have payload : packet.envelope.payload =
      .appendEntriesRequest (makeAppendEntriesRequest state batch.1 batch.2) := by
    simp [envelope, batchEnvelope]
  obtain ⟨delivery, deliveryStep, afterSend, deliveryBefore, deliveredAt, deliveryTime,
      deliverEq⟩ :=
    delivered_within admissible bounded nonneg good sent (by omega) (source ▸ leaderIn)
      (target ▸ nodeIn) lastFound within (by rw [sentTime]; linarith)
  rw [sentTime] at deliveryTime
  refine ⟨delivery, deliveryStep, by omega, deliveredAt, by linarith, ?_⟩
  have selectedDelivery : deliveryStep.action.action = some (.deliver packet.envelope) := by
    rw [deliverEq]; rfl
  obtain ⟨receiver, _, targetState, _, _, targetActs, targetFound, _⟩ :=
    step_found (admissible.reachable_before deliveredAt)
      (admissible.step deliveredAt selectedDelivery)
  obtain ⟨targetEq, _⟩ := targetActs
  rw [targetEq] at targetFound
  rw [ElectionReset, deliverEq]
  refine ⟨target, ?_⟩
  rw [show nodeState (proto deliveryStep.before) node = some targetState by
      simpa only [target] using targetFound]
  apply Or.inr
  rw [payload]
  have termLe := nodeTerm delivery deliveryStep.before targetState (by omega)
    deliveryBefore.le (admissible.before deliveredAt) (by simpa only [target] using targetFound)
  simp only [makeAppendEntriesRequest]
  rcases Nat.lt_or_ge targetState.currentTerm state.currentTerm with lt | ge
  · exact Or.inl lt
  refine Or.inr ⟨by omega, ?_⟩
  by_cases candidate : targetState.role = .candidate
  · exact Or.inl candidate
  by_cases preVote : targetState.role = .preVoteCandidate
  · exact Or.inr (Or.inl preVote)
  exact Or.inr (Or.inr
    (matching delivery deliveryStep packet _ targetState
      (windowed delivery (by omega) deliveryBefore.le) deliveredAt deliverEq source
      (target ▸ nodeIn) payload targetFound (by omega) candidate preVote))

end Recorded

end CCFRaft.Proofs.Leadership
