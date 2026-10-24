module

public import CCFRaft.Proofs.Leadership.Stable
public import CCFRaft.Proofs.Leadership.Membership
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
election timer, so no participant of the term times out in the window, and by
`QuietAmong.step` the term stays quiet among participants at every recorded
state of the window. Isolation keeps non-participants from reaching
participants, so they are unconstrained.

The primary tracks every participant because each is in its latest
configuration at the start, and a primary of a quiet term appending no
configuration keeps its latest configuration (`QuietAmong.history_keep`).

`WindowMatching`, the windowed form of `Matching`, and `LatestMembers` are
proposed as premises of `Properties.signature_settles`.
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

/-- At `start` every participant other than the primary is in the primary's
latest active configuration, and so is one of its replication peers. -/
def LatestMembers (trace : Trace W Liveness.Event) (start : Nat) (leader : NodeID)
    (participants : Finset NodeID)
    : Prop :=
  forall first state node,
    trace.stateAt start = some first
    -> nodeState (proto first) leader = some state
    -> node ∈ participants
    -> Not (node = leader)
    -> node ∈ latestConfigurationMembers state.activeConfigurations

/-- `QuietStart` among `participants`, with a freshness `fresh` in place of half
an election timeout: the term is quiet among participants at `start`, and no
participant of the term times out before `fresh` after it. An election spreads
the participants' timer resets over a few message delays, so the duel that ends
in `start` can only promise some `fresh` below `electionTimeout / 2`. -/
structure FreshStart (trace : Trace W Liveness.Event) (start : Nat) (leader : NodeID)
    (term : Nat) (participants : Finset NodeID) (fresh : Real)
    : Prop where
  quiet
    : exists first,
        trace.stateAt start = some first
        /\ QuietAmong participants leader term (proto first)
  timers
    : forall first index step node state,
        trace.stateAt start = some first
        -> start <= index
        -> trace.stepAt index = some step
        -> step.action = .local node (.timeout .election)
        -> nodeState (proto step.before) node = some state
        -> node ∈ participants
        -> state.currentTerm = term
        -> time first + fresh <= time step.before

omit [HasLive W] [HasNetwork W] in
/-- A quiet start is fresh for half an election timeout among any participants. -/
theorem FreshStart.of_quietStart {trace : Trace W Liveness.Event} {start : Nat}
    {leader : NodeID} {term : Nat} {electionTimeout : Real}
    (initial : QuietStart trace start leader term electionTimeout)
    (participants : Finset NodeID)
    : FreshStart trace start leader term participants (electionTimeout / 2) := by
  obtain ⟨first, found, quiet⟩ := initial.quiet
  exact ⟨⟨first, found, quiet.among participants⟩,
    fun first index step node state found afterStart stepped event nodeFound _ current =>
      initial.timers first index step node state found afterStart stepped event nodeFound
        current⟩

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
  refine ⟨
    exit,
    step,
    by omega,
    before,
    stepped,
    pending_deadline bounded exitFound exitMember exitLive,
    ?_
  ⟩
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
              (within_of_le admissible within lastFound (by omega) before.le) stepped
              action ⟨source, target⟩).elim
  | _ =>
      rw [action] at consumed
      simp [Event.consumedPacket] at consumed

end Trace

private theorem local_of_internal {event : Liveness.Event} {action : Model.Action}
    {actor : NodeID} {localEvent : Model.Node.Event} {input : Input}
    (selected : event.action = some action) (acts : Acts action actor localEvent)
    (internal : localEvent = .internal input)
    : event = .local actor input := by
  cases action with
  | «local» node input' =>
      obtain ⟨actorEq, eventEq⟩ := acts
      rw [eventEq] at internal
      cases internal
      rw [actorEq]
      cases event <;> simp_all [Liveness.Event.action]
  | deliver envelope =>
      obtain ⟨_, eventEq⟩ := acts
      rw [eventEq] at internal
      cases internal

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
  exact Or.inr
    (Or.inr
      (matching delivery deliveryStep packet _ targetState
        (windowed delivery (by omega) deliveryBefore.le) deliveredAt deliverEq source
        (target ▸ nodeIn) payload targetFound (by omega) candidate preVote))

/-- While `leader` leads `term` and a tracked participant stays within `term`, the
participant does not time out in the window at least `fresh` after the start,
where `fresh` exceeds the reset period and is at most half an election timeout. -/
theorem window_no_timeout {bounds : Bounds} {maxDelay : Real}
    (heartbeats : trace.HeartbeatScheduling (some bounds.heartbeatInterval))
    (elections : trace.ElectionScheduling (some (bounds.electionTimeout / 2)))
    (bounded : trace.Valid (boundedDelayModel maxDelay)) (nonneg : 0 <= maxDelay)
    {fresh : Real} (ratio : bounds.heartbeatInterval + maxDelay < fresh)
    (freshLe : fresh <= bounds.electionTimeout / 2)
    {start : Nat} {duration : Real} {leader node : NodeID} {term : Nat}
    {participants : Finset NodeID}
    (good : GoodPeriod trace start duration participants)
    (active : Window.StaysActive trace start duration leader)
    (matching : WindowMatching trace start duration leader term participants)
    (leaderIn : leader ∈ participants) (nodeIn : node ∈ participants)
    {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (afterStart : start <= index) (stepped : trace.stepAt index = some step)
    (within : Within trace start duration index)
    (event : step.action = .local node (.timeout .election))
    {first : W} (firstFound : trace.stateAt start = some first)
    (late : time first + fresh <= time step.before)
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
    : False := by
  have follows := window_reset_follows admissible heartbeats bounded nonneg good active
    matching leaderIn nodeIn (admissible.before stepped) within leads nodeTerm tracked
  obtain ⟨reset, resetPoint, _, before, resetFound, recent, resetStep, resetStepped, isReset⟩ :=
    recent_reset
      (fun _ _ _ _ le firstFound lastFound => admissible.time_le le firstFound lastFound)
      ratio afterStart firstFound (admissible.before stepped) late
      (reset := fun later =>
        exists reset, trace.stepAt later = some reset /\ ElectionReset reset node)
      (fun earlier point after le recorded early => by
        obtain ⟨later, reset, after, resetStepped, inTime, isReset⟩ :=
          follows earlier point after le recorded early
        exact ⟨later, reset.before, after, admissible.before resetStepped, inTime,
          reset, resetStepped, isReset⟩)
  have := elections reset index resetStep step node before resetStepped stepped event isReset
  rw [admissible.before resetStepped, Option.some.injEq] at resetFound
  rw [← resetFound] at recent
  linarith

/-- The primary's state, if any, has every participant other than itself in the
latest configuration of its log. -/
def MembersAt (participants : Finset NodeID) (leader : NodeID) (state : Model.State)
    : Prop :=
  forall local_,
    nodeState state leader = some local_
    -> forall node,
        node ∈ participants
        -> Not (node = leader)
        -> node ∈ latestConfigurationMembers (configurationHistory local_.log)

/-- The primary of a term quiet among participants, at a recorded state. -/
theorem quietAmong_leader {participants : Finset NodeID} {leader : NodeID}
    {term index : Nat} {point : W} (found : trace.stateAt index = some point)
    (quiet : QuietAmong participants leader term (proto point))
    : exists state,
        nodeState (proto point) leader = some state
        /\ state.role = .primary
        /\ state.currentTerm = term := by
  obtain ⟨_, exec⟩ := history_at admissible found
  obtain ⟨local_, now, primary, termEq⟩ := quiet.leader
  exact ⟨local_, found_of_now exec now, primary, termEq⟩

/-- From a fresh start, the term stays quiet among participants, and the
primary's latest configuration keeps every participant, at every recorded state
of a good period in which the primary stays active and its AppendEntries pass
participants' log checks. -/
theorem window_invariant {bounds : Bounds} {maxDelay : Real}
    (heartbeats : trace.HeartbeatScheduling (some bounds.heartbeatInterval))
    (elections : trace.ElectionScheduling (some (bounds.electionTimeout / 2)))
    (bounded : trace.Valid (boundedDelayModel maxDelay)) (nonneg : 0 <= maxDelay)
    {fresh : Real} (ratio : bounds.heartbeatInterval + maxDelay < fresh)
    (freshLe : fresh <= bounds.electionTimeout / 2)
    {start : Nat} {duration : Real} {leader : NodeID} {term : Nat}
    {participants : Finset NodeID}
    (initial : FreshStart trace start leader term participants fresh)
    (members : LatestMembers trace start leader participants)
    (good : GoodPeriod trace start duration participants)
    (active : Window.StaysActive trace start duration leader)
    (matching : WindowMatching trace start duration leader term participants)
    (leaderIn : leader ∈ participants)
    : forall index point,
        Within trace start duration index
        -> trace.stateAt index = some point
        -> QuietAmong participants leader term (proto point)
            /\ MembersAt participants leader (proto point) := by
  intro index
  induction index using Nat.strong_induction_on with
  | _ index ih =>
      intro point within recorded
      by_cases atStart : index = start
      · subst index
        obtain ⟨first, firstFound, quiet⟩ := initial.quiet
        rw [recorded, Option.some.injEq] at firstFound
        subst first
        refine ⟨quiet, fun local_ found node nodeIn different => ?_⟩
        have member := members point local_ node recorded found nodeIn different
        unfold NodeState.activeConfigurations at member
        rwa [latest_active] at member
      rcases index with _ | index
      · exact absurd (Nat.le_zero.mp within.1) (Ne.symm atStart)
      obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp recorded
      have afterStart : start <= index := by have := within.1; omega
      have windowed
          : forall earlier, start <= earlier -> earlier <= index
              -> Within trace start duration earlier :=
        fun earlier after le => within_of_le admissible within recorded after (by omega)
      have earlier_
          : forall earlier point,
              start <= earlier
              -> earlier <= index
              -> trace.stateAt earlier = some point
              -> QuietAmong participants leader term (proto point)
                  /\ MembersAt participants leader (proto point) :=
        fun earlier point after le found =>
          ih earlier (by omega) point (windowed earlier after le) found
      have indexWithin := windowed index afterStart le_rfl
      obtain ⟨nowQuiet, nowMembers⟩ :=
        earlier_ index step.before afterStart le_rfl (admissible.before stepped)
      rcases selected : step.action.action with _ | action
      · rw [admissible.stutter stepped selected]
        exact ⟨nowQuiet, nowMembers⟩
      obtain ⟨rest, c, acts, _⟩ := ctx_at admissible stepped selected
      have local_ : forall input, c.event = .internal input
          -> step.action = .local c.actor input :=
        fun _ eventEq => local_of_internal selected acts eventEq
      have isolated
          : c.actor ∈ participants
            -> forall source message,
                c.event = .receive source message -> source ∈ participants := by
        intro actorIn source message eventEq
        cases action with
        | «local» node input =>
            obtain ⟨_, eventEq'⟩ := acts
            cases eventEq'.symm.trans eventEq
        | deliver envelope =>
            obtain ⟨actorEq, eventEq'⟩ := acts
            obtain ⟨sourceEq, _⟩ := Model.Node.Event.receive.inj (eventEq'.symm.trans eventEq)
            rw [← sourceEq]
            exact good.isolated index step envelope indexWithin stepped
              (delivered_of_action selected) (actorEq ▸ actorIn)
      have plain
          : forall contents, c.event = .internal (.append contents)
            -> forall content, content ∈ contents
                -> content.metadata.configuration = none :=
        fun contents eventEq =>
          good.noReconfiguration index step c.actor contents indexWithin stepped
            (local_ _ eventEq)
      refine ⟨QuietAmong.step c nowQuiet leaderIn (fun actorIn eventEq => ?_) isolated
        (fun same eventEq =>
          good.noNominations index step leader indexWithin stepped
            (same ▸ local_ _ eventEq))
        (fun same eventEq =>
          good.noQuorumChecks index step leader indexWithin stepped leaderIn
            (same ▸ local_ _ eventEq))
        (fun same =>
          active.notRetired (index + 1) step.after _ within
            (Trace.stateAt_succ_of_stepAt stepped)
            (found_of_now c.exec (same ▸ c.post_now))), ?_⟩
      · have ran
            : (startElection (Capabilities.record c.tr.actor) c.tr.pre c.tr.actor).run {}
              = some (c.tr.post, c.tr.outputs) := by
          have ran := c.tr.ran
          have eventEq' : c.tr.event = .internal (.timeout .election) := eventEq
          rw [eventEq'] at ran
          exact ran
        obtain ⟨_, _, can⟩ := startElection_guard c.tr.actor c.tr.pre {} _ _ ran
        have preLe : c.tr.pre.currentTerm <= term := nowQuiet.terms _ _ c.pre_now actorIn
        show c.tr.pre.currentTerm < term
        by_contra notLt
        have different : Not (c.actor = leader) := by
          intro same
          obtain ⟨local_, lead⟩ := QuietAmong.lead c nowQuiet
          have primary : c.tr.pre.role = .primary := by
            have now : Now (proto step.before :: rest) c.actor local_ := by
              rw [same]
              exact lead.now
            have := lead.primary
            rwa [c.now_pre now] at this
          rcases can.1 with role | role | role <;> rw [role] at primary <;> cases primary
        have timeout := local_ _ eventEq
        obtain ⟨first, firstFound, _⟩ := initial.quiet
        exact window_no_timeout admissible heartbeats elections bounded nonneg ratio freshLe
          good active matching leaderIn actorIn afterStart stepped indexWithin timeout
          firstFound
          (initial.timers first index step c.actor c.tr.pre firstFound afterStart stepped
            timeout c.tr.found actorIn (by omega))
          (fun earlier point after le found =>
            quietAmong_leader admissible found (earlier_ earlier point after le found).1)
          (fun earlier point state after le found nodeFound =>
            (earlier_ earlier point after le found).1.terms _ _
              (Concrete.mem_of_nodeState nodeFound) actorIn)
          (fun earlier point leaderState after le found leaderFound =>
            eligible_of_latest
              ((earlier_ earlier point after le found).2 leaderState leaderFound c.actor
                actorIn different)
              different)
      · intro local_ found node nodeIn different
        have now : Now (proto step.after :: proto step.before :: rest) leader local_ :=
          now_of_found found
        rcases c.now_after now with ⟨same, localEq⟩ | ⟨_, before⟩
        · rw [localEq]
          show node ∈ latestConfigurationMembers (configurationHistory c.post.log)
          rw [QuietAmong.history_keep c nowQuiet leaderIn same.symm
            (isolated (same ▸ leaderIn)) plain]
          exact nowMembers c.pre (same ▸ c.tr.found) node nodeIn different
        · exact nowMembers local_ (found_of_now c.prior before) node nodeIn different

/-- From a fresh start, the term stays quiet among participants at every recorded
state of a good period in which the primary stays active and its AppendEntries
pass participants' log checks, when every participant starts in the primary's
latest configuration. -/
theorem window_quiet {bounds : Bounds} {maxDelay : Real}
    (heartbeats : trace.HeartbeatScheduling (some bounds.heartbeatInterval))
    (elections : trace.ElectionScheduling (some (bounds.electionTimeout / 2)))
    (bounded : trace.Valid (boundedDelayModel maxDelay)) (nonneg : 0 <= maxDelay)
    {fresh : Real} (ratio : bounds.heartbeatInterval + maxDelay < fresh)
    (freshLe : fresh <= bounds.electionTimeout / 2)
    {start : Nat} {duration : Real} {leader : NodeID} {term : Nat}
    {participants : Finset NodeID}
    (initial : FreshStart trace start leader term participants fresh)
    (members : LatestMembers trace start leader participants)
    (good : GoodPeriod trace start duration participants)
    (active : Window.StaysActive trace start duration leader)
    (matching : WindowMatching trace start duration leader term participants)
    (leaderIn : leader ∈ participants)
    : Window.StableLeader trace start duration leader term participants :=
  fun index point within found =>
    (window_invariant admissible heartbeats elections bounded nonneg ratio freshLe initial
      members good active matching leaderIn index point within found).1

/-- A stable window from a fresh start, under the proposed premises of
`Properties.signature_settles`: the live quorum and losslessness come from the
good period, and the election timers from the timer model. -/
theorem stable_window_fresh [HasTimers W] {bounds : Bounds} {maxDelay : Real}
    (timers : trace.Valid (timerModel bounds.electionTimeout))
    (bounded : trace.Valid (boundedDelayModel maxDelay)) (nonneg : 0 <= maxDelay)
    (heartbeats : trace.HeartbeatScheduling (some bounds.heartbeatInterval))
    {fresh : Real} (ratio : bounds.heartbeatInterval + maxDelay < fresh)
    (freshLe : fresh <= bounds.electionTimeout / 2)
    {start : Nat} {duration : Real} {leader : NodeID} {term : Nat}
    {participants : Finset NodeID} (leaderIn : leader ∈ participants)
    (initial : FreshStart trace start leader term participants fresh)
    (members : LatestMembers trace start leader participants)
    (good : GoodPeriod trace start duration participants)
    (active : Window.StaysActive trace start duration leader)
    (matching : WindowMatching trace start duration leader term participants)
    : StableWindow trace start duration leader term participants where
  stableLeader :=
    window_quiet admissible heartbeats
      (Liveness.electionScheduling_of_timerModel admissible.coherent admissible.timing
        timers)
      bounded nonneg ratio freshLe initial members good active matching leaderIn
  staysActive := active
  liveQuorum index point state within found leaderFound :=
    good.quorum index point leader state within found
      (active.live index point within found) leaderFound
  lossless index step packet within stepped dropped := by
    rintro (⟨source, target⟩ | ⟨source, target⟩)
    · exact good.lossless index step packet within stepped dropped ⟨source ▸ leaderIn, target⟩
    · exact good.lossless index step packet within stepped dropped ⟨source, target ▸ leaderIn⟩

/-- `stable_window_fresh` from a quiet start, fresh for half an election timeout. -/
theorem stable_window [HasTimers W] {bounds : Bounds} {maxDelay : Real}
    (timers : trace.Valid (timerModel bounds.electionTimeout))
    (bounded : trace.Valid (boundedDelayModel maxDelay)) (nonneg : 0 <= maxDelay)
    (heartbeats : trace.HeartbeatScheduling (some bounds.heartbeatInterval))
    (ratio : bounds.heartbeatInterval + maxDelay < bounds.electionTimeout / 2)
    {start : Nat} {duration : Real} {leader : NodeID} {term : Nat}
    {participants : Finset NodeID} (leaderIn : leader ∈ participants)
    (initial : QuietStart trace start leader term bounds.electionTimeout)
    (members : LatestMembers trace start leader participants)
    (good : GoodPeriod trace start duration participants)
    (active : Window.StaysActive trace start duration leader)
    (matching : WindowMatching trace start duration leader term participants)
    : StableWindow trace start duration leader term participants :=
  stable_window_fresh admissible timers bounded nonneg heartbeats ratio le_rfl leaderIn
    (FreshStart.of_quietStart initial participants) members good active matching

end Recorded

end CCFRaft.Proofs.Leadership
