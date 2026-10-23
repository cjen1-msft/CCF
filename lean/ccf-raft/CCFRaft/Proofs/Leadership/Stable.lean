module

public import CCFRaft.Proofs.Leadership.Quiet
public import CCFRaft.Proofs.Leadership.Timers
public import CCFRaft.Proofs.Replication.Step

@[expose] public section

/-!
# A stable primary from timing

The primary sends every peer a heartbeat within `heartbeatInterval`, and the
heartbeat arrives within `delay`, both measured at the steps' before-times.
Each arrival that passes the peer's log check,
which `Matching` assumes, resets the peer's election timer, and an expired timer
has gone at least half an election timeout without a reset.
So if `heartbeatInterval + delay` is below half the election timeout, no tracked
node of the term times out after `QuietStart`, and by `Quiet.step` the term stays
quiet at every recorded state: the primary keeps its role.
-/

namespace CCFRaft.Proofs.Leadership

open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Replication
open CCFRaft.Proofs.StablePrimary
open CCFRaft.Proofs.Liveness (Admissible)
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)

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

section Trace

variable [Config.InitialConfiguration]
  {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  {nodes : List NodeID} {trace : Trace W Liveness.Event}
  (admissible
    : Admissible (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) trace)

include admissible

theorem quiet_leader {leader : NodeID} {term index : Nat}
    {point : W} (found : trace.stateAt index = some point)
    (quiet : Quiet leader term (proto point))
    : exists state,
        nodeState (proto point) leader = some state
        /\ state.role = .primary
        /\ state.currentTerm = term := by
  obtain ⟨_, exec⟩ := history_at admissible found
  obtain ⟨local_, now, primary, termEq⟩ := quiet.leader
  exact ⟨local_, found_of_now exec now, primary, termEq⟩

/-- While the term stays quiet, a live node the primary tracks has its election
timer reset within `heartbeatInterval + delay` of every sufficiently early
recorded state. Send, delivery and reset times are all step before-times. -/
theorem reset_follows {heartbeatInterval : Real}
    (heartbeats : trace.HeartbeatScheduling (some heartbeatInterval))
    {start index : Nat} {leader node : NodeID} {term : Nat} {delay : Real}
    {last : W} (lastFound : trace.stateAt index = some last)
    (quiet
      : forall earlier point,
          start <= earlier
          -> earlier <= index
          -> trace.stateAt earlier = some point
          -> Quiet leader term (proto point))
    (timely : Timely trace start leader delay) (nonneg : 0 <= delay)
    (matching : Matching trace start leader term)
    (incumbent : Incumbent trace start leader) (alive : node ∈ live last)
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
        -> time point + (heartbeatInterval + delay) < time last
        -> exists later reset,
            earlier < later
            /\ trace.stepAt later = some reset
            /\ time reset.before <= time point + (heartbeatInterval + delay)
            /\ ElectionReset reset node := by
  have due
      : forall moment point,
          start <= moment
          -> moment <= index
          -> trace.stateAt moment = some point
          -> PeerDue point leader node := by
    intro moment point after le recorded
    obtain ⟨state, found, primary, _⟩ :=
      quiet_leader admissible recorded (quiet moment point after le recorded)
    exact ⟨incumbent.live moment point after recorded,
      admissible.live_anti le recorded lastFound alive, state, found, primary,
      incumbent.notRetired moment point state after recorded found,
      tracked moment point state after le recorded found⟩
  intro earlier point afterStart le recorded early
  obtain ⟨later, laterPoint, after, laterFound, within, sends⟩ :=
    heartbeats leader node earlier point recorded (due earlier point afterStart le recorded)
  change time laterPoint <= time point + heartbeatInterval at within
  have beforeIndex : later < index := by
    by_contra notBefore
    have := admissible.time_le (Nat.le_of_not_lt notBefore) lastFound laterFound
    linarith
  rcases sends with stopped | ⟨sendStep, stepped, state, frontier, found, event, _⟩
  · exact (stopped (due later laterPoint (by omega) beforeIndex.le laterFound)).elim
  rw [admissible.before stepped, Option.some.injEq] at laterFound
  subst laterPoint
  have stateTerm : state.currentTerm = term := by
    obtain ⟨state', found', _, termEq⟩ :=
      quiet_leader admissible (admissible.before stepped)
        (quiet later sendStep.before (by omega) beforeIndex.le (admissible.before stepped))
    rw [found, Option.some.injEq] at found'
    rw [found']
    exact termEq
  have selected : sendStep.action.action = some (.local leader (.sendEntries node frontier)) := by
    rw [event]; rfl
  obtain ⟨actor, localEvent, current, next, outputs, acts, actorFound, ran, _, out, _⟩ :=
    step_found (admissible.reachable_before stepped) (admissible.step stepped selected)
  obtain ⟨same, eventEq⟩ := acts
  subst same eventEq
  rw [found, Option.some.injEq] at actorFound
  subst actorFound
  obtain ⟨new, eq, single⟩ := sendEntries_sends actor state node frontier {} _ _ ran
  rw [eq, single] at out
  obtain ⟨packet, sent, envelope, sentTime⟩ :=
    admissible.sentAt_of_emitted stepped selected out
      (List.mem_append_right _ (List.mem_singleton_self _))
  have source : packet.envelope.source = actor := by rw [envelope]
  have target : packet.envelope.target = node := by rw [envelope]
  have payload : packet.envelope.payload =
      .appendEntriesRequest (makeAppendEntriesRequest state node frontier) := by rw [envelope]
  obtain ⟨delivery, deliveryStep, afterSend, deliveredAt, deliveryTime, delivered⟩ :=
    timely later packet sent (by omega) source ⟨_, payload⟩
  rw [sentTime] at deliveryTime
  have deliveryBefore : delivery < index := by
    by_contra notBefore
    have := admissible.time_le (Nat.le_of_not_lt notBefore) lastFound
      (admissible.before deliveredAt)
    linarith
  rcases delivered with deliverEq | crashed
  · refine ⟨delivery, deliveryStep, by omega, deliveredAt, by linarith, ?_⟩
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
    have le := (quiet delivery deliveryStep.before (by omega) deliveryBefore.le
      (admissible.before deliveredAt)).terms _ _ (Concrete.mem_of_nodeState targetFound)
    simp only [makeAppendEntriesRequest]
    rcases Nat.lt_or_ge targetState.currentTerm state.currentTerm with lt | ge
    · exact Or.inl lt
    refine Or.inr ⟨by omega, ?_⟩
    by_cases candidate : targetState.role = .candidate
    · exact Or.inl candidate
    by_cases preVote : targetState.role = .preVoteCandidate
    · exact Or.inr (Or.inl preVote)
    exact Or.inr (Or.inr
      (matching delivery deliveryStep packet _ targetState (by omega) deliveredAt deliverEq
        source payload targetFound (by omega) candidate preVote))
  · exfalso
    apply crashed
    rw [target]
    exact admissible.live_anti (by omega) (Trace.stateAt_succ_of_stepAt deliveredAt) lastFound
      alive

/-- While the term stays quiet, no tracked node of the term times out. -/
theorem no_timeout {bounds : Bounds}
    (heartbeats : trace.HeartbeatScheduling (some bounds.heartbeatInterval))
    (elections : trace.ElectionScheduling (some (bounds.electionTimeout / 2)))
    {start : Nat} {leader : NodeID} {term : Nat} {delay : Real}
    (initial : QuietStart trace start leader term bounds.electionTimeout)
    (timely : Timely trace start leader delay) (nonneg : 0 <= delay)
    (matching : Matching trace start leader term)
    (ratio : bounds.heartbeatInterval + delay < bounds.electionTimeout / 2)
    (covered : Covered trace start leader term) (incumbent : Incumbent trace start leader)
    {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (afterStart : start <= index) (stepped : trace.stepAt index = some step)
    (quiet
      : forall earlier point,
          start <= earlier
          -> earlier <= index
          -> trace.stateAt earlier = some point
          -> Quiet leader term (proto point))
    {node : NodeID} {state : NodeState}
    (event : step.action = .local node (.timeout .election))
    (different : Not (node = leader))
    (found : nodeState (proto step.before) node = some state)
    (termEq : state.currentTerm = term)
    : False := by
  have alive : node ∈ live step.before :=
    admissible.actor_live stepped (by rw [event]; rfl)
  obtain ⟨first, firstFound, _⟩ := initial.quiet
  have follows := reset_follows admissible heartbeats (admissible.before stepped) quiet timely
    nonneg matching incumbent alive
    (covered index step node state afterStart stepped event different found termEq)
  obtain ⟨reset, resetPoint, _, before, resetFound, recent, resetStep, resetStepped, isReset⟩ :=
    recent_reset
      (fun _ _ _ _ le firstFound lastFound => admissible.time_le le firstFound lastFound)
      ratio afterStart firstFound (admissible.before stepped)
      (initial.timers first index step node state firstFound afterStart stepped event found termEq)
      (reset := fun later =>
        exists reset, trace.stepAt later = some reset /\ ElectionReset reset node)
      (fun earlier point after le recorded early => by
        obtain ⟨later, reset, after, resetStepped, within, isReset⟩ :=
          follows earlier point after le recorded early
        exact ⟨later, reset.before, after, admissible.before resetStepped, within,
          reset, resetStepped, isReset⟩)
  have := elections reset index resetStep step node before resetStepped stepped event isReset
  rw [admissible.before resetStepped, Option.some.injEq] at resetFound
  rw [← resetFound] at recent
  linarith

/-- The term stays quiet at every recorded state from the quiet starting point. -/
theorem quiet_all {bounds : Bounds}
    (heartbeats : trace.HeartbeatScheduling (some bounds.heartbeatInterval))
    (elections : trace.ElectionScheduling (some (bounds.electionTimeout / 2)))
    {start : Nat} {leader : NodeID} {term : Nat} {delay : Real}
    (initial : QuietStart trace start leader term bounds.electionTimeout)
    (timely : Timely trace start leader delay) (nonneg : 0 <= delay)
    (matching : Matching trace start leader term)
    (ratio : bounds.heartbeatInterval + delay < bounds.electionTimeout / 2)
    (covered : Covered trace start leader term) (incumbent : Incumbent trace start leader)
    : forall index point,
        start <= index
        -> trace.stateAt index = some point
        -> Quiet leader term (proto point) := by
  intro index
  induction index using Nat.strong_induction_on with
  | _ index ih =>
      intro point afterStart recorded
      by_cases atStart : index = start
      · subst index
        obtain ⟨first, firstFound, quiet⟩ := initial.quiet
        rw [recorded, Option.some.injEq] at firstFound
        subst first
        exact quiet
      rcases index with _ | index
      · omega
      obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp recorded
      have afterStart : start <= index := by omega
      have quiet
          : forall earlier point,
              start <= earlier
              -> earlier <= index
              -> trace.stateAt earlier = some point
              -> Quiet leader term (proto point) :=
        fun earlier point le before found => ih earlier (by omega) point le found
      have nowQuiet := quiet index step.before afterStart le_rfl (admissible.before stepped)
      rcases selected : step.action.action with _ | action
      · rw [admissible.stutter stepped selected]
        exact nowQuiet
      obtain ⟨rest, c, acts, _⟩ := ctx_at admissible stepped selected
      have local_ : forall input, c.event = .internal input
          -> step.action = .local c.actor input :=
        fun _ eventEq => local_of_internal selected acts eventEq
      refine Quiet.step c nowQuiet (fun eventEq => ?_)
        (fun same eventEq =>
          incumbent.nominations index step afterStart stepped (same ▸ local_ _ eventEq))
        (fun same eventEq =>
          incumbent.quorumChecks index step afterStart stepped (same ▸ local_ _ eventEq))
        fun same =>
          incumbent.notRetired (index + 1) step.after _ (by omega)
            (Trace.stateAt_succ_of_stepAt stepped)
            (found_of_now c.exec (same ▸ c.post_now))
      have ran
          : (startElection (Capabilities.record c.tr.actor) c.tr.pre c.tr.actor).run {}
            = some (c.tr.post, c.tr.outputs) := by
        have ran := c.tr.ran
        have eventEq' : c.tr.event = .internal (.timeout .election) := eventEq
        rw [eventEq'] at ran
        exact ran
      obtain ⟨_, _, can⟩ := startElection_guard c.tr.actor c.tr.pre {} _ _ ran
      have preLe : c.tr.pre.currentTerm <= term := nowQuiet.terms _ _ c.pre_now
      show c.tr.pre.currentTerm < term
      by_contra notLt
      have different : Not (c.actor = leader) := by
        intro same
        obtain ⟨local_, lead⟩ := Quiet.lead c nowQuiet
        have primary : c.tr.pre.role = .primary := by
          have now : Now (proto step.before :: rest) c.actor local_ := by
            rw [same]
            exact lead.now
          have := lead.primary
          rwa [c.now_pre now] at this
        rcases can.1 with role | role | role <;> rw [role] at primary <;> cases primary
      exact no_timeout admissible heartbeats elections initial timely nonneg matching
        ratio covered incumbent afterStart stepped quiet (local_ _ eventEq) different
        c.tr.found (by omega)

/-- `Properties.stable_leader`. -/
theorem stable_leader {bounds : Bounds}
    (heartbeats : trace.HeartbeatScheduling (some bounds.heartbeatInterval))
    (elections : trace.ElectionScheduling (some (bounds.electionTimeout / 2)))
    {start : Nat} {leader : NodeID} {term : Nat} {delay : Real}
    (quiet : QuietStart trace start leader term bounds.electionTimeout)
    (timely : Timely trace start leader delay) (nonneg : 0 <= delay)
    (matching : Matching trace start leader term)
    (ratio : bounds.heartbeatInterval + delay < bounds.electionTimeout / 2)
    (covered : Covered trace start leader term) (incumbent : Incumbent trace start leader)
    : StableLeader trace start leader term := by
  refine ⟨?_, fun index point le recorded => ?_⟩
  · obtain ⟨first, found, _⟩ := quiet.quiet
    exact ⟨first, found⟩
  obtain ⟨state, found, primary, termEq⟩ :=
    quiet_leader admissible recorded
      (quiet_all admissible heartbeats elections quiet timely nonneg matching ratio covered
        incumbent index point le recorded)
  exact ⟨point, state, recorded, incumbent.live index point le recorded, found, primary, termEq,
    incumbent.notRetired index point state le recorded found⟩

end Trace

end CCFRaft.Proofs.Leadership
