module

public import CCFRaft.Proofs.Leadership.InitRaiseBroadcast
public import CCFRaft.Proofs.Leadership.InitRaiseVotes

@[expose] public section

set_option linter.unusedSectionVars false

/-!
Election activity disseminates the top term to every participant.
-/

namespace CCFRaft.Proofs.Leadership.InitRaise

open CCF CCF.MultiNodeTransitionSystem
open Model.Node CCFRaft.Liveness
open CCFRaft.Proofs.Safety CCFRaft.Proofs.Replication
open CCFRaft.Proofs.Liveness (Admissible)
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)

/-- Either kind of election request carries the named term. -/
def ElectionRequest (term : Nat) (message : Message) : Prop :=
  exists request : RequestVoteRequest,
    request.term = term
    /\ (message = .requestPreVoteRequest request \/ message = .requestVoteRequest request)

/-- Both request handlers adopt the request term before replying. -/
theorem request_adopts (self source : NodeID) (state : NodeState) {message : Message}
    {term : Nat} (request : ElectionRequest term message)
    : Sends (fun after _ => term <= after.currentTerm)
        (receive (Capabilities.record self) self source state message) := by
  obtain ⟨request, rfl, rfl | rfl⟩ := request
  · simp only [receive, handleRequestPreVoteRequest]
    refine Sends.ite' (fun no => by simp at no) fun _ => ?_
    refine Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' ?_
    simp only [observeTerm, Message.term, updateTerm]
    by_cases h : state.currentTerm < request.term <;> simp [h, becomeAwareOfNewTerm]
    omega
  · simp only [receive, handleRequestVoteRequest]
    refine Sends.ite' (fun no => by simp at no) fun _ => ?_
    refine Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' ?_
    have adopted : request.term <= (observeTerm state (.requestVoteRequest request)).currentTerm := by
      simp only [observeTerm, Message.term, updateTerm]
      by_cases h : state.currentTerm < request.term <;> simp [h, becomeAwareOfNewTerm]
      omega
    split <;> exact adopted

variable [Config.InitialConfiguration]
  {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W]
  {trace : Trace W Liveness.Event} {nodes : List NodeID}
  (admissible
    : Admissible (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) trace)

include admissible

/-- A delivered election request leaves its target at least at the carried term. -/
theorem delivered_adopts {index : Nat} {step : Execution.Step W Liveness.Event}
    {packet : Packet} {term : Nat}
    (stepped : trace.stepAt index = some step)
    (delivered : step.action = .deliver packet)
    (request : ElectionRequest term packet.envelope.payload)
    : exists state,
        nodeState (proto step.after) packet.envelope.target = some state
        /\ term <= state.currentTerm := by
  have selected : step.action.action = some (.deliver packet.envelope) := by
    rw [delivered]
    rfl
  obtain ⟨tr, ⟨actor, event⟩, _⟩ := transition_acts (admissible.step stepped selected)
  have ran : (receive (Capabilities.record packet.envelope.target) packet.envelope.target
      packet.envelope.source tr.pre packet.envelope.payload).run {}
      = some (tr.post, tr.outputs) := by
    simpa only [actor, event, Model.Node.step] using tr.ran
  obtain ⟨_, _, adopted⟩ := request_adopts packet.envelope.target packet.envelope.source
    tr.pre request {} _ _ ran
  refine ⟨tr.post, ?_, adopted⟩
  rw [← actor]
  exact Direct.nodeState_of_mem
    (Direct.keys_nodup (admissible.reachable (Trace.stateAt_succ_of_stepAt stepped)))
    tr.post_mem

/-- Election activity sends its term to every other participant. -/
theorem activity_broadcast {start index : Nat} {duration : Real}
    {participants members : Finset NodeID} {term : Nat}
    (subset : participants ⊆ members)
    (ready
      : forall index point node state,
          Within trace start duration index
          -> trace.stateAt index = some point
          -> node ∈ participants
          -> nodeState (proto point) node = some state
          -> state.activeMembers = members
              /\ (Not (state.role = .primary) -> canStartElection state node))
    (noLeader
      : forall index point node state,
          Within trace start duration index
          -> trace.stateAt index = some point
          -> node ∈ participants
          -> nodeState (proto point) node = some state
          -> state.currentTerm = term
          -> Not (state.role = .primary))
    (low : Low trace participants (index + 1) term)
    (within : Within trace start duration index)
    (activity : TermActivity trace participants index term)
    : exists step actor state,
        trace.stepAt index = some step
        /\ actor ∈ participants
        /\ nodeState (proto step.after) actor = some state
        /\ state.currentTerm = term
        /\ forall target,
            target ∈ participants
            -> Not (target = actor)
            -> exists packet,
                trace.SentAt index packet
                /\ packet.envelope.source = actor
                /\ packet.envelope.target = target
                /\ ElectionRequest term packet.envelope.payload := by
  rcases activity with ⟨step, actor, before, stepped, action, actorIn, beforeFound, beforeTerm⟩
    | ⟨packet, request, sentAt, sourceIn, payload, requestTerm⟩
  · have selected : step.action.action = some (.local actor (.timeout .election)) := by
      rw [action]
      rfl
    obtain ⟨tr, ⟨actorEq, eventEq⟩, output⟩ := transition_acts (admissible.step stepped selected)
    have beforeEq : tr.pre = before := by
      have found := tr.found
      rw [actorEq, beforeFound, Option.some.injEq] at found
      exact found.symm
    have ran : (startElection (Capabilities.record actor) before actor).run {}
        = some (tr.post, tr.outputs) := by
      simpa only [actorEq, eventEq, beforeEq, Model.Node.step, act] using tr.ran
    have afterFound : nodeState (proto step.after) actor = some tr.post := by
      rw [← actorEq]
      exact Direct.nodeState_of_mem
        (Direct.keys_nodup (admissible.reachable (Trace.stateAt_succ_of_stepAt stepped))) tr.post_mem
    have afterLow := low step.after actor tr.post
      (Trace.stateAt_succ_of_stepAt stepped) actorIn afterFound
    obtain ⟨sent, outputs, result⟩ := timeout_outcome actor before {} _ _ ran
    have result : tr.post = preVoteState actor before
        /\ tr.outputs.outgoing =
          broadcast actor before (.requestPreVoteRequest (makeRequestVoteRequest before)) := by
      simpa [outputs] using result (by omega)
    refine ⟨step, actor, tr.post, stepped, actorIn, afterFound, ?_, ?_⟩
    · rw [result.1]
      exact beforeTerm
    · intro target targetIn different
      have members := (ready index step.before actor before within
        (admissible.before stepped) actorIn beforeFound).1
      have member : ({ source := actor, target := target, payload := .requestPreVoteRequest (makeRequestVoteRequest before) } : Model.Envelope)
          ∈ tr.outputs.outgoing := by
        rw [result.2]
        exact mem_broadcast (by rw [members]; exact subset targetIn) different
      obtain ⟨packet, sentAt, envelope, _⟩ :=
        admissible.sentAt_of_emitted stepped selected output member
      refine ⟨packet, sentAt, ?_, ?_, ?_⟩
      · rw [envelope]
      · rw [envelope]
      · exact ⟨makeRequestVoteRequest before, beforeTerm, Or.inl (by rw [envelope])⟩
  · obtain ⟨step, action, emitted, stepped, selected, output, member, _, _, _⟩ :=
      admissible.sentAt_emitted sentAt
    obtain ⟨tr, _, output'⟩ := transition_acts (admissible.step stepped selected)
    rw [output', Option.some.injEq] at output
    subst emitted
    have sends := CCFRaft.Proofs.Safety.Summary.sends tr.summary packet.envelope member
    have actorIn : tr.actor ∈ participants := sends.1 ▸ sourceIn
    have afterFound := Direct.nodeState_of_mem
      (Direct.keys_nodup (admissible.reachable (Trace.stateAt_succ_of_stepAt stepped))) tr.post_mem
    have nextWithin := admissible.within_after within stepped (by
      intro idle
      simp [idle, Liveness.Event.action] at selected)
    have ok := sends.2
    simp only [payload] at ok
    have term : tr.post.currentTerm = term := ok.1.symm.trans requestTerm
    have notPrimary := noLeader (index + 1) step.after tr.actor tr.post nextWithin
      (Trace.stateAt_succ_of_stepAt stepped) actorIn afterFound term
    have ⟨members, can⟩ := ready (index + 1) step.after tr.actor tr.post nextWithin
      (Trace.stateAt_succ_of_stepAt stepped) actorIn afterFound
    obtain ⟨sent, outputs, result⟩ := step_votes tr.actor tr.pre tr.event {} _ _ tr.ran
    have result : VotePackets tr.actor tr.post tr.outputs.outgoing := by
      simpa [outputs] using result
    have broadcast := result notPrimary (eligible_not_none (can notPrimary))
      packet.envelope request member payload
    refine ⟨step, tr.actor, tr.post, stepped, actorIn, afterFound, term, ?_⟩
    intro target targetIn different
    have targetMem : ({ source := tr.actor, target := target, payload := .requestVoteRequest request } : Model.Envelope)
        ∈ tr.outputs.outgoing := by
      rw [broadcast]
      exact mem_broadcast (by rw [members]; exact subset targetIn) different
    obtain ⟨p, pSent, envelope, _⟩ :=
      admissible.sentAt_of_emitted stepped selected output' targetMem
    refine ⟨p, pSent, ?_, ?_, ?_⟩
    · rw [envelope]
    · rw [envelope]
    · exact ⟨request, requestTerm, Or.inr (by rw [envelope])⟩

/-- One network delay after the first activity, all participants have adopted
the top term at a common recorded point no later than the phase bound. -/
theorem activity_converges {start index : Nat} {duration maxDelay bound : Real}
    {participants members : Finset NodeID} {term : Nat}
    (delay : trace.Valid (boundedDelayModel maxDelay))
    (diverges : TimeDiverges trace)
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
    (noLeader
      : forall index point node state,
          Within trace start duration index
          -> trace.stateAt index = some point
          -> node ∈ participants
          -> nodeState (proto point) node = some state
          -> state.currentTerm = term
          -> Not (state.role = .primary))
    (low
      : forall index,
          Within trace start duration index -> Low trace participants index term)
    {first point : W}
    (firstFound : trace.stateAt start = some first)
    (within : Within trace start duration index)
    (found : trace.stateAt index = some point)
    (early : time point <= bound) (nonnegative : 0 <= maxDelay)
    (room : bound + maxDelay <= time first + duration)
    (activity : TermActivity trace participants index term)
    : exists last step,
        index < last
        /\ trace.stepAt last = some step
        /\ time step.before <= bound + maxDelay
        /\ bound + maxDelay < time step.after
        /\ forall node,
            node ∈ participants
            -> exists state,
                nodeState (proto step.before) node = some state
                /\ state.currentTerm = term := by
  have stepped : exists step, trace.stepAt index = some step /\ Not (step.action = .idle) := by
    rcases activity with ⟨step, _, _, stepped, action, _⟩ | ⟨packet, _, sentAt, _⟩
    · exact ⟨step, stepped, by rw [action]; simp⟩
    · obtain ⟨step, _, _, stepped, selected, _⟩ := admissible.sentAt_emitted sentAt
      exact ⟨step, stepped, by intro idle; simp [idle, Liveness.Event.action] at selected⟩
  obtain ⟨sentStep, sentStepped, busy⟩ := stepped
  have nextWithin := admissible.within_after within sentStepped busy
  obtain ⟨sentStep', actor, actorState, sentStepped', actorIn, actorFound, actorTerm, broadcasts⟩ :=
    activity_broadcast admissible subset ready noLeader (low (index + 1) nextWithin) within activity
  rw [sentStepped, Option.some.injEq] at sentStepped'
  subst sentStep'
  have timeEq : time sentStep.before = time point := by
    rw [admissible.before sentStepped, Option.some.injEq] at found
    exact congrArg time found
  have afterEq := (admissible.timing.next sentStepped).2 busy
  have sentEarly : time sentStep.after <= bound + maxDelay := by linarith
  obtain ⟨last, crossing, lower, crossed, near, far⟩ :=
    boundary admissible diverges (Trace.stateAt_succ_of_stepAt sentStepped) sentEarly
  have crossWithin : Within trace start duration last := by
    refine ⟨within.1.trans (Nat.le_of_lt lower), fun first' point' firstFound' found' => ?_⟩
    rw [firstFound, Option.some.injEq] at firstFound'
    rw [admissible.before crossed, Option.some.injEq] at found'
    subst first' point'
    exact near.trans room
  refine ⟨last, crossing, lower, crossed, near, far, ?_⟩
  intro node member
  by_cases same : node = actor
  · subst node
    exact top_stays admissible (Trace.stateAt_succ_of_stepAt sentStepped) actorFound actorTerm
      actorIn lower (admissible.before crossed) (low last crossWithin)
  · obtain ⟨packet, sentAt, sourceEq, targetEq, request⟩ := broadcasts node member same
    obtain ⟨sentStep', _, _, sentStepped', _, _, _, _, _, sentTime⟩ :=
      admissible.sentAt_emitted sentAt
    rw [sentStepped, Option.some.injEq] at sentStepped'
    subst sentStep'
    have sentEarly : packet.sentAt + maxDelay <= bound + maxDelay := by
      rw [sentTime, timeEq]
      linarith
    obtain ⟨delivered, step, afterSent, stepped, deliveredEarly, delivery⟩ :=
      sent_delivered admissible delay diverges good firstFound within sentAt
        (sourceEq ▸ actorIn) (targetEq ▸ member) (sentEarly.trans room)
    have before : delivered < last := by
      by_contra late
      by_cases same : delivered = last
      · subst delivered
        rw [crossed, Option.some.injEq] at stepped
        subst step
        have sameTime := (admissible.timing.next crossed).2 (by rw [delivery]; simp)
        linarith
      · have elapsed := admissible.time_le (by omega : last + 1 <= delivered)
          (Trace.stateAt_succ_of_stepAt crossed) (admissible.before stepped)
        linarith
    obtain ⟨state, stateFound, adopted⟩ := delivered_adopts admissible stepped delivery request
    rw [targetEq] at stateFound
    obtain ⟨later, laterFound, grows⟩ := CCFRaft.Proofs.StablePrimary.term_mono admissible
      (by omega : delivered + 1 <= last)
      (Trace.nodeAt_eq_some.mpr ⟨step.after, Trace.stateAt_succ_of_stepAt stepped, stateFound⟩)
      (admissible.before crossed)
    rw [Trace.nodeAt_of_stateAt (admissible.before crossed)] at laterFound
    have cap := low last crossWithin crossing.before node later
      (admissible.before crossed) member laterFound
    exact ⟨later, laterFound, by omega⟩

end CCFRaft.Proofs.Leadership.InitRaise
