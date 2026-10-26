module

public import CCFRaft.Proofs.Duel.RoundStep

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# One duel round: trace facts

NOT IMPORTED BY `Properties`. Trace facts for `Duel.Round`: packet delays, the
window, a step as one handler run, and the raiser's vote requests reaching every
participant.
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
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Replication
open CCFRaft.Proofs.Liveness (Admissible)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W]

omit [HasTime W] [HasLive W] [HasNetwork W] [HasTimers W] in
theorem Capped.down {trace : Trace W Liveness.Event} {participants : Finset NodeID}
    {c term index : Nat} (capped : Capped trace participants c term index) {earlier : Nat}
    (le : c <= earlier) (bound : earlier <= index)
    : Capped trace participants c term earlier :=
  ⟨
    le,
    fun e p n s first last found member nodeFound =>
      capped.2 e p n s first (le_trans last bound) found member nodeFound
  ⟩

omit [HasTimers W] in
/-- `node` is past `term`, or a vote request past `term` to it, sent by `bound`, is
still pending and `node` is live. -/
def Reached (participants : Finset NodeID) (node : NodeID) (term : Nat) (bound : Real)
    (point : W)
    : Prop :=
  (forall state,
    nodeState (proto point) node = some state -> term + 1 <= state.currentTerm)
  \/ exists packet request,
      packet ∈ pending point
      /\ node ∈ live point
      /\ packet.envelope.source ∈ participants
      /\ packet.envelope.target = node
      /\ packet.envelope.payload = .requestVoteRequest request
      /\ term + 1 <= request.term
      /\ packet.sentAt <= bound

/-- What a packet between participants in the round can be, by when it was sent. -/
def Shape (term : Nat) (origin electionTimeout maxDelay : Real) (packet : Packet)
    : Prop :=
  packet.envelope.payload.term <= term + 1
  /\ (packet.envelope.payload.term <= term
      -> (forall response,
            Not (packet.envelope.payload = .appendEntriesResponse response))
      -> packet.sentAt <= origin + maxDelay)
  /\ (forall request,
        packet.envelope.payload = .requestVoteRequest request
        -> packet.sentAt <= origin + maxDelay)
  /\ (packet.envelope.payload
        = .requestVoteResponse { term := term + 1, voteGranted := true }
      -> packet.sentAt <= origin + 2 * maxDelay)
  /\ (forall request,
        packet.envelope.payload = .requestPreVoteRequest request
        -> request.term = term + 1
        -> origin + electionTimeout / 2 <= packet.sentAt)
  /\ (packet.envelope.payload
        = .requestPreVoteResponse { term := term + 1, voteGranted := true }
      -> origin + electionTimeout / 2 <= packet.sentAt)

/-- A sent message carries its sender's new term, or for an AppendEntries response
possibly a term of its log. -/
theorem sendOK_terms {self : NodeID} {before after : NodeState} {event : Model.Node.Event}
    {envelope : Model.Envelope} (ok : SendOK self before event after envelope)
    (logLe : forall k, termAt after.log k <= after.currentTerm)
    : envelope.payload.term <= after.currentTerm
      /\ ((forall response, Not (envelope.payload = .appendEntriesResponse response))
          -> envelope.payload.term = after.currentTerm) := by
  obtain ⟨_, ok⟩ := ok
  cases h : envelope.payload with
  | appendEntriesRequest request =>
      simp only [h] at ok
      simp [Message.term, ok.1.2.1]
  | appendEntriesResponse response =>
      simp only [h] at ok
      refine ⟨?_, fun no => absurd rfl (no response)⟩
      rcases ok.1 with eq | ⟨k, eq⟩
      · simp [Message.term, eq]
      · simp only [Message.term, eq]
        exact logLe k
  | requestVoteRequest request =>
      simp only [h] at ok
      simp [Message.term, ok.1]
  | requestVoteResponse response =>
      simp only [h] at ok
      simp [Message.term, ok.1]
  | proposeRequestVoteRequest term =>
      simp only [h] at ok
      simp [Message.term, ok.1]
  | requestPreVoteRequest request =>
      simp only [h, Message.term] at ok
      simp [Message.term, ok]
  | requestPreVoteResponse response =>
      simp only [h, Message.term] at ok
      simp [Message.term, ok]

section Lemmas

variable [Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event} {electionTimeout maxDelay jump : Real} {start : Nat}
  {duration : Real} {participants members : Finset NodeID} {c term : Nat}
  (setup
    : RoundSetup nodes trace electionTimeout maxDelay jump start duration participants
        members c term)

include setup

namespace RoundSetup

theorem delay_at {index : Nat} {point : W} (found : trace.stateAt index = some point)
    {packet : Packet} (member : packet ∈ pending point)
    (alive : packet.envelope.target ∈ live point)
    : time point <= packet.sentAt + maxDelay := by
  cases index with
  | zero =>
      simp only [Trace.stateAt_zero, Option.some.injEq] at found
      subst found
      exact setup.delay.1 packet member alive
  | succ index =>
      obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp found
      exact setup.delay.next stepped packet member alive

theorem sent_le {index : Nat} {point : W} (found : trace.stateAt index = some point)
    {packet : Packet} (member : packet ∈ pending point)
    : packet.sentAt <= time point := by
  obtain ⟨sent, lt, sentAt⟩ := setup.admissible.pending_sent found member
  obtain ⟨step, _, _, stepped, _, _, _, _, _, sentEq⟩ :=
    setup.admissible.sentAt_emitted sentAt
  rw [sentEq]
  exact setup.admissible.time_le (Nat.le_of_lt lt) (setup.admissible.before stepped) found

theorem timeout_pos : 0 < electionTimeout := by
  linarith [setup.ratio, setup.nonnegative]

theorem within_of_time {origin : W} (originFound : trace.stateAt c = some origin)
    {index : Nat} {point : W} (le : c <= index) (found : trace.stateAt index = some point)
    (timeLe : time point <= time origin + electionTimeout / 2)
    : Within trace start duration index := by
  refine ⟨le_trans setup.startLe le, fun first last firstFound lastFound => ?_⟩
  rw [found, Option.some.injEq] at lastFound
  subst lastFound
  have covers := setup.covers first origin firstFound originFound
  unfold roundLength at covers
  linarith [setup.nonnegative, setup.jumpNonnegative, setup.ratio]

theorem stays_live {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (within : Within trace start duration index)
    (stepped : trace.stepAt index = some step) {node : NodeID}
    (member : node ∈ participants)
    : node ∈ live step.after := by
  have alive :=
    setup.period.participantsLive index step.before node within
      (setup.admissible.before stepped) member
  by_contra dead
  have crashed := setup.admissible.crashes stepped alive dead
  have next := setup.admissible.within_after within stepped (fun idle => by
    rw [crashed] at idle
    cases idle)
  exact dead (setup.period.participantsLive (index + 1) step.after node next
    (Trace.stateAt_succ_of_stepAt stepped) member)

/-- A packet between participants survives a step in the window that does not
deliver it. -/
theorem kept {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (within : Within trace start duration index)
    (stepped : trace.stepAt index = some step) {packet : Packet}
    (member : packet ∈ pending step.before)
    (source : packet.envelope.source ∈ participants)
    (target : packet.envelope.target ∈ participants)
    (notDelivered : step.action ≠ .deliver packet)
    : packet ∈ pending step.after := by
  by_contra gone
  have consumed := setup.admissible.consumed_of_left stepped member gone
  cases event : step.action with
  | deliver delivered =>
      simp only [event, Liveness.Event.consumedPacket, Option.some.injEq] at consumed
      exact notDelivered (by rw [event, consumed])
  | drop dropped =>
      simp only [event, Liveness.Event.consumedPacket, Option.some.injEq] at consumed
      apply setup.period.lossless index step dropped within stepped event
      rw [consumed]
      exact ⟨source, target⟩
  | _ => simp [event, Liveness.Event.consumedPacket] at consumed

/-- A protocol step, seen as one node's handler run. -/
theorem view {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {action : Model.Action}
    (selected : step.action.action = some action)
    : exists actor pre post,
    exists event : Model.Node.Event,
    exists outputs : CCF.Outputs NodeID Message Notification,
      nodeState (proto step.before) actor = some pre
      /\ nodeState (proto step.after) actor = some post
      /\ (forall node,
            node ≠ actor
            -> nodeState (proto step.after) node = nodeState (proto step.before) node)
      /\ ((exists input, step.action = .local actor input /\ event = .internal input)
          \/ exists packet,
              step.action = .deliver packet
              /\ packet.envelope.target = actor
              /\ event = .receive packet.envelope.source packet.envelope.payload)
      /\ (Model.Node.step (CCF.Capabilities.record actor) actor pre event).run {}
          = some (post, outputs)
      /\ pending step.after
          = step.action.remaining (pending step.before)
            ++ Packet.batch outputs.outgoing (HasNetwork.issued step.before)
                (time step.before) := by
  obtain ⟨actor, pre, post, outputs, preFound, postFound, others, ran, ledger⟩ :=
    Racing.protocol_view setup.admissible stepped selected
  rcases ran with ⟨input, eventEq, ran⟩ | ⟨packet, eventEq, targetEq, ran⟩
  · exact ⟨actor, pre, post, .internal input, outputs, preFound, postFound, others,
      Or.inl ⟨input, eventEq, rfl⟩, ran, ledger⟩
  · exact ⟨actor, pre, post, .receive packet.envelope.source packet.envelope.payload,
      outputs, preFound, postFound, others, Or.inr ⟨packet, eventEq, targetEq, rfl⟩, ran,
      ledger⟩

theorem log_le {index : Nat} {point : W} (found : trace.stateAt index = some point)
    {node : NodeID} {state : NodeState}
    (nodeFound : nodeState (proto point) node = some state) (k : Nat)
    : termAt state.log k <= state.currentTerm := by
  obtain ⟨rest, exec⟩ := history_at setup.admissible found
  exact termAt_le_term (good_of_exec exec _ (List.suffix_refl _) (List.cons_ne_nil _ _))
    (now_of_found nodeFound) k

/-- A packet left pending by an environment step was pending before it. -/
theorem pending_env {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) (selected : step.action.action = none)
    {packet : Packet} (member : packet ∈ pending step.after)
    : packet ∈ pending step.before := by
  obtain ⟨_, _, emitted, emittedEq, _, ledger⟩ := setup.admissible.delivery.next stepped
  simp only [selected, Option.some.injEq] at emittedEq
  subst emittedEq
  rw [ledger] at member
  simp only [Packet.batch, List.zipIdx_nil, List.map_nil, List.append_nil] at member
  unfold Liveness.Event.remaining at member
  split at member
  · exact List.mem_of_mem_eraseP member
  · exact member

/-- A received message came in a pending packet to the actor. -/
theorem received {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {actor : NodeID} {event : Model.Node.Event}
    (cause
      : (exists input, step.action = .local actor input /\ event = .internal input)
        \/ exists packet,
            step.action = .deliver packet
            /\ packet.envelope.target = actor
            /\ event = .receive packet.envelope.source packet.envelope.payload)
    {source : NodeID} {message : Message} (eventEq : event = .receive source message)
    : exists packet,
        step.action = .deliver packet
        /\ packet ∈ pending step.before
        /\ packet.envelope.target = actor
        /\ packet.envelope.source = source
        /\ packet.envelope.payload = message := by
  rcases cause with ⟨input, _, eventIs⟩ | ⟨packet, delivered, targetEq, eventIs⟩
  · rw [eventIs] at eventEq
    cases eventEq
  rw [eventIs] at eventEq
  injection eventEq with sourceEq messageEq
  exact ⟨
    packet,
    delivered,
    setup.admissible.consumed_pending stepped
      (by simp [delivered, Liveness.Event.consumedPacket]),
    targetEq,
    sourceEq,
    messageEq
  ⟩

theorem local_of_event {step : CCF.Execution.Step W Liveness.Event} {actor : NodeID}
    {event : Model.Node.Event}
    (cause
      : (exists input, step.action = .local actor input /\ event = .internal input)
        \/ exists packet,
            step.action = .deliver packet
            /\ packet.envelope.target = actor
            /\ event = .receive packet.envelope.source packet.envelope.payload)
    {input : Input} (eventEq : event = .internal input)
    : step.action = .local actor input := by
  rcases cause with ⟨other, action, eventIs⟩ | ⟨packet, _, _, eventIs⟩
  · rw [eventIs] at eventEq
    injection eventEq with inputEq
    rw [action, inputEq]
  · rw [eventIs] at eventEq
    cases eventEq

/-- A participant of `term + 1` times out in the round only from half an election
timeout on. -/
theorem timeout_late {origin : W} (originFound : trace.stateAt c = some origin)
    {index : Nat} {step : CCF.Execution.Step W Liveness.Event} (le : c <= index)
    (stepped : trace.stepAt index = some step) {node : NodeID}
    (nodeIn : node ∈ participants) {state : NodeState}
    (nodeFound : nodeState (proto step.before) node = some state)
    (termEq : state.currentTerm = term + 1)
    (action : step.action = .local node (.timeout .election))
    : time origin + electionTimeout / 2 <= time step.before := by
  have fresh :=
    Racing.term_fresh setup.admissible setup.timers originFound
      (fun node state member found => setup.round.low origin node state originFound member found)
      index step.before node state le (setup.admissible.before stepped) nodeIn nodeFound termEq
  linarith [((setup.timers.next stepped) node).2.2 action]

/-! ## The raiser's vote requests -/

theorem reached_step {origin : W} (originFound : trace.stateAt c = some origin)
    {index : Nat} {step : CCF.Execution.Step W Liveness.Event} (le : c <= index)
    (stepped : trace.stepAt index = some step) {node : NodeID}
    (nodeIn : node ∈ participants)
    (reached : Reached participants node term (time origin) step.before)
    : Reached participants node term (time origin) step.after := by
  rcases reached with
    high | ⟨packet, request, member, alive, sourceIn, targetEq, payload, high, sentLe⟩
  · left
    intro state found
    obtain ⟨before, beforeFound, termLe⟩ := Racing.node_before setup.admissible stepped found
    exact le_trans (high before beforeFound) termLe
  have beforeFound := setup.admissible.before stepped
  have timeLe := setup.delay_at beforeFound member (targetEq ▸ alive)
  have within :=
    setup.within_of_time originFound le beforeFound
      (by linarith [setup.ratio, setup.nonnegative])
  by_cases delivered : step.action = .deliver packet
  · left
    intro state found
    have selected : step.action.action = some (.deliver packet.envelope) := by
      simp [delivered, Liveness.Event.action]
    obtain ⟨actor, pre, post, event, outputs, _, postFound, _, cause, ran, _⟩ :=
      setup.view stepped selected
    rcases cause with ⟨input, eventEq, _⟩ | ⟨other, eventEq, actorEq, eventIs⟩
    · rw [delivered] at eventEq
      cases eventEq
    rw [delivered] at eventEq
    cases eventEq
    rw [targetEq] at actorEq
    subst actorEq
    rw [postFound, Option.some.injEq] at found
    subst found
    rw [eventIs, payload] at ran
    obtain ⟨middle, granted, _, requestLe, _, afterEq, _⟩ :=
      Racing.sends_run (Racing.voteRequest_receive node packet.envelope.source pre request)
        ran
    rw [afterEq]
    split <;> first | omega | (dsimp only; omega)
  · right
    exact ⟨packet, request,
      setup.kept within stepped member sourceIn (targetEq ▸ nodeIn) delivered,
      setup.stays_live within stepped nodeIn, sourceIn, targetEq, payload, high, sentLe⟩

theorem reached_from {origin : W} (originFound : trace.stateAt c = some origin)
    {node : NodeID} (nodeIn : node ∈ participants) {first : Nat} (cle : c <= first)
    {firstPoint : W} (firstFound : trace.stateAt first = some firstPoint)
    (base : Reached participants node term (time origin) firstPoint)
    : forall index point,
        first <= index
        -> trace.stateAt index = some point
        -> Reached participants node term (time origin) point := by
  intro index
  induction index with
  | zero =>
      intro point le found
      have : first = 0 := by omega
      subst this
      rw [firstFound, Option.some.injEq] at found
      subst found
      exact base
  | succ index ih =>
      intro point le found
      by_cases atFirst : first = index + 1
      · subst atFirst
        rw [firstFound, Option.some.injEq] at found
        subst found
        exact base
      obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp found
      exact setup.reached_step originFound (by omega) stepped nodeIn
        (ih step.before (by omega) (setup.admissible.before stepped))

/-- Right after step `c` every participant is past `term`, or the raiser's vote
request past `term` to it is pending. -/
theorem reached_start {origin : W} (originFound : trace.stateAt c = some origin)
    : exists step,
        trace.stepAt c = some step
        /\ forall node,
            node ∈ participants
            -> Reached participants node term (time origin) step.after := by
  obtain ⟨step, raiser, raised, stepped, raiserIn, raisedFound, above⟩ := setup.round.raise
  refine ⟨step, stepped, fun node nodeIn => ?_⟩
  have beforeFound := setup.admissible.before stepped
  rw [originFound, Option.some.injEq] at beforeFound
  subst beforeFound
  have within :=
    setup.within_of_time originFound le_rfl (setup.admissible.before stepped)
      (by linarith [setup.timeout_pos])
  have low := setup.round.low step.before
  rcases selected : step.action.action with _ | action
  · rw [setup.admissible.stutter stepped selected] at raisedFound
    have := low raiser raised originFound raiserIn raisedFound
    omega
  obtain ⟨actor, pre, post, event, outputs, preFound, postFound, others, cause, ran, ledger⟩ :=
    setup.view stepped selected
  by_cases actorEq : raiser = actor
  swap
  · rw [others raiser actorEq] at raisedFound
    have := low raiser raised originFound raiserIn raisedFound
    omega
  subst actorEq
  rw [postFound, Option.some.injEq] at raisedFound
  subst raisedFound
  have preLe := low raiser pre originFound raiserIn preFound
  rcases Racing.sends_run (raise_sends raiser pre event) ran (by omega) with
    ⟨source, message, eventEq, termLe⟩ | ⟨request, requestGe, sends⟩
  · exfalso
    rcases cause with ⟨input, _, eventIs⟩ | ⟨packet, delivered, targetEq, eventIs⟩
    · rw [eventIs] at eventEq
      cases eventEq
    rw [eventIs] at eventEq
    cases eventEq
    have member :=
      setup.admissible.consumed_pending stepped
        (packet := packet) (by simp [delivered, Liveness.Event.consumedPacket])
    have sourceIn :=
      setup.period.isolated c step packet.envelope within stepped
        (by simp [delivered, Liveness.Event.delivered]) (targetEq ▸ raiserIn)
    have := setup.round.messages step.before packet originFound member sourceIn
      (targetEq ▸ raiserIn)
    omega
  by_cases self : node = raiser
  · subst self
    left
    intro state found
    rw [postFound, Option.some.injEq] at found
    subst found
    omega
  right
  have alive := setup.period.participantsLive c step.before raiser within originFound raiserIn
  have quorum := setup.period.quorum c step.before raiser pre within originFound alive preFound
  have targetIn : node ∈ pre.activeMembers.erase raiser := by
    rcases (setup.membership step.before originFound).activeMembers
        (Concrete.mem_of_nodeState preFound) raiserIn with empty | membersEq
    · exact absurd empty quorum.1
    · rw [membersEq]
      exact Finset.mem_erase.mpr ⟨self, setup.subset nodeIn⟩
  obtain ⟨packet, member, envelopeEq, sentEq⟩ :=
    Racing.pending_of_sent ledger (sends node targetIn)
  refine ⟨
    packet,
    request,
    member,
    setup.stays_live within stepped nodeIn,
    by rw [envelopeEq]; exact raiserIn,
    by rw [envelopeEq],
    by rw [envelopeEq],
    by omega,
    le_of_eq sentEq
  ⟩

end RoundSetup

end Lemmas

end CCFRaft.Proofs.Duel.Round
