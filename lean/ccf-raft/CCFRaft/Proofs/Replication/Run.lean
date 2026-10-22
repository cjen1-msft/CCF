module

public import CCFRaft.Proofs.Replication.Step
public import CCFRaft.Proofs.Safety.Origin
public import CCFRaft.Proofs.Replication.Eligible
public import CCFRaft.Proofs.Direct.AppendOnly

import all Init.Control.State

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# The stable primary and its peers along a timed execution

The stable primary's state at each index, how one step moves its frontiers for a
peer, and where AppendEntries traffic comes from.
-/

open CCF CCF.MultiNodeTransitionSystem
open CCFRaft
open CCFRaft.Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Config
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.StablePrimary

namespace CCFRaft.Proofs.LeadsThroughout

variable {trace : Trace} {leader : NodeID} {term : Nat}
  (stable : LeadsThroughout trace leader term)

/-- The stable primary's state at an index. -/
noncomputable def state (index : Nat) : NodeState := Classical.choose (stable index).2

theorem found (index : Nat)
    : nodeState (trace.state index) leader = some (stable.state index) :=
  (Classical.choose_spec (stable index).2).1

theorem primary (index : Nat) : (stable.state index).role = .primary :=
  (Classical.choose_spec (stable index).2).2.1

theorem current (index : Nat) : (stable.state index).currentTerm = term :=
  (Classical.choose_spec (stable index).2).2.2.1

theorem state_eq {index : Nat} {state : NodeState}
    (found : nodeState (trace.state index) leader = some state)
    : state = stable.state index := by
  rw [stable.found index, Option.some.injEq] at found
  exact found.symm

end CCFRaft.Proofs.LeadsThroughout

namespace CCFRaft.Proofs.Replication

/-! ## Events -/

theorem action_of_delivered {event : Liveness.Event} {envelope : Model.Envelope}
    (delivered : event.delivered = some envelope)
    : event.action = some (.deliver envelope) := by
  cases event <;> simp_all [Event.action, Event.delivered]

theorem event_of_local {event : Liveness.Event} {node : NodeID} {input : Input}
    (selected : event.action = some (.local node input))
    : event = .local node input := by
  cases event <;> simp_all [Event.action]

theorem acts_internal {action : Model.Action} {actor : NodeID} {event : Model.Node.Event}
    {input : Input} (acts : Acts action actor event) (eq : event = .internal input)
    : action = .local actor input := by
  cases action with
  | «local» node input' =>
      obtain ⟨actorEq, eventEq⟩ := acts
      rw [eventEq] at eq
      cases eq
      rw [actorEq]
  | deliver envelope =>
      obtain ⟨_, eventEq⟩ := acts
      rw [eventEq] at eq
      cases eq

variable [Config.InitialConfiguration]

section Trace

variable {trace : Trace} {nodes : List NodeID}
  (execution : trace.ValidFrom Config.INITIAL_CONFIGURATION nodes)

include execution

theorem stable_prefix {leader : NodeID} {term : Nat}
    (stable : LeadsThroughout trace leader term) {index later : Nat} (le : index <= later)
    : (stable.state index).log <+: (stable.state later).log :=
  CCFRaft.Proofs.CommitLiveness.stable_log_prefix execution stable le (stable.found index)
    (stable.found later)

/-- A node's commit index lies within its log. -/
theorem commit_le_length {index : Nat} {node : NodeID} {state : NodeState}
    (found : nodeState (trace.state index) node = some state)
    : state.commitIndex <= state.log.length := by
  obtain ⟨_, exec⟩ := history_at execution index
  exact (now_of_found found).seen.commit_le exec

/-- The step that emitted a packet, the packet among its actor's sends. -/
theorem sent_step {packet : Packet} (sent : trace.Sent packet)
    : exists action actor event state next outputs,
        (trace.event packet.sent).action = some action
        /\ Acts action actor event
        /\ nodeState (trace.state packet.sent) actor = some state
        /\ (Model.Node.step (Capabilities.record actor) actor state event).run {}
            = some (next, outputs)
        /\ nodeState (trace.state (packet.sent + 1)) actor = some next
        /\ outputs.outgoing[packet.ordinal]? = some packet.envelope
        /\ packet.envelope.source = actor := by
  unfold Trace.Sent at sent
  cases selected : (trace.event packet.sent).action with
  | none => simp [selected] at sent
  | some action =>
      obtain ⟨actor, event, state, next, outputs, acts, found, ran, found', out, _⟩ :=
        step_found (CCFRaft.Proofs.Liveness.reachable execution _)
          (execution.step _ action selected)
      simp only [selected, out, Option.bind_some] at sent
      obtain ⟨new, eq, holds⟩ := CCFRaft.Proofs.Safety.summary actor state event {} _ _ ran
      have facts : Summary actor state event next outputs.outgoing := by simpa [eq] using holds
      obtain ⟨sender, _⟩ := Summary.sends facts _ (List.mem_of_getElem? sent)
      exact ⟨
        action,
        actor,
        event,
        state,
        next,
        outputs,
        rfl,
        acts,
        found,
        ran,
        found',
        sent,
        sender
      ⟩

/-- A send of a step, as a packet. -/
theorem sent_of_outgoing {index : Nat} {action : Model.Action}
    (selected : (trace.event index).action = some action) {sends : List Model.Envelope}
    (out : outgoing (trace.state index) action = some sends) {ordinal : Nat}
    {envelope : Model.Envelope} (member : sends[ordinal]? = some envelope)
    : trace.Sent ⟨index, ordinal, envelope⟩ := by
  simp [Trace.Sent, selected, out, member]

/-! ## The stable primary's frontiers -/

/-- How one step moves the stable primary's frontiers for `peer`. -/
theorem leader_move {leader : NodeID} {term : Nat}
    (stable : LeadsThroughout trace leader term) (peer : NodeID) (index : Nat)
    {before after : NodeState}
    (found : nodeState (trace.state index) leader = some before)
    (found' : nodeState (trace.state (index + 1)) leader = some after)
    : (after.matchIndex peer = before.matchIndex peer
        \/ exists envelope response,
            (trace.event index).delivered = some envelope
            /\ envelope.source = peer
            /\ envelope.target = leader
            /\ envelope.payload = .appendEntriesResponse response
            /\ response.success = true
            /\ response.term = term
            /\ after.matchIndex peer = max (before.matchIndex peer) response.lastLogIndex)
      /\ (after.sentIndex peer = before.sentIndex peer
          \/ (exists endIndex,
                trace.event index = .local leader (.sendEntries peer endIndex)
                /\ before.sentIndex peer <= endIndex
                /\ endIndex <= before.log.length
                /\ after.sentIndex peer = endIndex
                /\ trace.Sent
                    ⟨
                      index,
                      0,
                      {
                        source := leader
                        target := peer
                        payload :=
                          .appendEntriesRequest
                            (makeAppendEntriesRequest before peer endIndex)
                      }
                    ⟩)
          \/ (exists envelope response,
                (trace.event index).delivered = some envelope
                /\ envelope.source = peer
                /\ envelope.target = leader
                /\ envelope.payload = .appendEntriesResponse response
                /\ response.success = false
                /\ after.sentIndex peer
                    = max
                        (min
                          (findHighestPossibleMatch before.log response.lastLogIndex
                            response.term)
                          (before.sentIndex peer))
                        (before.matchIndex peer))
          \/ exists contents content,
              trace.event index = .local leader (.append contents)
              /\ content ∈ contents
              /\ Not (content.metadata.configuration = none)
              /\ Not (peer ∈ eligiblePeers before leader)) := by
  cases selected : (trace.event index).action with
  | none =>
      rw [execution.stutter index selected, found, Option.some.injEq] at found'
      subst found'
      exact ⟨Or.inl rfl, Or.inl rfl⟩
  | some action =>
      obtain ⟨actor, event, state, next, outputs, acts, actorFound, ran, actorFound', out, others⟩ :=
        step_found (CCFRaft.Proofs.Liveness.reachable execution index)
          (execution.step index action selected)
      by_cases isLeader : actor = leader
      swap
      · have kept := others leader before (Ne.symm isLeader) found
        rw [found', Option.some.injEq] at kept
        subst kept
        exact ⟨Or.inl rfl, Or.inl rfl⟩
      subst isLeader
      rw [found, Option.some.injEq] at actorFound
      rw [found', Option.some.injEq] at actorFound'
      subst state next
      have beforeEq := stable.state_eq found
      have afterEq := stable.state_eq found'
      have primary : before.role = .primary := by
        rw [beforeEq]; exact stable.primary index
      have afterPrimary : after.role = .primary := by rw [afterEq]; exact stable.primary _
      have beforeTerm : before.currentTerm = term := by
        rw [beforeEq]; exact stable.current index
      have afterTerm : after.currentTerm = term := by rw [afterEq]; exact stable.current _
      obtain ⟨_, _, flow⟩ := leader_flow actor peer before primary event {} _ _ ran
      obtain ⟨matched, sentMove⟩ := flow afterPrimary (afterTerm.trans beforeTerm.symm)
      refine ⟨?_, ?_⟩
      · rcases matched with same | ⟨response, eventEq, success, termEq, value⟩
        · exact Or.inl same
        · obtain ⟨envelope, rfl, targetEq, sourceEq, payloadEq⟩ :=
            acts_receive acts eventEq
          exact Or.inr
            ⟨
              envelope,
              response,
              delivered_of_action selected,
              sourceEq,
              targetEq.symm,
              payloadEq,
              success,
              termEq.trans beforeTerm,
              value
            ⟩
      · rcases sentMove with same | ⟨endIndex, eventEq, le, bound, value⟩
            | ⟨response, eventEq, failure, value⟩ | ⟨contents, content, eventEq, member, config⟩
        · exact Or.inl same
        · have actionEq := acts_internal acts eventEq
          subst actionEq
          rw [eventEq] at ran
          obtain ⟨_, outEq, single⟩ :=
            sendEntries_sends actor before peer endIndex {} _ _ ran
          refine Or.inr (Or.inl ⟨endIndex, event_of_local selected, le, bound, value, ?_⟩)
          exact sent_of_outgoing execution selected out (by simp [outEq, single])
        · obtain ⟨envelope, rfl, targetEq, sourceEq, payloadEq⟩ :=
            acts_receive acts eventEq
          exact Or.inr
            (Or.inr
              (Or.inl
                ⟨
                  envelope,
                  response,
                  delivered_of_action selected,
                  sourceEq,
                  targetEq.symm,
                  payloadEq,
                  failure,
                  value
                ⟩))
        · have actionEq := acts_internal acts eventEq
          subst actionEq
          by_cases eligible : peer ∈ eligiblePeers before actor
          · rw [eventEq] at ran
            obtain ⟨_, _, kept, _⟩ :=
              appendBatch_eligible actor before contents (commit_le_length execution found) {} _
                _ ran
            exact Or.inl (kept peer eligible)
          · exact Or.inr
              (Or.inr
                (Or.inr ⟨contents, content, event_of_local selected, member, config, eligible⟩))

/-- The stable primary's commit index never drops. -/
theorem commit_step {leader : NodeID} {term : Nat}
    (stable : LeadsThroughout trace leader term) (index : Nat)
    : (stable.state index).commitIndex <= (stable.state (index + 1)).commitIndex := by
  cases selected : (trace.event index).action with
  | none =>
      have found' := stable.found (index + 1)
      rw [execution.stutter index selected, stable.found index, Option.some.injEq] at found'
      exact (congrArg NodeState.commitIndex found').le
  | some action =>
      obtain ⟨actor, event, state, next, outputs, acts, actorFound, ran, actorFound', out, others⟩ :=
        step_found (CCFRaft.Proofs.Liveness.reachable execution index)
          (execution.step index action selected)
      by_cases isLeader : actor = leader
      · subst isLeader
        rw [← stable.state_eq actorFound, ← stable.state_eq actorFound']
        exact (CCFRaft.Proofs.Direct.extends_step ran).1
      · have kept := others leader (stable.state index) (Ne.symm isLeader) (stable.found index)
        rw [stable.found (index + 1), Option.some.injEq] at kept
        exact (congrArg NodeState.commitIndex kept).ge

theorem commit_mono {leader : NodeID} {term : Nat}
    (stable : LeadsThroughout trace leader term) {index later : Nat} (le : index <= later)
    : (stable.state index).commitIndex <= (stable.state later).commitIndex :=
  mono_of_step (f := fun index => (stable.state index).commitIndex) (start := 0)
    (fun d _ => commit_step execution stable d) (Nat.zero_le _) le

/-- A rejection delivered to the stable primary from an eligible peer moves that
peer's retry index exactly as the handler computes it. -/
theorem nack_exact {leader : NodeID} {term : Nat}
    (stable : LeadsThroughout trace leader term) {index : Nat} {envelope : Model.Envelope}
    (delivered : (trace.event index).delivered = some envelope)
    (target : envelope.target = leader) {response : AppendEntriesResponse}
    (payload : envelope.payload = .appendEntriesResponse response)
    (failure : response.success = false) {before after : NodeState}
    (found : nodeState (trace.state index) leader = some before)
    (found' : nodeState (trace.state (index + 1)) leader = some after)
    (eligible : envelope.source ∈ eligiblePeers before leader)
    : after.sentIndex envelope.source
      = max
          (min (findHighestPossibleMatch before.log response.lastLogIndex response.term)
            (before.sentIndex envelope.source))
          (before.matchIndex envelope.source) := by
  have selected := action_of_delivered delivered
  obtain ⟨actor, event, state, next, outputs, ⟨actorEq, eventEq⟩, actorFound, ran, actorFound',
      _, _⟩ :=
    step_found (CCFRaft.Proofs.Liveness.reachable execution index)
      (execution.step index _ selected)
  subst actorEq eventEq
  rw [target] at actorFound actorFound' ran
  rw [payload] at ran
  rw [found, Option.some.injEq] at actorFound
  rw [found', Option.some.injEq] at actorFound'
  subst state next
  have primary : before.role = .primary := by rw [stable.state_eq found]; exact stable.primary _
  have beforeTerm : before.currentTerm = term := by
    rw [stable.state_eq found]; exact stable.current _
  have afterTerm : after.currentTerm = term := by
    rw [stable.state_eq found']; exact stable.current _
  have le : response.term <= before.currentTerm := by
    by_contra newer
    have bumped := newer_response_deposes leader envelope.source before after response outputs
      ran eligible primary (Nat.lt_of_not_le newer)
    omega
  obtain ⟨_, _, value⟩ := receive_nack leader before primary envelope.source eligible response
    failure le {} _ _ ran
  exact value

/-- A success of the term or newer delivered to the stable primary from an eligible
peer raises that peer's match index to the acknowledged index. -/
theorem ack_exact {leader : NodeID} {term : Nat} (stable : LeadsThroughout trace leader term)
    {index : Nat} {envelope : Model.Envelope}
    (delivered : (trace.event index).delivered = some envelope)
    (target : envelope.target = leader) {response : AppendEntriesResponse}
    (payload : envelope.payload = .appendEntriesResponse response)
    (success : response.success = true) (current : term <= response.term)
    {before after : NodeState}
    (found : nodeState (trace.state index) leader = some before)
    (found' : nodeState (trace.state (index + 1)) leader = some after)
    (eligible : envelope.source ∈ eligiblePeers before leader)
    : after.matchIndex envelope.source
      = max (before.matchIndex envelope.source) response.lastLogIndex := by
  have selected := action_of_delivered delivered
  obtain ⟨actor, event, state, next, outputs, ⟨actorEq, eventEq⟩, actorFound, ran, actorFound',
      _, _⟩ :=
    step_found (CCFRaft.Proofs.Liveness.reachable execution index)
      (execution.step index _ selected)
  subst actorEq eventEq
  rw [target] at actorFound actorFound' ran
  rw [payload] at ran
  rw [found, Option.some.injEq] at actorFound
  rw [found', Option.some.injEq] at actorFound'
  subst state next
  have primary : before.role = .primary := by rw [stable.state_eq found]; exact stable.primary _
  have beforeTerm : before.currentTerm = term := by
    rw [stable.state_eq found]; exact stable.current _
  have afterTerm : after.currentTerm = term := by
    rw [stable.state_eq found']; exact stable.current _
  have le : response.term <= before.currentTerm := by
    by_contra newer
    have bumped := newer_response_deposes leader envelope.source before after response outputs
      ran eligible primary (Nat.lt_of_not_le newer)
    omega
  obtain ⟨_, _, value⟩ := receive_ack leader before primary envelope.source eligible response
    success (by omega) {} _ _ ran
  exact value

/-! ## AppendEntries traffic -/

/-- A node receiving an AppendEntries request no newer than its term runs `AEStep`,
and the step's sends are exactly the `AEStep` sends. -/
theorem receive_step {index : Nat} {envelope : Model.Envelope}
    (delivered : (trace.event index).delivered = some envelope)
    {request : AppendEntriesRequest}
    (payload : envelope.payload = .appendEntriesRequest request) {before : NodeState}
    (found : nodeState (trace.state index) envelope.target = some before)
    (le : request.term <= before.currentTerm)
    : exists after sends,
        nodeState (trace.state (index + 1)) envelope.target = some after
        /\ AEStep envelope.target envelope.source (awareState before request) request
            after sends
        /\ outgoing (trace.state index) (.deliver envelope) = some sends := by
  have selected := action_of_delivered delivered
  obtain ⟨actor, event, state, next, outputs, ⟨actorEq, eventEq⟩, actorFound, ran, actorFound',
      out, _⟩ :=
    step_found (CCFRaft.Proofs.Liveness.reachable execution index)
      (execution.step index _ selected)
  subst actorEq eventEq
  rw [found, Option.some.injEq] at actorFound
  subst state
  rw [payload] at ran
  obtain ⟨new, outEq, step⟩ := receive_ae envelope.target before envelope.source request le
    {} _ _ ran
  refine ⟨next, new, actorFound', step, ?_⟩
  rw [out, outEq]
  simp

/-- Every AppendEntries response answers an AppendEntries request delivered in the
same step. -/
theorem response_origin {packet : Packet} (sent : trace.Sent packet)
    {response : AppendEntriesResponse}
    (payload : packet.envelope.payload = .appendEntriesResponse response)
    : exists envelope request before,
        (trace.event packet.sent).delivered = some envelope
        /\ envelope.target = packet.envelope.source
        /\ envelope.payload = .appendEntriesRequest request
        /\ nodeState (trace.state packet.sent) envelope.target = some before := by
  obtain ⟨action, actor, event, state, _, outputs, selected, acts, found, ran, _, member,
      source⟩ := sent_step execution sent
  obtain ⟨new, outEq, origins⟩ := origin actor state event {} _ _ ran
  have mem : packet.envelope ∈ new := by
    have := List.mem_of_getElem? member
    rw [outEq] at this
    simpa using this
  obtain ⟨requester, request, eventEq⟩ := (origins _ mem).1 response payload
  obtain ⟨envelope, rfl, targetEq, _, payloadEq⟩ := acts_receive acts eventEq
  refine ⟨envelope, request, state, delivered_of_action selected, ?_, payloadEq, ?_⟩
  · rw [← targetEq, source]
  · rw [← targetEq]
    exact found

/-- Every AppendEntries request a primary sends comes from `sendEntries`, or from
appending a configuration change. -/
theorem request_origin {packet : Packet} (sent : trace.Sent packet)
    {request : AppendEntriesRequest}
    (payload : packet.envelope.payload = .appendEntriesRequest request)
    {before : NodeState}
    (found : nodeState (trace.state packet.sent) packet.envelope.source = some before)
    (primary : before.role = .primary)
    : (exists endIndex,
        trace.event packet.sent
          = .local packet.envelope.source (.sendEntries packet.envelope.target endIndex)
        /\ request = makeAppendEntriesRequest before packet.envelope.target endIndex)
      \/ exists contents content,
          trace.event packet.sent = .local packet.envelope.source (.append contents)
          /\ content ∈ contents
          /\ Not (content.metadata.configuration = none)
          /\ Not
              (packet.envelope.target ∈ eligiblePeers before packet.envelope.source) := by
  obtain ⟨action, actor, event, state, _, _, selected, acts, actorFound, ran, _, member,
      source⟩ := sent_step execution sent
  rw [← source, found, Option.some.injEq] at actorFound
  subst state
  obtain ⟨new, outEq, origins⟩ := origin actor before event {} _ _ ran
  have mem : packet.envelope ∈ new := by
    have := List.mem_of_getElem? member
    rw [outEq] at this
    simpa using this
  rcases (origins _ mem).2 request payload primary with ⟨endIndex, eventEq, requestEq⟩
      | ⟨contents, content, eventEq, contentMem, config⟩
  · have actionEq := acts_internal acts eventEq
    subst actionEq
    exact Or.inl ⟨endIndex, by rw [source]; exact event_of_local selected, requestEq⟩
  · have actionEq := acts_internal acts eventEq
    subst actionEq
    rw [eventEq] at ran
    obtain ⟨new', outEq', _, aimed⟩ :=
      appendBatch_eligible actor before contents
        (commit_le_length execution found) {} _ _ ran
    have mem' : packet.envelope ∈ new' := by
      have := List.mem_of_getElem? member
      rw [outEq'] at this
      simpa using this
    refine Or.inr ⟨contents, content, by rw [source]; exact event_of_local selected, contentMem,
      config, ?_⟩
    rw [source]
    exact aimed _ request mem' payload

end Trace

end CCFRaft.Proofs.Replication
