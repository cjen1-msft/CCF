module

public import CCFRaft.Proofs.CommitLiveness

import all Init.Control.State

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Executions with a stable primary

Under the fair-loss traffic classes, which cover a minimum term and every newer one,
an eligible live peer of a stable primary never holds a newer term. Such a peer
rejects every heartbeat with its newer term, one rejection gets through, and the
primary steps down, contradicting stability. With exact-term classes a peer that
keeps moving to newer terms could have all of its rejections dropped.

The final commit step is also proved here: a successful current-term
acknowledgement reaching a primary whose signature is already acknowledged by a
quorum commits that signature.
-/

namespace CCFRaft.Proofs.StablePrimary

open CCFRaft.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Liveness (Admissible)
open HasProtocol (proto)
open HasTime (time)

/-- The node and local event that an action runs. -/
def Acts : Model.Action -> NodeID -> Model.Node.Event -> Prop
  | .local node input, actor, event => actor = node /\ event = .internal input
  | .deliver envelope, actor, event =>
      actor = envelope.target /\ event = .receive envelope.source envelope.payload

section Steps

variable [Config.InitialConfiguration]

/-- One protocol step: its actor's states and sends, other nodes unchanged. -/
theorem step_found {nodes : List NodeID} {before after : Model.State}
    {action : Model.Action}
    (reachable
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).Reachable before)
    (stepped
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).step before action
        = some after)
    : exists actor event state next outputs,
        Acts action actor event
        /\ nodeState before actor = some state
        /\ (Model.Node.step (Capabilities.record actor) actor state event).run {}
            = some (next, outputs)
        /\ nodeState after actor = some next
        /\ outgoing before action = some outputs.outgoing
        /\ forall node other,
            Not (node = actor)
            -> nodeState before node = some other
            -> nodeState after node = some other := by
  have distinct := Direct.keys_nodup (TransitionSystem.Reachable.step reachable stepped)
  cases action with
  | «local» node input =>
      obtain ⟨state, next, outputs, found, ran, rfl⟩ := Concrete.step_local stepped
      have ran' :
          (Model.Node.step (Capabilities.record node) node state (.internal input)).run {}
            = some (next, outputs) := ran
      refine ⟨
        node,
        .internal input,
        state,
        next,
        outputs,
        ⟨rfl, rfl⟩,
        found,
        ran',
        ?_,
        ?_,
        ?_
      ⟩
      · exact Direct.nodeState_of_mem distinct
          (List.mem_map.mpr ⟨(node, state), Concrete.mem_of_nodeState found, by simp⟩)
      · simp [outgoing, found, ran']
      · intro other value different otherFound
        exact Direct.nodeState_of_mem distinct
          (List.mem_map.mpr
            ⟨(other, value), Concrete.mem_of_nodeState otherFound, by simp [different]⟩)
  | deliver envelope =>
      obtain ⟨_, state, next, outputs, found, ran, rfl⟩ := Concrete.step_deliver stepped
      have ran' :
          (Model.Node.step (Capabilities.record envelope.target) envelope.target state
                (.receive envelope.source envelope.payload)).run
              {}
            = some (next, outputs) := ran
      refine ⟨
        envelope.target,
        .receive envelope.source envelope.payload,
        state,
        next,
        outputs,
        ⟨rfl, rfl⟩,
        found,
        ran',
        ?_,
        ?_,
        ?_
      ⟩
      · exact Direct.nodeState_of_mem distinct
          (List.mem_map.mpr ⟨(envelope.target, state), Concrete.mem_of_nodeState found, by simp⟩)
      · simp [outgoing, found, ran']
      · intro other value different otherFound
        exact Direct.nodeState_of_mem distinct
          (List.mem_map.mpr
            ⟨(other, value), Concrete.mem_of_nodeState otherFound, by simp [different]⟩)

end Steps

/-! ## Local handlers -/

/-- A request from an older term is rejected with the receiver's newer term. -/
theorem stale_request_sends (self source : NodeID) (state : NodeState)
    (request : AppendEntriesRequest) (stale : request.term < state.currentTerm)
    : Sends
        (fun (_ : NodeState) sent =>
          sent
          = [{
              source := self
              target := source
              payload :=
                .appendEntriesResponse
                  {
                    term := state.currentTerm
                    success := false
                    lastLogIndex := state.log.length
                  }
            }])
        (receive (Capabilities.record self) self source state
          (.appendEntriesRequest request)) := by
  have observed : observeTerm state (.appendEntriesRequest request) = state :=
    updateTerm_of_le stale.le
  unfold receive
  simp only [observed]
  unfold handleAppendEntriesRequest
  simp only [Nat.ne_of_lt stale, false_and, ite_false, stale, true_or, ite_true]
  refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' ?_
  simp [eq]

/-- A primary that hears of a newer term from an eligible peer stops being primary. -/
theorem newer_response_deposes (self source : NodeID) (state next : NodeState)
    (response : AppendEntriesResponse)
    (outputs : CCF.Outputs NodeID Message Notification)
    (ran
      : (receive (Capabilities.record self) self source state
          (.appendEntriesResponse response)).run
          {}
        = some (next, outputs))
    (eligible : source ∈ eligiblePeers state self) (primary : state.role = .primary)
    (newer : state.currentTerm < response.term)
    : next.currentTerm = response.term := by
  have observed :
      observeTerm state (.appendEntriesResponse response) = bumpedState state response.term := by
    rcases observe_response state response with ⟨_, _, bumped⟩ | ⟨stays, _⟩
    · exact bumped
    · exact absurd (stays primary) (Nat.not_le.mpr newer)
  unfold receive at ran
  simp only [eligible, observed] at ran
  simp [handleAppendEntriesResponse, bumpedState, StateT.run, pure, StateT.pure] at ran
  rw [← ran.1]

theorem hasQuorum_mono {configurations : List Configuration} {small large : Finset NodeID}
    (quorum : hasQuorum configurations small) (sub : small ⊆ large)
    : hasQuorum configurations large := by
  refine ⟨quorum.1, List.all_eq_true.mpr fun configuration member => ?_⟩
  have majority := hasQuorum_majority quorum member
  simp only [hasConfigurationMajority, decide_eq_true_eq] at majority ⊢
  have := Finset.card_le_card (Finset.inter_subset_inter sub (subset_refl configuration.nodes))
  omega

/-- The final commit step: a successful current-term acknowledgement that reaches
a primary holding a quorum-acknowledged current-term signature commits it. -/
theorem ack_commits (self source : NodeID) (state next : NodeState)
    (response : AppendEntriesResponse)
    (outputs : CCF.Outputs NodeID Message Notification)
    (ran
      : (receive (Capabilities.record self) self source state
          (.appendEntriesResponse response)).run
          {}
        = some (next, outputs))
    (eligible : source ∈ eligiblePeers state self) (primary : state.role = .primary)
    (success : response.success = true) (current : response.term = state.currentTerm)
    {signature : Nat} (ready : SignatureReady state self signature)
    : signature <= next.commitIndex := by
  have observed : observeTerm state (.appendEntriesResponse response) = state := by
    rcases observe_response state response with ⟨_, newer, _⟩ | ⟨_, stays⟩
    · omega
    · exact stays
  let updated : NodeState :=
    {
      state with
        matchIndex :=
          Function.update state.matchIndex source
            (max (state.matchIndex source) response.lastLogIndex)
    }
  have ready' : SignatureReady updated self signature := by
    obtain ⟨inLog, isSignature, termEq, quorum⟩ := ready
    refine ⟨inLog, isSignature, termEq, hasQuorum_mono quorum ?_⟩
    intro node member
    simp only [Finset.mem_filter] at member ⊢
    refine ⟨member.1, member.2.imp id fun covered => le_trans covered ?_⟩
    by_cases same : node = source
    · subst same
      simp [updated]
    · simp [updated, Function.update, same]
  have reduces
      : receive (Capabilities.record self) self source state (.appendEntriesResponse response)
        = advanceCommit (Capabilities.record self) updated self := by
    unfold receive
    simp [eligible, observed, handleAppendEntriesResponse, primary, success, current, updated]
  obtain ⟨after, effects, run, committed⟩ :=
    CCFRaft.Proofs.Liveness.acknowledged_signature_commits updated self signature ready'
  rw [reduces, run, Option.some.injEq, Prod.mk.injEq] at ran
  rw [← ran.1]
  exact committed

/-! ## The stable primary's peers -/

section Recorded

variable [Config.InitialConfiguration]
  {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  {nodes : List NodeID} {trace : Trace W Liveness.Event}
  (admissible : Admissible Config.INITIAL_CONFIGURATION nodes trace)

include admissible

/-- Every send of the execution comes from a step satisfying the step summary. -/
theorem sent_summary {index : Nat} {packet : Packet} (sent : trace.SentAt index packet)
    : exists actor event state next sends,
        trace.nodeAt (index + 1) actor = some next
        /\ Summary actor state event next sends
        /\ packet.envelope ∈ sends := by
  obtain ⟨step, action, emitted, stepped, selected, out, member, -⟩ :=
    admissible.sentAt_emitted sent
  obtain ⟨actor, event, state, next, outputs, _, _, ran, found', out', _⟩ :=
    step_found (admissible.reachable_before stepped) (admissible.step stepped selected)
  obtain ⟨new, eq, holds⟩ := CCFRaft.Proofs.Safety.summary actor state event {} _ _ ran
  rw [out', Option.some.injEq] at out
  subst out
  refine ⟨actor, event, state, next, outputs.outgoing, ?_, ?_, member⟩
  · rw [Trace.nodeAt_succ stepped, found']
  · simpa [eq] using holds

/-- A recorded send pass: its effect on the primary, and the recorded sends of its
batches, all at the step's before-time. -/
theorem pass_step {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {leader peer : NodeID}
    {batchEnds : List Nat}
    (event : step.action = .local leader (.sendEntries peer batchEnds))
    {before : NodeState} (found : nodeState (proto step.before) leader = some before)
    : exists after sent,
        nodeState (proto step.after) leader = some after
        /\ Pass leader before peer batchEnds after sent
        /\ forall envelope,
            envelope ∈ sent
            -> exists packet,
                trace.SentAt index packet
                /\ packet.envelope = envelope
                /\ packet.sentAt = time step.before := by
  have selected : step.action.action = some (.local leader (.sendEntries peer batchEnds)) := by
    rw [event]
    rfl
  obtain ⟨actor, localEvent, current, next, outputs, ⟨actorEq, eventEq⟩, actorFound, ran,
      nextFound, out, _⟩ :=
    step_found (admissible.reachable_before stepped) (admissible.step stepped selected)
  subst actorEq eventEq
  rw [found, Option.some.injEq] at actorFound
  subst actorFound
  obtain ⟨sent, outEq, pass⟩ := sendEntries_pass actor before peer batchEnds {} _ _ ran
  rw [outEq] at out
  exact ⟨next, sent, nextFound, pass, fun _ member =>
    admissible.sentAt_of_emitted stepped selected out (List.mem_append_right _ member)⟩

/-- A send pass of a primary whose retirement is not committed records each of its
batches. -/
theorem pass_sends {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {leader peer : NodeID}
    {batchEnds : List Nat}
    (event : step.action = .local leader (.sendEntries peer batchEnds))
    {before : NodeState} (found : nodeState (proto step.before) leader = some before)
    (notRetired : Not (before.isRetiredCommitted leader)) {batch : Nat × Nat}
    (member : batch ∈ passBatches (before.sentIndex peer) batchEnds)
    : exists packet,
        trace.SentAt index packet
        /\ packet.envelope = batchEnvelope before leader peer batch
        /\ packet.sentAt = time step.before := by
  obtain ⟨_, _, _, pass, recorded⟩ := pass_step admissible stepped event found
  exact recorded _ (pass.sent_of_mem notRetired member)

/-- A node's term never decreases along an execution, and the node stays present. -/
theorem term_mono {node : NodeID} {index later : Nat} (le : index <= later)
    {before : NodeState} (found : trace.nodeAt index node = some before)
    {last : W} (lastFound : trace.stateAt later = some last)
    : exists after,
        trace.nodeAt later node = some after
        /\ before.currentTerm <= after.currentTerm := by
  obtain ⟨first, firstFound, nodeFound⟩ := Trace.nodeAt_eq_some.mp found
  obtain ⟨after, afterFound, grows⟩ :=
    admissible.coherent.chain
      (relation := fun first last =>
        forall before,
          nodeState (proto first) node = some before
          -> exists after,
              nodeState (proto last) node = some after
              /\ before.currentTerm <= after.currentTerm)
      (fun _ before found => ⟨before, found, le_rfl⟩)
      (fun _ _ _ first second before found => by
        obtain ⟨middle, middleFound, grows⟩ := first before found
        obtain ⟨after, afterFound, grows'⟩ := second middle middleFound
        exact ⟨after, afterFound, grows.trans grows'⟩)
      (fun _ step stepped middle middleFound => by
        cases selected : step.action.action with
        | none =>
            exact ⟨middle, by rw [admissible.stutter stepped selected]; exact middleFound,
              le_rfl⟩
        | some action =>
            obtain ⟨actor, event, state, next, outputs, _, actorFound, ran, actorFound', _,
                others⟩ :=
              step_found (admissible.reachable_before stepped) (admissible.step stepped selected)
            by_cases same : node = actor
            · subst same
              rw [actorFound, Option.some.injEq] at middleFound
              subst middleFound
              obtain ⟨_, _, facts⟩ := CCFRaft.Proofs.Safety.summary node state event {} _ _ ran
              exact ⟨next, actorFound', Summary.term_le facts⟩
            · exact ⟨middle, others node middle same middleFound, le_rfl⟩)
      le firstFound lastFound before nodeFound
  exact ⟨after, by rw [Trace.nodeAt_of_stateAt lastFound, afterFound], grows⟩

/-- Every AppendEntries request a stable primary sends from `start` on carries its
term. -/
theorem stable_requests {start : Nat} {leader : NodeID} {term : Nat}
    (stable : StableLeader trace start leader term) {sent : Nat} {packet : Packet}
    (afterStart : start <= sent) (sentAt : trace.SentAt sent packet)
    (source : packet.envelope.source = leader) {request : AppendEntriesRequest}
    (payload : packet.envelope.payload = .appendEntriesRequest request)
    : request.term = term := by
  obtain ⟨actor, event, state, next, sends, found, facts, member⟩ :=
    sent_summary admissible sentAt
  obtain ⟨sender, ok⟩ := Summary.sends facts _ member
  rw [payload] at ok
  have same : actor = leader := sender.symm.trans source
  subst same
  exact ok.1.2.1.trans (stable.current (Nat.le_succ_of_le afterStart) found)

/-- A stable primary keeps sending requests in its term to a peer that stays live
and eligible. -/
theorem heartbeats_sent {bound : Option Real}
    (heartbeats : trace.HeartbeatScheduling bound) {start : Nat} {leader peer : NodeID}
    {term : Nat} (stable : StableLeader trace start leader term)
    (live
      : forall index point,
          start <= index -> trace.stateAt index = some point -> peer ∈ HasLive.live point)
    (eligible
      : forall index state,
          start <= index
          -> trace.nodeAt index leader = some state
          -> peer ∈ eligiblePeers state leader)
    : InfinitelySent trace leader peer (.appendRequest term) := by
  obtain ⟨first, firstFound⟩ := stable.1
  have due
      : forall index point,
          start <= index -> trace.stateAt index = some point -> PeerDue point leader peer := by
    intro index point le found
    obtain ⟨leaderLive, state, nodeFound, primary, _, notRetired⟩ := stable.leads le found
    exact ⟨leaderLive, live index point le found, state, nodeFound, primary, notRetired,
      eligible index state le (by rw [Trace.nodeAt_of_stateAt found, nodeFound])⟩
  intro cutoff
  obtain ⟨index, step, after, stepped, batchEnds, event⟩ :=
    (heartbeats leader peer).often firstFound due (max cutoff start)
  have afterStart := Nat.le_trans (Nat.le_max_right _ _) after
  obtain ⟨_, state, found, _, _, notRetired⟩ :=
    stable.leads afterStart (admissible.before stepped)
  have stateTerm :=
    stable.current afterStart (by rw [admissible.nodeAt_before stepped, found])
  obtain ⟨_, _, _, pass, _⟩ := pass_step admissible stepped event found
  obtain ⟨batch, member⟩ := passBatches_nonempty pass.valid
  obtain ⟨packet, sent, envelope, -⟩ :=
    pass_sends admissible stepped event found notRetired member
  refine ⟨index, packet, sent, Nat.le_trans (Nat.le_max_left _ _) after, ?_, ?_, ?_⟩ <;>
    simp [envelope, Traffic.Matches, batchEnvelope, makeAppendEntriesRequest, stateTerm]

/-- Under fair loss between a stable primary and an eligible live peer, the peer
never holds a newer term: it would keep rejecting the primary's heartbeats with
that term, one rejection would be delivered, and the primary would step down.
This is what makes the fair-loss traffic classes cover every newer term. -/
theorem peer_term_le {bound : Option Real} (heartbeats : trace.HeartbeatScheduling bound)
    {start : Nat} {leader peer : NodeID} {term : Nat} {participants : Finset NodeID}
    (stable : StableLeader trace start leader term) (fair : FairLoss trace participants)
    (leaderIn : leader ∈ participants) (peerIn : peer ∈ participants)
    (live
      : forall index point,
          start <= index -> trace.stateAt index = some point -> peer ∈ HasLive.live point)
    (eligible
      : forall index state,
          start <= index
          -> trace.nodeAt index leader = some state
          -> peer ∈ eligiblePeers state leader)
    : forall index state,
        start <= index
        -> trace.nodeAt index peer = some state
        -> state.currentTerm <= term := by
  intro index state _ found
  by_contra notLe
  have ahead : term < state.currentTerm := Nat.lt_of_not_le notLe
  have requests :=
    fair leader peer _ leaderIn peerIn (heartbeats_sent admissible heartbeats stable live eligible)
  obtain ⟨stop, _, horizon⟩ := admissible.horizon start
  have rejections : InfinitelySent trace peer leader (.response (term + 1) false 0) := by
    intro cutoff
    obtain ⟨delivery, step, packet, after, stepped, action, source, target, matching⟩ :=
      requests (max cutoff (max index stop))
    have selected : step.action.action = some (.deliver packet.envelope) := by
      rw [action]; rfl
    obtain ⟨sent, sentAfter, _, sentAt⟩ :=
      horizon delivery step packet (by omega) stepped (by rw [action]; rfl)
    obtain ⟨current, currentFound, grows⟩ :=
      term_mono admissible (show index <= delivery by omega) found (admissible.before stepped)
    cases payload : packet.envelope.payload with
    | appendEntriesRequest request =>
        have requestTerm := stable_requests admissible stable sentAfter sentAt source payload
        obtain ⟨actor, localEvent, receiver, next, outputs, acts, actorFound, ran, _, out, _⟩ :=
          step_found (admissible.reachable_before stepped) (admissible.step stepped selected)
        obtain ⟨same, eventEq⟩ := acts
        subst same eventEq
        rw [admissible.nodeAt_before stepped] at currentFound
        rw [target, currentFound, Option.some.injEq] at actorFound
        subst actorFound
        rw [target, source, payload] at ran
        obtain ⟨new, eq, single⟩ :=
          stale_request_sends peer leader current request (by omega) {} _ _ ran
        rw [eq, single] at out
        obtain ⟨reply, replySent, envelope, -⟩ :=
          admissible.sentAt_of_emitted stepped selected out
            (List.mem_append_right _ (List.mem_singleton_self _))
        refine ⟨delivery, reply, replySent, by omega, ?_, ?_, ?_⟩ <;> rw [envelope]
        exact ⟨by dsimp only; omega, rfl, Nat.zero_le _⟩
    | _ => rw [payload] at matching; simp [Traffic.Matches] at matching
  obtain ⟨delivery, step, packet, after, stepped, action, source, target, matching⟩ :=
    fair peer leader _ peerIn leaderIn rejections start
  have selected : step.action.action = some (.deliver packet.envelope) := by
    rw [action]; rfl
  cases payload : packet.envelope.payload with
  | appendEntriesResponse response =>
      rw [payload] at matching
      obtain ⟨newer, _, _⟩ := matching
      obtain ⟨actor, localEvent, primary, next, outputs, acts, actorFound, ran, actorFound', _,
          _⟩ :=
        step_found (admissible.reachable_before stepped) (admissible.step stepped selected)
      obtain ⟨same, eventEq⟩ := acts
      subst same eventEq
      rw [target] at actorFound actorFound' ran
      rw [source, payload] at ran
      have beforeNode : trace.nodeAt delivery leader = some primary := by
        rw [admissible.nodeAt_before stepped, actorFound]
      have deposed :=
        newer_response_deposes leader peer primary next response outputs ran
          (eligible delivery primary after beforeNode) (stable.primary after beforeNode)
          (by have := stable.current after beforeNode; omega)
      have afterNode : trace.nodeAt (delivery + 1) leader = some next := by
        rw [Trace.nodeAt_succ stepped, actorFound']
      have := stable.current (Nat.le_succ_of_le after) afterNode
      omega
  | _ => rw [payload] at matching; simp [Traffic.Matches] at matching

/-- The final commit step along an execution, for an acknowledgement of the
primary's term or newer. -/
theorem ack_commits_trace {start : Nat} {leader : NodeID} {term : Nat}
    (stable : StableLeader trace start leader term) {index : Nat}
    (afterStart : start <= index) {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {packet : Packet}
    (action : step.action = .deliver packet) (target : packet.envelope.target = leader)
    {response : AppendEntriesResponse}
    (payload : packet.envelope.payload = .appendEntriesResponse response)
    (success : response.success = true) (current : term <= response.term)
    {state : NodeState} (found : trace.nodeAt index leader = some state)
    (eligible : packet.envelope.source ∈ eligiblePeers state leader) {signature : Nat}
    (ready : SignatureReady state leader signature)
    : exists after,
        trace.nodeAt (index + 1) leader = some after
        /\ signature <= after.commitIndex := by
  have selected : step.action.action = some (.deliver packet.envelope) := by
    rw [action]; rfl
  obtain ⟨actor, localEvent, primary, next, outputs, acts, actorFound, ran, actorFound', _, _⟩ :=
    step_found (admissible.reachable_before stepped) (admissible.step stepped selected)
  obtain ⟨same, eventEq⟩ := acts
  subst same eventEq
  rw [target] at actorFound actorFound' ran
  rw [payload] at ran
  have role := stable.primary afterStart found
  have stableTerm := stable.current afterStart found
  rw [admissible.nodeAt_before stepped, actorFound, Option.some.injEq] at found
  subst found
  have afterNode : trace.nodeAt (index + 1) leader = some next := by
    rw [Trace.nodeAt_succ stepped, actorFound']
  have le : response.term <= primary.currentTerm := by
    by_contra newer
    have bumped := newer_response_deposes leader _ primary next response outputs ran eligible role
      (Nat.lt_of_not_le newer)
    have := stable.current (Nat.le_succ_of_le afterStart) afterNode
    omega
  exact ⟨
    next,
    afterNode,
    ack_commits leader _ primary next response outputs ran eligible role success
      (by omega) ready
  ⟩

end Recorded

end CCFRaft.Proofs.StablePrimary
