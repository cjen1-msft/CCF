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

/-- Every send of the execution comes from a step satisfying the step summary. -/
theorem sent_summary {trace : Trace} {nodes : List NodeID}
    (valid : trace.ValidFrom Config.INITIAL_CONFIGURATION nodes) {packet : Packet}
    (sent : trace.Sent packet)
    : exists actor event state next sends,
        nodeState (trace.state (packet.sent + 1)) actor = some next
        /\ Summary actor state event next sends
        /\ packet.envelope ∈ sends := by
  unfold Trace.Sent at sent
  cases selected : (trace.event packet.sent).action with
  | none => simp [selected] at sent
  | some action =>
      obtain ⟨actor, event, state, next, outputs, _, _, ran, found', out, _⟩ :=
        step_found (CCFRaft.Proofs.Liveness.reachable valid _)
          (valid.step _ action selected)
      obtain ⟨new, eq, holds⟩ :=
        CCFRaft.Proofs.Safety.summary actor state event {} _ _ ran
      simp only [selected, out, Option.bind_some] at sent
      refine ⟨actor, event, state, next, outputs.outgoing, found', ?_,
        List.mem_of_getElem? sent⟩
      simpa [eq] using holds

/-- A node's term never decreases along an execution, and the node stays present. -/
theorem term_mono {trace : Trace} {nodes : List NodeID}
    (valid : trace.ValidFrom Config.INITIAL_CONFIGURATION nodes) {node : NodeID}
    {index later : Nat} (le : index <= later) {before : NodeState}
    (found : nodeState (trace.state index) node = some before)
    : exists after,
        nodeState (trace.state later) node = some after
        /\ before.currentTerm <= after.currentTerm := by
  induction later, le using Nat.le_induction with
  | base => exact ⟨before, found, le_rfl⟩
  | succ later _ ih =>
      obtain ⟨middle, middleFound, grows⟩ := ih
      cases selected : (trace.event later).action with
      | none =>
          exact ⟨middle, by rw [valid.stutter later selected]; exact middleFound, grows⟩
      | some action =>
          obtain ⟨actor, event, state, next, outputs, _, actorFound, ran, actorFound', _,
              others⟩ :=
            step_found (CCFRaft.Proofs.Liveness.reachable valid later)
              (valid.step later action selected)
          by_cases same : node = actor
          · subst same
            rw [actorFound, Option.some.injEq] at middleFound
            subst middleFound
            obtain ⟨_, _, facts⟩ :=
              CCFRaft.Proofs.Safety.summary node state event {} _ _ ran
            exact ⟨next, actorFound', grows.trans (Summary.term_le facts)⟩
          · exact ⟨middle, others node middle same middleFound, grows⟩

end Steps

/-! ## Local handlers -/

/-- A heartbeat or replication attempt sends exactly its request. -/
theorem sendEntries_sends (self : NodeID) (state : NodeState) (destination : NodeID)
    (endIndex : Nat)
    : Sends
        (fun (_ : NodeState) sent =>
          sent
          = [{
              source := self
              target := destination
              payload :=
                .appendEntriesRequest
                  (makeAppendEntriesRequest state destination endIndex)
            }])
        (sendEntries (Capabilities.record self) self state destination endIndex) := by
  unfold sendEntries
  refine Sends.bind' Sends.guard' fun _ sent ⟨_, empty⟩ => ?_
  subst empty
  refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' ?_
  simp [eq]

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

section Trace

variable [Config.InitialConfiguration]

/-- Every AppendEntries request a stable primary sends during the execution
carries its term. -/
theorem stable_requests {trace : Trace} {nodes : List NodeID}
    (valid : trace.ValidFrom Config.INITIAL_CONFIGURATION nodes) {leader : NodeID}
    {term : Nat} (stable : LeadsThroughout trace leader term) {packet : Packet}
    (sent : trace.Sent packet) (source : packet.envelope.source = leader)
    {request : AppendEntriesRequest}
    (payload : packet.envelope.payload = .appendEntriesRequest request)
    : request.term = term := by
  obtain ⟨actor, event, state, next, sends, found, facts, member⟩ := sent_summary valid sent
  obtain ⟨sender, ok⟩ := Summary.sends facts _ member
  rw [payload] at ok
  have same : actor = leader := sender.symm.trans source
  subst same
  obtain ⟨_, stableState, stableFound, _, stableTerm, _⟩ := stable (packet.sent + 1)
  rw [found, Option.some.injEq] at stableFound
  subst stableFound
  exact ok.1.2.1.trans stableTerm

end Trace

/-- A stable primary keeps sending requests in its term to a peer that stays live
and eligible. -/
theorem heartbeats_sent (model : LivenessModel) {trace : Trace}
    (valid : model.FairFrom trace) {leader peer : NodeID} {term start : Nat}
    (stable : LeadsThroughout trace leader term)
    (live : forall index, peer ∈ trace.live index)
    (eligible
      : forall index state,
          start <= index
          -> nodeState (trace.state index) leader = some state
          -> peer ∈ eligiblePeers state leader)
    : InfinitelySent trace leader peer (.appendRequest term) := by
  let _ : Config.InitialConfiguration := ⟨model.initialConfiguration⟩
  have execution : trace.ValidFrom Config.INITIAL_CONFIGURATION model.nodes := valid.execution
  have due : forall index, start <= index -> trace.PeerDue leader peer index := by
    intro index afterStart
    obtain ⟨leaderLive, state, found, primary, _, notRetired⟩ := stable index
    exact ⟨leaderLive, live index, state, found, primary, notRetired,
      eligible index state afterStart found⟩
  intro cutoff
  obtain ⟨later, after, sends⟩ :=
    valid.heartbeats (max cutoff start) leader peer (due _ (Nat.le_max_right _ _))
  rcases sends with stopped | ⟨state, frontier, found, event, _⟩
  · exact (stopped (due later (le_trans (Nat.le_max_right _ _) after))).elim
  · have selected
        : (trace.event later).action = some (.local leader (.sendEntries peer frontier)) := by
      rw [event]; rfl
    obtain ⟨actor, localEvent, current, next, outputs, acts, actorFound, ran, _, out, _⟩ :=
      step_found (CCFRaft.Proofs.Liveness.reachable execution later)
        (execution.step later _ selected)
    obtain ⟨same, eventEq⟩ := acts
    subst same eventEq
    rw [found, Option.some.injEq] at actorFound
    subst actorFound
    obtain ⟨new, eq, single⟩ := sendEntries_sends actor state peer frontier {} _ _ ran
    obtain ⟨_, stableState, stableFound, _, stableTerm, _⟩ := stable later
    rw [found, Option.some.injEq] at stableFound
    subst stableFound
    refine ⟨⟨later, 0,
        {
          source := actor
          target := peer
          payload :=
            .appendEntriesRequest (makeAppendEntriesRequest state peer frontier)
        }⟩,
      ?_, le_trans (Nat.le_max_left _ _) after, rfl, rfl, ?_⟩
    · simp [Trace.Sent, selected, out, eq, single]
    · simp [Traffic.Matches, makeAppendEntriesRequest, stableTerm]

/-- Under fair loss between a stable primary and an eligible live peer, the peer
never holds a newer term: it would keep rejecting the primary's heartbeats with
that term, one rejection would be delivered, and the primary would step down.
This is what makes the fair-loss traffic classes cover every newer term. -/
theorem peer_term_le (model : LivenessModel) {trace : Trace} (valid : model.FairFrom trace)
    {leader peer : NodeID} {term start : Nat} {participants : Finset NodeID}
    (stable : LeadsThroughout trace leader term) (fair : FairLoss trace participants)
    (leaderIn : leader ∈ participants) (peerIn : peer ∈ participants)
    (live : forall index, peer ∈ trace.live index)
    (eligible
      : forall index state,
          start <= index
          -> nodeState (trace.state index) leader = some state
          -> peer ∈ eligiblePeers state leader)
    : forall index state,
        start <= index
        -> nodeState (trace.state index) peer = some state
        -> state.currentTerm <= term := by
  let _ : Config.InitialConfiguration := ⟨model.initialConfiguration⟩
  have execution : trace.ValidFrom Config.INITIAL_CONFIGURATION model.nodes := valid.execution
  intro index state _ found
  by_contra notLe
  have ahead : term < state.currentTerm := Nat.lt_of_not_le notLe
  have requests :=
    fair leader peer _ leaderIn peerIn (heartbeats_sent model valid stable live eligible)
  have rejections : InfinitelySent trace peer leader (.response (term + 1) false 0) := by
    intro cutoff
    obtain ⟨delivery, packet, after, event, source, target, matching⟩ :=
      requests (max cutoff index)
    have selected : (trace.event delivery).action = some (.deliver packet.envelope) := by
      rw [event]; rfl
    have sent : trace.Sent packet :=
      (execution.resolution delivery packet (by rw [event]; rfl)).1
    obtain ⟨current, currentFound, grows⟩ :=
      term_mono execution (le_trans (Nat.le_max_right _ _) after) found
    cases payload : packet.envelope.payload with
    | appendEntriesRequest request =>
        have requestTerm := stable_requests execution stable sent source payload
        obtain ⟨actor, localEvent, receiver, next, outputs, acts, actorFound, ran, _, out, _⟩ :=
          step_found (CCFRaft.Proofs.Liveness.reachable execution delivery)
            (execution.step delivery _ selected)
        obtain ⟨same, eventEq⟩ := acts
        subst same eventEq
        rw [target, currentFound, Option.some.injEq] at actorFound
        subst actorFound
        rw [target, source, payload] at ran
        obtain ⟨new, eq, single⟩ :=
          stale_request_sends peer leader current request (by omega) {} _ _ ran
        refine ⟨⟨delivery, 0,
            {
              source := peer
              target := leader
              payload :=
                .appendEntriesResponse
                  {
                    term := current.currentTerm
                    success := false
                    lastLogIndex := current.log.length
                  }
            }⟩,
          ?_, le_trans (Nat.le_max_left _ _) after, rfl, rfl, ?_⟩
        · simp [Trace.Sent, selected, out, eq, single]
        · exact ⟨by dsimp only; omega, rfl, Nat.zero_le _⟩
    | _ => rw [payload] at matching; simp [Traffic.Matches] at matching
  obtain ⟨delivery, packet, after, event, source, target, matching⟩ :=
    fair peer leader _ peerIn leaderIn rejections start
  have selected : (trace.event delivery).action = some (.deliver packet.envelope) := by
    rw [event]; rfl
  cases payload : packet.envelope.payload with
  | appendEntriesResponse response =>
      rw [payload] at matching
      obtain ⟨newer, _, _⟩ := matching
      obtain ⟨actor, localEvent, primary, next, outputs, acts, actorFound, ran, actorFound', _,
          _⟩ :=
        step_found (CCFRaft.Proofs.Liveness.reachable execution delivery)
          (execution.step delivery _ selected)
      obtain ⟨same, eventEq⟩ := acts
      subst same eventEq
      rw [target] at actorFound actorFound' ran
      rw [source, payload] at ran
      obtain ⟨_, before, beforeFound, role, beforeTerm, _⟩ := stable delivery
      rw [actorFound, Option.some.injEq] at beforeFound
      subst beforeFound
      have deposed :=
        newer_response_deposes leader peer primary next response outputs ran
          (eligible delivery primary after actorFound) role (by omega)
      obtain ⟨_, later, laterFound, _, laterTerm, _⟩ := stable (delivery + 1)
      rw [actorFound', Option.some.injEq] at laterFound
      subst laterFound
      omega
  | _ => rw [payload] at matching; simp [Traffic.Matches] at matching

/-- The final commit step along an execution, for an acknowledgement of the
primary's term or newer. -/
theorem ack_commits_trace (model : LivenessModel) {trace : Trace}
    (valid : model.FairFrom trace) {leader : NodeID} {term : Nat}
    (stable : LeadsThroughout trace leader term) {index : Nat} {packet : Packet}
    (event : trace.event index = .deliver packet)
    (target : packet.envelope.target = leader) {response : AppendEntriesResponse}
    (payload : packet.envelope.payload = .appendEntriesResponse response)
    (success : response.success = true) (current : term <= response.term)
    {state : NodeState} (found : nodeState (trace.state index) leader = some state)
    (eligible : packet.envelope.source ∈ eligiblePeers state leader) {signature : Nat}
    (ready : SignatureReady state leader signature)
    : exists after,
        nodeState (trace.state (index + 1)) leader = some after
        /\ signature <= after.commitIndex := by
  let _ : Config.InitialConfiguration := ⟨model.initialConfiguration⟩
  have execution : trace.ValidFrom Config.INITIAL_CONFIGURATION model.nodes := valid.execution
  have selected : (trace.event index).action = some (.deliver packet.envelope) := by
    rw [event]; rfl
  obtain ⟨actor, localEvent, primary, next, outputs, acts, actorFound, ran, actorFound', _, _⟩ :=
    step_found (CCFRaft.Proofs.Liveness.reachable execution index)
      (execution.step index _ selected)
  obtain ⟨same, eventEq⟩ := acts
  subst same eventEq
  rw [target] at actorFound actorFound' ran
  rw [payload] at ran
  rw [found, Option.some.injEq] at actorFound
  subst actorFound
  obtain ⟨_, stableState, stableFound, role, stableTerm, _⟩ := stable index
  rw [found, Option.some.injEq] at stableFound
  subst stableFound
  have le : response.term <= state.currentTerm := by
    by_contra newer
    have bumped := newer_response_deposes leader _ state next response outputs ran eligible role
      (Nat.lt_of_not_le newer)
    obtain ⟨_, later, laterFound, _, laterTerm, _⟩ := stable (index + 1)
    rw [actorFound', Option.some.injEq] at laterFound
    subst laterFound
    omega
  exact ⟨
    next,
    actorFound',
    ack_commits leader _ state next response outputs ran eligible role success (by omega)
      ready
  ⟩

end CCFRaft.Proofs.StablePrimary
