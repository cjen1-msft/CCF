module

public import CCFRaft.Proofs.Replication.Run

import all Init.Control.State

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# The link from the stable primary to one peer

Facts about the AppendEntries traffic between the stable primary and a peer of
its term: what the primary sends, what a delivered request carries, and how the
peer's log compares with the primary's at every index.
-/

open CCF CCF.MultiNodeTransitionSystem
open CCFRaft
open CCFRaft.Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Config
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.StablePrimary

namespace CCFRaft.Proofs.Replication

theorem sendEntries_guard (self : NodeID) (before : NodeState) (destination : NodeID)
    (endIndex : Nat)
    : Sends
        (fun after (_ : List Model.Envelope) =>
          before.sentIndex destination <= endIndex
          /\ endIndex <= before.log.length
          /\ after.sentIndex destination = endIndex)
        (sendEntries (Capabilities.record self) self before destination endIndex) := by
  unfold sendEntries
  refine Sends.bind' Sends.guard' fun _ sent ⟨⟨_, _, le, bound, _⟩, empty⟩ => ?_
  subst empty
  refine Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' ⟨le, bound, ?_⟩
  simp

theorem messageEntries_length {log : List Entry} {previous batchEnd : Nat}
    (bound : batchEnd <= log.length)
    : (messageEntries log previous batchEnd).length = batchEnd - previous := by
  simp only [messageEntries, List.length_take, List.length_drop]
  omega

variable [Config.InitialConfiguration]

/-- What a node's state says about its log relative to the primary's log. -/
structure View (leaderLog : List Entry) (term : Nat) (state : NodeState)
    (matchIndex : Nat)
    : Prop where
  matching
    : forall index,
        0 < index
        -> index <= state.log.length
        -> index <= leaderLog.length
        -> termAt state.log index = termAt leaderLog index
        -> state.log.take index = leaderLog.take index
  commit : state.commitIndex <= agree state.log leaderLog
  settled : Settled state -> state.log <+: leaderLog
  sorted : state.log.Pairwise fun first second => first.term <= second.term
  positive
    : forall index, 0 < index -> index <= state.log.length -> 0 < termAt state.log index
  matchLe : matchIndex <= agree state.log leaderLog
  leaderSorted : leaderLog.Pairwise fun first second => first.term <= second.term
  leaderTerms : forall index, termAt leaderLog index <= term
  leaderPositive
    : forall index, 0 < index -> index <= leaderLog.length -> 0 < termAt leaderLog index

section Trace

variable {trace : Trace} {nodes : List NodeID}
  (execution : trace.ValidFrom Config.INITIAL_CONFIGURATION nodes)
  {leader : NodeID} {term : Nat} (stable : LeadsThroughout trace leader term)

include execution stable

/-- A peer of the term, seen against the stable primary at the same index. -/
theorem view_at {peer : NodeID} (different : Not (peer = leader)) {index : Nat}
    {state : NodeState} (found : nodeState (trace.state index) peer = some state)
    (current : state.currentTerm = term)
    : View (stable.state index).log term state
        ((stable.state index).matchIndex peer) := by
  obtain ⟨rest, exec⟩ := history_at execution index
  have lead := lead_at execution stable exec (stable.found index)
  have now := now_of_found (rest := rest) found
  exact {
    matching := fun _ positive bound leaderBound same =>
      lead.matching now.seen positive bound leaderBound same
    commit := lead.commit_le now current.le
    settled := fun settled => lead.settled_prefix now settled current
    sorted := lead.inv.sorted peer state now
    positive := fun _ positive bound => termAt_pos lead.inv now positive bound
    matchLe := lead.match_le different now current
    leaderSorted := lead.sorted
    leaderTerms := lead.termAt_le
    leaderPositive := fun _ positive bound => termAt_pos lead.inv lead.now positive bound
  }

/-- A request of the term delivered at an index is a slice of the stable
primary's log at that index. -/
theorem request_at {index : Nat} {envelope : Model.Envelope}
    (delivered : (trace.event index).delivered = some envelope)
    {request : AppendEntriesRequest}
    (payload : envelope.payload = .appendEntriesRequest request)
    (current : request.term = term)
    : envelope.source = leader
      /\ Not (envelope.target = leader)
      /\ request.prevLogIndex <= (stable.state index).log.length
      /\ request.prevLogTerm = termAt (stable.state index).log request.prevLogIndex
      /\ request.entries <+: (stable.state index).log.drop request.prevLogIndex := by
  obtain ⟨rest, exec⟩ := history_at execution index
  have lead := lead_at execution stable exec (stable.found index)
  have queued := (Concrete.step_deliver
    (execution.step index _ (action_of_delivered delivered))).1
  exact lead.request queued payload current

/-- A `sendEntries` step of the stable primary sends exactly one request and moves
the peer's frontier to the batch end. -/
theorem send_step {index : Nat} {peer : NodeID} {endIndex : Nat}
    (event : trace.event index = .local leader (.sendEntries peer endIndex))
    : (stable.state index).sentIndex peer <= endIndex
      /\ endIndex <= (stable.state index).log.length
      /\ (stable.state (index + 1)).sentIndex peer = endIndex
      /\ trace.Sent
          ⟨
            index,
            0,
            {
              source := leader
              target := peer
              payload :=
                .appendEntriesRequest
                  (makeAppendEntriesRequest (stable.state index) peer endIndex)
            }
          ⟩ := by
  have selected : (trace.event index).action = some (.local leader (.sendEntries peer endIndex)) := by
    rw [event]
    rfl
  obtain ⟨actor, localEvent, state, next, outputs, ⟨actorEq, eventEq⟩, found, ran, found', out,
      _⟩ :=
    step_found (CCFRaft.Proofs.Liveness.reachable execution index)
      (execution.step index _ selected)
  subst actorEq eventEq
  rw [stable.state_eq found] at ran
  rw [stable.state_eq found'] at ran
  obtain ⟨_, _, le, bound, frontier⟩ :=
    sendEntries_guard actor (stable.state index) peer endIndex {} _ _ ran
  obtain ⟨_, outEq, single⟩ := sendEntries_sends actor (stable.state index) peer endIndex {} _ _ ran
  refine ⟨le, bound, frontier, ?_⟩
  exact sent_of_outgoing execution selected out (by simp [outEq, single])

/-- Every request of the stable primary to a peer eligible when it was sent is a
`sendEntries` batch of the primary's log. -/
theorem leader_request {packet : Packet}
    (eligible : packet.envelope.target ∈ eligiblePeers (stable.state packet.sent) leader)
    (sent : trace.Sent packet) (source : packet.envelope.source = leader)
    {request : AppendEntriesRequest}
    (payload : packet.envelope.payload = .appendEntriesRequest request)
    : exists endIndex,
        trace.event packet.sent
          = .local leader (.sendEntries packet.envelope.target endIndex)
        /\ request
            = makeAppendEntriesRequest (stable.state packet.sent) packet.envelope.target
                endIndex := by
  have found : nodeState (trace.state packet.sent) packet.envelope.source
      = some (stable.state packet.sent) := by
    rw [source]
    exact stable.found _
  rcases request_origin execution sent payload found
      (stable.primary _) with ⟨endIndex, event, requestEq⟩
      | ⟨_, _, _, _, _, aimed⟩
  · rw [source] at event
    exact ⟨endIndex, event, requestEq⟩
  · rw [source] at aimed
    exact absurd eligible aimed

/-- The shape of a stable primary's request to `peer`. -/
theorem leader_request_shape {packet : Packet}
    (eligible : packet.envelope.target ∈ eligiblePeers (stable.state packet.sent) leader)
    (sent : trace.Sent packet) (source : packet.envelope.source = leader)
    {request : AppendEntriesRequest}
    (payload : packet.envelope.payload = .appendEntriesRequest request)
    : request.term = term
      /\ request.prevLogIndex
          = (stable.state packet.sent).sentIndex packet.envelope.target
      /\ request.prevLogIndex + request.entries.length
          = (stable.state (packet.sent + 1)).sentIndex packet.envelope.target
      /\ request.prevLogIndex + request.entries.length
          <= (stable.state packet.sent).log.length := by
  obtain ⟨endIndex, event, rfl⟩ := leader_request execution stable eligible sent source payload
  obtain ⟨le, bound, frontier, _⟩ := send_step execution stable event
  refine ⟨stable.current _, rfl, ?_, ?_⟩ <;>
    simp only [makeAppendEntriesRequest, messageEntries_length bound] <;> omega

/-- A node that receives a request is at least at the request's term afterwards. -/
theorem request_term_le {index : Nat} {envelope : Model.Envelope}
    (delivered : (trace.event index).delivered = some envelope)
    {request : AppendEntriesRequest}
    (payload : envelope.payload = .appendEntriesRequest request) {after : NodeState}
    (found' : nodeState (trace.state (index + 1)) envelope.target = some after)
    : request.term <= after.currentTerm := by
  have selected := action_of_delivered delivered
  obtain ⟨actor, localEvent, state, next, outputs, ⟨actorEq, eventEq⟩, _, ran, actorFound', _,
      _⟩ :=
    step_found (CCFRaft.Proofs.Liveness.reachable execution index)
      (execution.step index _ selected)
  subst actorEq eventEq
  rw [payload] at ran
  rw [found', Option.some.injEq] at actorFound'
  subst actorFound'
  obtain ⟨_, _, received, _⟩ :=
    CCFRaft.Proofs.Safety.receive_ae_term envelope.target state envelope.source request {} _ _ ran
  exact received

/-- Once a peer receives a request of the term, it stays at the term or newer. -/
theorem term_after_request {index : Nat} {envelope : Model.Envelope}
    (delivered : (trace.event index).delivered = some envelope)
    {request : AppendEntriesRequest}
    (payload : envelope.payload = .appendEntriesRequest request)
    (newer : term <= request.term) {later : Nat} (lt : index < later)
    : exists state,
        nodeState (trace.state later) envelope.target = some state
        /\ term <= state.currentTerm := by
  have selected := action_of_delivered delivered
  obtain ⟨actor, localEvent, state, next, outputs, ⟨actorEq, eventEq⟩, _, ran, found', _, _⟩ :=
    step_found (CCFRaft.Proofs.Liveness.reachable execution index)
      (execution.step index _ selected)
  subst actorEq eventEq
  rw [payload] at ran
  obtain ⟨_, _, received, _⟩ :=
    CCFRaft.Proofs.Safety.receive_ae_term envelope.target state envelope.source request {} _ _ ran
  obtain ⟨after, found, grows⟩ := term_mono execution lt found'
  exact ⟨after, found, newer.trans (received.trans grows)⟩

end Trace

end CCFRaft.Proofs.Replication
