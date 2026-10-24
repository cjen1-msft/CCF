module

public import CCFRaft.Proofs.Leadership.Settles
public import CCFRaft.Proofs.Leadership.Ledger
public import CCFRaft.Proofs.Replication.Link

@[expose] public section

/-!
# Participants in sync with the primary

`InSync` is a state premise at the start of a window that replaces the trace
premise `WindowMatching`: every participant other than the primary is at the
term, holds a prefix of the primary's log, has no rejection outstanding to the
primary, and the primary's outstanding AppendEntries to it, in send order,
chain from the end of its log to the primary's `sentIndex` for it.

Channels are FIFO, so the request a participant receives from the primary is
always the first of that chain, which starts at the end of the participant's
log and so passes its log check. The participant accepts it, so the rest of the
chain starts at the participant's new log end; the primary's passes extend the
chain from its `sentIndex`. So the window keeps every participant in sync, and
every request from the primary to a participant in the window matches.
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
open HasNetwork (pending issued)

/-- The AppendEntries request an envelope carries from `leader` to `peer`, if any. -/
def requestFor (leader peer : NodeID) (envelope : Model.Envelope)
    : Option AppendEntriesRequest :=
  if envelope.source = leader /\ envelope.target = peer then
    match envelope.payload with
    | .appendEntriesRequest request => some request
    | _ => none
  else
    none

/-- The AppendEntries requests outstanding from `leader` to `peer`, in ledger order. -/
def queued (leader peer : NodeID) (packets : List Packet) : List AppendEntriesRequest :=
  packets.filterMap fun packet => requestFor leader peer packet.envelope

/-- Requests of `term` that chain from `low` to `high`: each starts where the last
ended. -/
def Chain (term : Nat) : Nat -> List AppendEntriesRequest -> Nat -> Prop
  | low, [], high => low = high
  | low, request :: rest, high =>
      request.term = term
      /\ request.prevLogIndex = low
      /\ Chain term (low + request.entries.length) rest high

/-- A rejection from `peer` to `leader`. -/
def Nack (peer leader : NodeID) (envelope : Model.Envelope) : Prop :=
  envelope.source = peer
  /\ envelope.target = leader
  /\ exists response,
      envelope.payload = .appendEntriesResponse response /\ response.success = false

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]

/-- `peer`, in state `state`, is in sync with `leader`, in state `leaderState`, at
`point`. -/
structure InSyncWith (leader : NodeID) (term : Nat) (peer : NodeID) (point : W)
    (leaderState state : NodeState)
    : Prop where
  leaderFound : nodeState (proto point) leader = some leaderState
  found : nodeState (proto point) peer = some state
  /-- Needed: a participant of an older term still accepts AppendEntries from a
  participant that was primary of that term. That old primary can rewrite the
  participant's log after the primary of `term` has sent it requests chained
  from the old log, and the next of those requests then fails its log check. -/
  current : state.currentTerm = term
  prefix_ : state.log <+: leaderState.log
  chain
    : Chain term state.log.length (queued leader peer (pending point))
        (leaderState.sentIndex peer)
  /-- Needed: the primary handles a rejection of any term by rewinding its
  `sentIndex` for the peer to the retry hint, but not below its `matchIndex`. A
  stale rejection with a stale `matchIndex` rewinds it below the peer's commit
  index. The peer silently ignores the batch from there, as it starts below its
  commit index, and the next heartbeat, chained from that batch's end, fails its
  log check. -/
  noNack : forall packet, packet ∈ pending point -> Not (Nack peer leader packet.envelope)

/-- At `start`, every participant other than the primary is in sync with it. -/
def InSync (trace : Trace W Liveness.Event) (start : Nat) (leader : NodeID) (term : Nat)
    (participants : Finset NodeID)
    : Prop :=
  forall first peer,
    trace.stateAt start = some first
    -> peer ∈ participants
    -> Not (peer = leader)
    -> exists leaderState state, InSyncWith leader term peer first leaderState state

/-! ## Queued requests -/

theorem requestFor_some {leader peer : NodeID} {envelope : Model.Envelope}
    {request : AppendEntriesRequest}
    (some_ : requestFor leader peer envelope = some request)
    : envelope.source = leader
      /\ envelope.target = peer
      /\ envelope.payload = .appendEntriesRequest request := by
  unfold requestFor at some_
  split at some_
  · rename_i ends
    split at some_
    · rename_i payload
      cases some_
      exact ⟨ends.1, ends.2, payload⟩
    · cases some_
  · cases some_

theorem requestFor_of {leader peer : NodeID} {envelope : Model.Envelope}
    {request : AppendEntriesRequest} (source : envelope.source = leader)
    (target : envelope.target = peer)
    (payload : envelope.payload = .appendEntriesRequest request)
    : requestFor leader peer envelope = some request := by
  simp [requestFor, source, target, payload]

theorem requestFor_source {leader peer : NodeID} {envelope : Model.Envelope}
    (different : Not (envelope.source = leader))
    : requestFor leader peer envelope = none := by
  simp [requestFor, different]

theorem requestFor_target {leader peer : NodeID} {envelope : Model.Envelope}
    (different : Not (envelope.target = peer))
    : requestFor leader peer envelope = none := by
  simp [requestFor, different]

theorem queued_append (leader peer : NodeID) (front back : List Packet)
    : queued leader peer (front ++ back)
      = queued leader peer front ++ queued leader peer back :=
  List.filterMap_append

theorem queued_batch (leader peer : NodeID) (emitted : List Model.Envelope) (first : Nat)
    (sentAt : Real)
    : queued leader peer (Packet.batch emitted first sentAt)
      = emitted.filterMap (requestFor leader peer) := by
  unfold queued Packet.batch
  rw [List.filterMap_map]
  have : (fun packet : Packet => requestFor leader peer packet.envelope)
        ∘ (fun (pair : Model.Envelope × Nat) =>
            ({ id := pair.2, envelope := pair.1, sentAt } : Packet))
      = requestFor leader peer ∘ Prod.fst := rfl
  rw [this, ← List.filterMap_map, List.zipIdx_map_fst]

/-- A packet taken from the ledger, with only packets of other channels before it,
is the first queued request when it is one. -/
theorem queued_split {leader peer : NodeID} {front back : List Packet} {packet : Packet}
    (others
      : forall other,
          other ∈ front
          -> other.envelope.source = packet.envelope.source
          -> Not (other.envelope.target = packet.envelope.target))
    : queued leader peer (front ++ packet :: back)
      = (requestFor leader peer packet.envelope).toList
        ++ queued leader peer (front ++ back) := by
  cases found : requestFor leader peer packet.envelope with
  | none => simp [queued, List.filterMap_append, found]
  | some request =>
      obtain ⟨source, target, _⟩ := requestFor_some found
      have empty : queued leader peer front = [] := by
        rw [queued, List.filterMap_eq_nil_iff]
        intro other member
        by_cases otherSource : other.envelope.source = leader
        · exact requestFor_target fun otherTarget =>
            others other member (otherSource.trans source.symm)
              (otherTarget.trans target.symm)
        · exact requestFor_source otherSource
      rw [queued_append, queued_append, empty]
      simp [queued, found]

/-- A packet that is no queued request leaves the queue unchanged. -/
theorem queued_skip {leader peer : NodeID} {front back : List Packet} {packet : Packet}
    (none_ : requestFor leader peer packet.envelope = none)
    : queued leader peer (front ++ packet :: back)
      = queued leader peer (front ++ back) := by
  simp [queued, List.filterMap_append, none_]

/-! ## Chains -/

theorem Chain.append {term : Nat}
    : forall {low middle high : Nat} {first : List AppendEntriesRequest}
              {second : List AppendEntriesRequest},
        Chain term low first middle
        -> Chain term middle second high
        -> Chain term low (first ++ second) high
  | _, _, _, [], _, first, second => by
      cases first
      exact second
  | _, _, _, _ :: _, _, ⟨termEq, prev, rest⟩, second =>
      ⟨termEq, prev, Chain.append rest second⟩

/-- A pass chains its batches from where it starts to the end of the log. -/
theorem chain_pass {term : Nat} (state : NodeState) (current : state.currentTerm = term)
    : forall {previousIndex : Nat} {batchEnds : List Nat},
        isPass state.log previousIndex batchEnds = true
        -> Chain term previousIndex
            ((passBatches previousIndex batchEnds).map
              fun batch =>
                makeAppendEntriesRequest state batch.1 batch.2)
            state.log.length
  | _, [], pass => by simp [isPass] at pass
  | previousIndex, [endIndex], pass => by
      simp only [isPass, Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq] at pass
      refine ⟨current, rfl, ?_⟩
      show previousIndex + (messageEntries state.log previousIndex endIndex).length = _
      rw [messageEntries_length (by omega)]
      omega
  | previousIndex, endIndex :: next :: rest, pass => by
      simp only [isPass, Bool.and_eq_true, decide_eq_true_eq] at pass
      have tail := chain_pass state current pass.2
      refine ⟨current, rfl, ?_⟩
      show Chain term (previousIndex + (messageEntries state.log previousIndex endIndex).length)
        ((passBatches endIndex (next :: rest)).map fun batch =>
          makeAppendEntriesRequest state batch.1 batch.2) state.log.length
      rw [messageEntries_length (by omega), show previousIndex + (endIndex - previousIndex)
        = endIndex by omega]
      exact tail

/-- The requests of a pass to `peer`, as `peer` receives them. -/
theorem requests_pass (state : NodeState) (self peer : NodeID)
    (batches : List (Nat × Nat))
    : (batches.map (batchEnvelope state self peer)).filterMap (requestFor self peer)
      = batches.map fun batch => makeAppendEntriesRequest state batch.1 batch.2 := by
  induction batches with
  | nil => rfl
  | cons batch rest ih =>
      rw [List.map_cons, List.filterMap_cons, ih, List.map_cons,
        requestFor_of (leader := self) (peer := peer)
          (envelope := batchEnvelope state self peer batch) rfl rfl rfl]

/-- A request that ends the log it is sent to matches it in no entry. -/
theorem conflictIndex_end {log : List Entry} {request : AppendEntriesRequest}
    (prev : request.prevLogIndex = log.length)
    : conflictIndex log request = none := by
  unfold conflictIndex
  rw [List.drop_eq_nil_of_le (by omega)]
  simp

/-- A request that ends the log it is sent to appends its entries. -/
theorem acceptLog_end {log : List Entry} {request : AppendEntriesRequest}
    (prev : request.prevLogIndex = log.length)
    : acceptLog log request = log ++ request.entries := by
  unfold acceptLog
  rw [conflictIndex_end prev]
  simp [prev]

theorem awareState_commit (state : NodeState) (request : AppendEntriesRequest)
    : (awareState state request).commitIndex = state.commitIndex := by
  unfold awareState
  split <;> rfl

/-- Every response of an AppendEntries step goes back to the requester. -/
theorem aeStep_target {self source : NodeID} {state after : NodeState}
    {request : AppendEntriesRequest} {sent : List Model.Envelope}
    (step : AEStep self source state request after sent) {envelope : Model.Envelope}
    (member : envelope ∈ sent)
    : envelope.target = source := by
  rcases step with ⟨_, _, rfl⟩ | ⟨_, _, _, _, rfl⟩ | ⟨_, _, _, _, _, _, _, _, _, _, rfl⟩
  · rw [List.mem_singleton.mp member]
  · cases member
  · rw [List.mem_singleton.mp member]

omit [HasProtocol W Model.State] [HasLive W] in
/-- No NACK is pending after a step that emits none, if none was pending before. -/
theorem noNack_after {step : CCF.Execution.Step W Liveness.Event}
    {emitted : List Model.Envelope}
    (ledger
      : pending step.after
        = step.action.remaining (pending step.before)
          ++ Packet.batch emitted (issued step.before) (time step.before))
    {peer leader : NodeID}
    (old
      : forall packet,
          packet ∈ pending step.before -> Not (Nack peer leader packet.envelope))
    (new : forall envelope, envelope ∈ emitted -> Not (Nack peer leader envelope))
    : forall packet,
        packet ∈ pending step.after -> Not (Nack peer leader packet.envelope) := by
  intro packet member
  rw [ledger, List.mem_append] at member
  rcases member with kept | fresh
  · exact old packet (Event.mem_remaining kept)
  · obtain ⟨ordinal, found, _, _⟩ := Packet.mem_batch.mp fresh
    exact new _ (List.mem_of_getElem? found)

section Recorded

variable [Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event}
  (admissible
    : Admissible (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) trace)

include admissible

/-- A step's ledger update, with the envelopes its protocol action emits. -/
theorem ledger_step {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step)
    : exists emitted,
        pending step.after
          = step.action.remaining (pending step.before)
            ++ Packet.batch emitted (issued step.before) (time step.before)
        /\ (step.action.action = none -> emitted = [])
        /\ forall action,
            step.action.action = some action
            -> outgoing (proto step.before) action = some emitted := by
  obtain ⟨_, _, emitted, produced, _, ledger⟩ := admissible.delivery.next stepped
  refine ⟨emitted, ledger, fun selected => ?_, fun action selected => ?_⟩
  · simp only [selected, Option.some.injEq] at produced
    exact produced.symm
  · simp only [selected, Option.bind_eq_bind, Option.bind_eq_some_iff] at produced
    obtain ⟨_, _, out⟩ := produced
    exact out

/-- The queue after a step that consumes no queued request. -/
theorem queued_after {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {emitted : List Model.Envelope}
    (ledger
      : pending step.after
        = step.action.remaining (pending step.before)
          ++ Packet.batch emitted (issued step.before) (time step.before))
    {leader peer : NodeID}
    (skip
      : forall packet,
          step.action.consumedPacket = some packet
          -> requestFor leader peer packet.envelope = none)
    : queued leader peer (pending step.after)
      = queued leader peer (pending step.before)
        ++ emitted.filterMap (requestFor leader peer) := by
  rw [ledger, queued_append, queued_batch]
  congr 1
  cases consumed : step.action.consumedPacket with
  | none =>
      unfold Event.remaining
      rw [consumed]
  | some packet =>
      obtain ⟨front, back, split, remaining, _⟩ := admissible.consumed_split stepped consumed
      rw [remaining, split, queued_skip (skip packet consumed)]

/-- The request a participant in sync receives from the primary is the first of its
chain: it starts at the end of the participant's log, with the primary's term
there, and its entries continue the participant's log along the primary's. -/
theorem head_request {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {leader : NodeID} {term : Nat}
    {peer : NodeID} {leaderState state : NodeState}
    (sync : InSyncWith leader term peer step.before leaderState state)
    (primary : leaderState.role = .primary) (leaderTerm : leaderState.currentTerm = term)
    {packet : Packet} (delivered : step.action = .deliver packet)
    {request : AppendEntriesRequest}
    (found : requestFor leader peer packet.envelope = some request)
    : request.term = term
      /\ request.prevLogIndex = state.log.length
      /\ request.prevLogTerm = termAt state.log state.log.length
      /\ state.log ++ request.entries <+: leaderState.log
      /\ Chain term (state.log.length + request.entries.length)
          (queued leader peer (step.action.remaining (pending step.before)))
          (leaderState.sentIndex peer) := by
  obtain ⟨front, back, split, remaining, others⟩ := admissible.delivered_split stepped delivered
  have chain := sync.chain
  rw [split, queued_split others, found] at chain
  simp only [Option.toList_some, List.singleton_append] at chain
  obtain ⟨requestTerm, prev, rest⟩ := chain
  obtain ⟨history, exec⟩ := history_at admissible (admissible.before stepped)
  have lead : Lead nodes (proto step.before :: history) leader term leaderState :=
    ⟨exec, now_of_found sync.leaderFound, primary, leaderTerm⟩
  obtain ⟨_, _, payload⟩ := requestFor_some found
  have selected : step.action.action = some (.deliver packet.envelope) := by
    rw [delivered]
    rfl
  have queuedNow := (Concrete.step_deliver (admissible.step stepped selected)).1
  obtain ⟨_, _, _, prevTerm, entries⟩ := lead.request queuedNow payload requestTerm
  obtain ⟨tail, logEq⟩ := sync.prefix_
  refine ⟨requestTerm, prev, ?_, ?_, ?_⟩
  · rw [prevTerm, prev, termAt_of_prefix ⟨tail, logEq⟩ le_rfl]
  · rw [← logEq, prev, List.drop_left] at entries
    rw [← logEq]
    exact (List.prefix_append_right_inj state.log).mpr entries
  · rw [remaining]
    exact rest

/-- Participants in sync with the primary before a step pass the log check of the
primary's request delivered by it. -/
theorem matches_at {start : Nat} {duration : Real} {leader : NodeID} {term : Nat}
    {participants : Finset NodeID} {index : Nat}
    {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step)
    (quiet : QuietAmong participants leader term (proto step.before))
    (sync
      : forall peer,
          peer ∈ participants
          -> Not (peer = leader)
          -> exists leaderState state,
              InSyncWith leader term peer step.before leaderState state)
    : MatchesAt trace start duration leader term participants index := by
  intro step' packet request state _ stepped' delivered source targetIn different payload
    found _ _ _
  rw [stepped, Option.some.injEq] at stepped'
  subst stepped'
  obtain ⟨leaderState, peerState, sync⟩ := sync _ targetIn different
  rw [sync.found, Option.some.injEq] at found
  subst found
  obtain ⟨leaderState', leaderFound, primary, leaderTerm⟩ :=
    quietAmong_leader admissible (admissible.before stepped) quiet
  rw [sync.leaderFound, Option.some.injEq] at leaderFound
  subst leaderFound
  obtain ⟨_, prev, prevTerm, _⟩ :=
    head_request admissible stepped sync primary leaderTerm delivered
      (requestFor_of source rfl payload)
  rw [prev, prevTerm]

/-- A participant other than the primary, of the term on both sides of a step,
changes its log only by receiving an AppendEntries request from the primary. -/
theorem peer_log {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {leader : NodeID} {term : Nat}
    {leaderState : NodeState}
    (leaderFound : nodeState (proto step.before) leader = some leaderState)
    (primary : leaderState.role = .primary) (leaderTerm : leaderState.currentTerm = term)
    {peer : NodeID} (different : Not (peer = leader)) {pre post : NodeState}
    (preFound : nodeState (proto step.before) peer = some pre)
    (postFound : nodeState (proto step.after) peer = some post)
    (preTerm : pre.currentTerm = term) (postTerm : post.currentTerm = term)
    (changed : Not (post.log = pre.log))
    : exists packet request,
        step.action = .deliver packet
        /\ packet.envelope.source = leader
        /\ packet.envelope.target = peer
        /\ packet.envelope.payload = .appendEntriesRequest request := by
  cases selected : step.action.action with
  | none =>
      rw [admissible.stutter stepped selected, preFound, Option.some.injEq] at postFound
      exact absurd (by rw [postFound]) changed
  | some action =>
      obtain ⟨rest, c, acts, _⟩ := ctx_at admissible stepped selected
      have actorEq : c.tr.actor = peer := by
        by_contra other
        have kept :=
          found_of_now c.exec (c.now_other (Ne.symm other) (now_of_found preFound))
        rw [postFound, Option.some.injEq] at kept
        exact changed (by rw [kept])
      have prePre : c.tr.pre = pre := by
        have found := c.tr.found
        rw [actorEq, preFound, Option.some.injEq] at found
        exact found.symm
      have postPost : c.tr.post = post := by
        have found := found_of_now c.exec c.post_now
        rw [show c.actor = peer from actorEq, postFound, Option.some.injEq] at found
        exact found.symm
      have lead : Lead nodes (proto step.before :: rest) leader term leaderState :=
        ⟨c.prior, now_of_found leaderFound, primary, leaderTerm⟩
      have changed' : Not (c.post.log = c.pre.log) := by
        show Not (c.tr.post.log = c.tr.pre.log)
        rw [prePre, postPost]
        exact changed
      have postTerm' : c.post.currentTerm = term := by
        show c.tr.post.currentTerm = term
        rw [postPost, postTerm]
      have notLeader : Not (c.actor = leader) := by
        show Not (c.tr.actor = leader)
        rw [actorEq]
        exact different
      cases Summary.kind c.sum with
      | same log _ => exact absurd log changed'
      | append _ _ primary _ _ _ =>
          have led := c.inv.leader_led c.actor c.pre c.pre_now primary
          have preTerm' : c.pre.currentTerm = term := by
            show c.tr.pre.currentTerm = term
            rw [prePre, preTerm]
          rw [preTerm'] at led
          exact absurd (lead.unique led) notLeader
      | ack _ _ _ _ _ _ advance => exact absurd (Advance.facts advance).1 changed'
      | elect wins =>
          have led
              : Led (proto step.after :: proto step.before :: rest) c.actor term := by
            rw [← postTerm']
            exact Or.inr ⟨_, _, _, _, rest, List.suffix_refl _, c.wins_elect wins⟩
          have inv := good_of_exec c.exec _ (List.suffix_refl _) (List.cons_ne_nil _ _)
          exact absurd (inv.election_safety _ _ _ led (lead.led.mono c.suffix_tail))
            notLeader
      | accept source request eq accepted =>
          have requestTerm := accepted.1
          rw [postTerm'] at requestTerm
          obtain ⟨queued_, pending_, queuedSource, _, queuedPayload⟩ := c.received eq
          obtain ⟨sourceEq, _⟩ := lead.request pending_ queuedPayload requestTerm
          rw [queuedSource] at sourceEq
          obtain ⟨envelope, rfl, targetEq, envelopeSource, envelopePayload⟩ :=
            acts_receive acts eq
          obtain ⟨packet, event, packetEnvelope⟩ :=
            packet_of_delivered (delivered_of_action selected)
          refine ⟨packet, request, event, ?_, ?_, ?_⟩
          · rw [packetEnvelope, envelopeSource, sourceEq]
          · rw [packetEnvelope, ← targetEq]
            exact actorEq
          · rw [packetEnvelope, envelopePayload]

end Recorded

end CCFRaft.Proofs.Leadership
