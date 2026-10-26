module

public import CCFRaft.Proofs.Leadership.Settles
public import CCFRaft.Proofs.Leadership.Ledger
public import CCFRaft.Proofs.Replication.Link

@[expose] public section

/-!
# Participants in sync with the primary

`InSync`, defined in `Liveness/Assumptions/Settles.lean`, is a state premise at
the start of a window that replaces the trace premise `WindowMatching`: every
participant other than the primary is at the term, holds a prefix of the
primary's log, has no rejection outstanding to the primary, and the primary's
outstanding AppendEntries to it, in send order, chain from the end of its log to
the primary's `sentIndex` for it.

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

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]

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

/-- What a node step sends: its summary, and where its AppendEntries traffic comes
from. -/
theorem step_facts {self : NodeID} {pre post : NodeState} {event : Model.Node.Event}
    {outputs}
    (ran
      : (Model.Node.step (Capabilities.record self) self pre event).run {}
        = some (post, outputs))
    : Summary self pre event post outputs.outgoing
      /\ forall envelope, envelope ∈ outputs.outgoing -> Origin pre event envelope := by
  obtain ⟨_, eq, holds⟩ := CCFRaft.Proofs.Safety.summary self pre event {} _ _ ran
  obtain ⟨_, eq', origins⟩ := CCFRaft.Proofs.Safety.origin self pre event {} _ _ ran
  refine ⟨by simpa [eq] using holds, fun envelope member => origins envelope ?_⟩
  rw [eq'] at member
  simpa using member

omit [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W] in
/-- A participant's term stays at the quiet term. -/
theorem term_settles {participants : Finset NodeID} {leader : NodeID} {term : Nat}
    {state : Model.State} (quiet : QuietTerm participants leader term state)
    {node : NodeID} (nodeIn : node ∈ participants) {pre post : NodeState}
    (found : nodeState state node = some post) (preTerm : pre.currentTerm = term)
    (le : pre.currentTerm <= post.currentTerm)
    : post.currentTerm = term := by
  have := quiet.terms node post (Concrete.mem_of_nodeState found) nodeIn
  omega

section Recorded

variable [Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event}
  (admissible : Admissible Config.INITIAL_CONFIGURATION nodes trace)

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
  have chain := sync.inflightChain
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
    (quiet : QuietTerm participants leader term (proto step.before))
    (sync
      : forall peer,
          peer ∈ participants
          -> Not (peer = leader)
          -> exists leaderState state,
              InSyncWith leader term peer step.before leaderState state)
    : MatchesAt trace start duration leader term participants index := by
  intro step' packet request state _ stepped' delivered source targetIn different payload
    found _ _ _ _
  rw [stepped, Option.some.injEq] at stepped'
  subst stepped'
  obtain ⟨leaderState, peerState, sync⟩ := sync _ targetIn different
  rw [sync.found, Option.some.injEq] at found
  subst found
  obtain ⟨leaderState', leaderFound, primary, leaderTerm⟩ :=
    quietTerm_leader admissible (admissible.before stepped) quiet
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

/-- A step that consumes and emits no request from the primary to `peer` and no
rejection from `peer`, keeps the primary's log and `sentIndex` for `peer` and
`peer`'s log and term, keeps `peer` in sync. -/
theorem sync_keep {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {emitted : List Model.Envelope}
    (ledger
      : pending step.after
        = step.action.remaining (pending step.before)
          ++ Packet.batch emitted (issued step.before) (time step.before))
    {leader : NodeID} {term : Nat} {peer : NodeID} {leaderState state : NodeState}
    (sync : InSyncWith leader term peer step.before leaderState state)
    {leaderState' state' : NodeState}
    (leaderFound : nodeState (proto step.after) leader = some leaderState')
    (found : nodeState (proto step.after) peer = some state')
    (skip
      : forall packet,
          step.action.consumedPacket = some packet
          -> requestFor leader peer packet.envelope = none)
    (quietSends
      : forall envelope,
          envelope ∈ emitted
          -> requestFor leader peer envelope = none /\ Not (Nack peer leader envelope))
    (sent : leaderState'.sentIndex peer = leaderState.sentIndex peer)
    (grows : leaderState.log <+: leaderState'.log) (log : state'.log = state.log)
    (current : state'.currentTerm = term)
    : InSyncWith leader term peer step.after leaderState' state' := by
  refine ⟨leaderFound, found, current, ?_, ?_, ?_⟩
  · rw [log]
    exact sync.prefix_.trans grows
  · have none_ : emitted.filterMap (requestFor leader peer) = [] :=
      List.filterMap_eq_nil_iff.mpr fun envelope member => (quietSends envelope member).1
    rw [queued_after admissible stepped ledger skip, none_, List.append_nil, log, sent]
    exact sync.inflightChain
  · exact noNack_after ledger sync.noNack fun envelope member => (quietSends envelope member).2

/-- A participant other than the primary stays in sync with it across a step of
the window in which the term stays quiet among participants. -/
theorem sync_step {start : Nat} {duration : Real} {leader : NodeID} {term : Nat}
    {participants : Finset NodeID} {index : Nat}
    {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step)
    (within : Within trace start duration index)
    (good : GoodPeriod trace start duration participants)
    (active : Window.StaysActive trace start duration leader)
    (leaderIn : leader ∈ participants)
    (quiet : QuietTerm participants leader term (proto step.before))
    (quiet' : QuietTerm participants leader term (proto step.after)) {peer : NodeID}
    (peerIn : peer ∈ participants) (different : Not (peer = leader))
    {leaderState state : NodeState}
    (sync : InSyncWith leader term peer step.before leaderState state)
    : exists leaderState' state',
        InSyncWith leader term peer step.after leaderState' state' := by
  obtain ⟨emitted, ledger, silent, out⟩ := ledger_step admissible stepped
  obtain ⟨leaderState', leaderFound', primary', leaderTerm'⟩ :=
    quietTerm_leader admissible (Trace.stateAt_succ_of_stepAt stepped) quiet'
  obtain ⟨leaderState_, leaderFound_, primary_, leaderTerm_⟩ :=
    quietTerm_leader admissible (admissible.before stepped) quiet
  have same_ : leaderState_ = leaderState := by
    rw [sync.leaderFound, Option.some.injEq] at leaderFound_
    exact leaderFound_.symm
  have primary : leaderState.role = .primary := same_ ▸ primary_
  have leaderTerm : leaderState.currentTerm = term := same_ ▸ leaderTerm_
  have stutterCase
      : step.action.action = none
        -> (forall packet,
              step.action.consumedPacket = some packet
              -> requestFor leader peer packet.envelope = none)
        -> exists leaderState' state',
            InSyncWith leader term peer step.after leaderState' state' := by
    intro selected skip
    have same := admissible.stutter stepped selected
    have empty := silent selected
    subst empty
    exact ⟨leaderState, state,
      sync_keep admissible stepped ledger sync (by rw [same]; exact sync.leaderFound)
        (by rw [same]; exact sync.found) skip (fun _ member => by cases member) rfl
        (List.prefix_refl _) rfl sync.current⟩
  cases eventEq : step.action with
  | crash node =>
      exact stutterCase
        (by rw [eventEq]; rfl)
        (by rw [eventEq]; intro _ consumed; simp [Event.consumedPacket] at consumed)
  | idle =>
      exact stutterCase
        (by rw [eventEq]; rfl)
        (by rw [eventEq]; intro _ consumed; simp [Event.consumedPacket] at consumed)
  | drop packet =>
      refine stutterCase (by rw [eventEq]; rfl) ?_
      rw [eventEq]
      intro dropped consumed
      simp only [Event.consumedPacket, Option.some.injEq] at consumed
      subst consumed
      cases found : requestFor leader peer packet.envelope with
      | none => rfl
      | some request =>
          obtain ⟨source, target, _⟩ := requestFor_some found
          exact absurd ⟨by rw [source]; exact leaderIn, by rw [target]; exact peerIn⟩
            (good.lossless index step packet within stepped eventEq)
  | «local» node input =>
      have selected : step.action.action = some (.local node input) := by
        rw [eventEq]
        rfl
      obtain ⟨actor, event, pre, post, outputs, acts, actorFound, ran, actorFound', outEq,
          others⟩ :=
        step_found (admissible.reachable_before stepped) (admissible.step stepped selected)
      obtain ⟨actorEq, eventEq'⟩ := acts
      subst eventEq'
      have emittedEq : outputs.outgoing = emitted := by
        have := out _ selected
        rw [outEq, Option.some.injEq] at this
        exact this
      subst emittedEq
      obtain ⟨facts, origins⟩ := step_facts ran
      have skip
          : forall packet,
              step.action.consumedPacket = some packet
              -> requestFor leader peer packet.envelope = none := by
        rw [eventEq]
        intro _ consumed
        simp [Event.consumedPacket] at consumed
      rw [← actorEq] at eventEq
      by_cases isLeader : actor = leader
      · subst isLeader
        rw [sync.leaderFound, Option.some.injEq] at actorFound
        rw [leaderFound', Option.some.injEq] at actorFound'
        subst actorFound actorFound'
        have peerKept := others peer state different sync.found
        by_cases toPeer : exists ends, input = .sendEntries peer ends
        · obtain ⟨ends, rfl⟩ := toPeer
          obtain ⟨sent, sentEq, pass⟩ := sendEntries_pass actor leaderState peer ends {} _ _ ran
          have sentEq' : outputs.outgoing = sent := by simpa using sentEq
          have notRetired :=
            active.notRetired index step.before leaderState within (admissible.before stepped)
              sync.leaderFound
          obtain ⟨sentIndexEq, sentList⟩ := pass.complete notRetired
          have logEq : leaderState'.log = leaderState.log := by rw [pass.state]
          refine ⟨leaderState', state, leaderFound', peerKept, sync.current,
            by rw [logEq]; exact sync.prefix_, ?_, ?_⟩
          · rw [queued_after admissible stepped ledger skip, sentEq', sentList, requests_pass,
              sentIndexEq]
            exact Chain.append sync.inflightChain (chain_pass leaderState leaderTerm pass.valid)
          · refine noNack_after ledger sync.noNack fun envelope member nack => ?_
            exact different (nack.1.symm.trans (Summary.sends facts envelope member).1)
        · obtain ⟨_, _, flow⟩ := leader_flow actor peer leaderState primary (.internal input) {} _ _ ran
          obtain ⟨_, sentMove⟩ := flow primary' (leaderTerm'.trans leaderTerm.symm)
          have sentSame : leaderState'.sentIndex peer = leaderState.sentIndex peer := by
            rcases sentMove with same | ⟨ends, inputEq, _⟩ | ⟨_, inputEq, _⟩
                | ⟨contents, content, inputEq, member, config⟩
            · exact same
            · cases inputEq
              exact absurd ⟨ends, rfl⟩ toPeer
            · cases inputEq
            · cases inputEq
              exact absurd
                (good.noReconfiguration index step actor contents within stepped eventEq content
                  member) config
          obtain ⟨rest, c, _, _⟩ := ctx_at admissible stepped selected
          have grows :=
            CCFRaft.Proofs.CommitLiveness.primary_log_prefix c.prior c.exec
              (List.suffix_cons _ _) sync.leaderFound leaderFound' primary primary'
              (leaderTerm.trans leaderTerm'.symm)
          refine ⟨
            leaderState',
            state,
            sync_keep admissible stepped ledger sync leaderFound' peerKept skip
              (fun envelope member => ⟨?_, fun nack => ?_⟩) sentSame grows rfl
              sync.current
          ⟩
          · cases found : requestFor actor peer envelope with
            | none => rfl
            | some request =>
                obtain ⟨_, target, payload⟩ := requestFor_some found
                rcases (origins envelope member).2 request payload primary
                    with ⟨ends, _, inputEq, _⟩ | ⟨contents, content, inputEq, contentIn, config⟩
                · cases inputEq
                  rw [target] at toPeer
                  exact absurd ⟨ends, rfl⟩ toPeer
                · cases inputEq
                  exact absurd
                    (good.noReconfiguration index step actor contents within stepped eventEq
                      content contentIn) config
          · exact different (nack.1.symm.trans (Summary.sends facts envelope member).1)
      · have leaderKept := others leader leaderState (fun h => isLeader h.symm) sync.leaderFound
        by_cases isPeer : actor = peer
        · subst isPeer
          rw [sync.found, Option.some.injEq] at actorFound
          subst actorFound
          have current := term_settles quiet' peerIn actorFound' sync.current (Summary.term_le facts)
          have logSame : post.log = state.log := by
            by_contra changed
            obtain ⟨_, _, delivered, _⟩ :=
              peer_log admissible stepped sync.leaderFound primary leaderTerm different sync.found
                actorFound' sync.current current changed
            rw [eventEq] at delivered
            cases delivered
          refine ⟨leaderState, post,
            sync_keep admissible stepped ledger sync leaderKept actorFound' skip
              (fun envelope member => ⟨requestFor_source ?_, fun nack => ?_⟩) rfl
              (List.prefix_refl _) logSame current⟩
          · rw [(Summary.sends facts envelope member).1]
            exact isLeader
          · obtain ⟨_, _, response, payload, _⟩ := nack
            obtain ⟨_, _, inputEq⟩ := (origins envelope member).1 response payload
            cases inputEq
        · have peerKept := others peer state (fun h => isPeer h.symm) sync.found
          refine ⟨leaderState, state,
            sync_keep admissible stepped ledger sync leaderKept peerKept skip
              (fun envelope member => ⟨requestFor_source ?_, fun nack => ?_⟩) rfl
              (List.prefix_refl _) rfl sync.current⟩
          · rw [(Summary.sends facts envelope member).1]
            exact isLeader
          · exact isPeer ((Summary.sends facts envelope member).1.symm.trans nack.1)
  | deliver packet =>
      have selected : step.action.action = some (.deliver packet.envelope) := by
        rw [eventEq]
        rfl
      have delivered : step.action.delivered = some packet.envelope := by
        rw [eventEq]
        rfl
      have member : packet ∈ pending step.before :=
        admissible.consumed_pending stepped (by rw [eventEq]; rfl)
      obtain ⟨actor, event, pre, post, outputs, acts, actorFound, ran, actorFound', outEq,
          others⟩ :=
        step_found (admissible.reachable_before stepped) (admissible.step stepped selected)
      obtain ⟨actorEq, eventEq'⟩ := acts
      subst eventEq' actorEq
      have emittedEq : outputs.outgoing = emitted := by
        have := out _ selected
        rw [outEq, Option.some.injEq] at this
        exact this
      subst emittedEq
      obtain ⟨facts, origins⟩ := step_facts ran
      have skipOf
          : Not (packet.envelope.target = peer)
            -> forall other,
                step.action.consumedPacket = some other
                -> requestFor leader peer other.envelope = none := by
        intro notPeer other consumed
        rw [eventEq] at consumed
        simp only [Event.consumedPacket, Option.some.injEq] at consumed
        subst consumed
        exact requestFor_target notPeer
      by_cases toLeader : packet.envelope.target = leader
      · rw [toLeader, sync.leaderFound, Option.some.injEq] at actorFound
        rw [toLeader, leaderFound', Option.some.injEq] at actorFound'
        subst actorFound actorFound'
        have peerKept := others peer state (fun h => different (h.trans toLeader)) sync.found
        obtain ⟨_, _, flow⟩ :=
          leader_flow packet.envelope.target peer leaderState primary _ {} _ _ ran
        obtain ⟨_, sentMove⟩ := flow primary' (leaderTerm'.trans leaderTerm.symm)
        have sentSame : leaderState'.sentIndex peer = leaderState.sentIndex peer := by
          rcases sentMove with same | ⟨_, inputEq, _⟩ | ⟨response, inputEq, failure, _⟩
              | ⟨_, _, inputEq, _⟩
          · exact same
          · cases inputEq
          · injection inputEq with sourceEq payloadEq
            exact absurd ⟨sourceEq, toLeader, response, payloadEq, failure⟩
              (sync.noNack packet member)
          · cases inputEq
        obtain ⟨rest, c, _, _⟩ := ctx_at admissible stepped selected
        have grows :=
          CCFRaft.Proofs.CommitLiveness.primary_log_prefix c.prior c.exec
            (List.suffix_cons _ _) sync.leaderFound leaderFound' primary primary'
            (leaderTerm.trans leaderTerm'.symm)
        refine ⟨leaderState', state,
          sync_keep admissible stepped ledger sync leaderFound' peerKept
            (skipOf fun h => different (h.symm.trans toLeader))
            (fun envelope member => ⟨?_, fun nack => ?_⟩) sentSame grows rfl sync.current⟩
        · cases found : requestFor leader peer envelope with
          | none => rfl
          | some request =>
              obtain ⟨_, _, payload⟩ := requestFor_some found
              rcases (origins envelope member).2 request payload primary
                  with ⟨_, _, inputEq, _⟩ | ⟨_, _, inputEq, _⟩
              · cases inputEq
              · cases inputEq
        · exact different (nack.1.symm.trans ((Summary.sends facts envelope member).1.trans toLeader))
      by_cases toPeer : packet.envelope.target = peer
      · rw [toPeer, sync.found, Option.some.injEq] at actorFound
        subst actorFound
        have leaderKept :=
          others leader leaderState (fun h => different (toPeer.symm.trans h.symm))
            sync.leaderFound
        have targetIn : packet.envelope.target ∈ participants := by
          rw [toPeer]
          exact peerIn
        have sourceIn := good.isolated index step packet.envelope within stepped delivered targetIn
        have inNetwork := (Concrete.step_deliver (admissible.step stepped selected)).1
        have peerFound : nodeState (proto step.before) packet.envelope.target = some state := by
          rw [toPeer]
          exact sync.found
        cases found : requestFor leader peer packet.envelope with
        | some request =>
            obtain ⟨_, _, payload⟩ := requestFor_some found
            obtain ⟨requestTerm, prev, prevTerm, extends_, rest⟩ :=
              head_request admissible stepped sync primary leaderTerm eventEq found
            obtain ⟨after, sends, afterFound, aeStep, sendsEq⟩ :=
              receive_step admissible stepped delivered payload peerFound
                (by rw [requestTerm, sync.current])
            have sendsEq' : sends = outputs.outgoing := by
              rw [sendsEq, Option.some.injEq] at outEq
              exact outEq
            have commitLe :=
              commit_le_length admissible (node := peer)
                (by rw [admissible.nodeAt_before stepped, sync.found])
            rcases aeStep with ⟨reject, _, _⟩ | ⟨_, _, ignore, _, _⟩
                | ⟨_, _, _, _, afterTerm, _, afterLog, _, _, _, sent⟩
            · exfalso
              rcases reject with lower | mismatch
              · rw [awareState_term, sync.current, requestTerm] at lower
                exact lt_irrefl _ lower
              · exact mismatch
                  ⟨by rw [awareState_log, prev], by rw [awareState_log, prev, prevTerm]⟩
            · exfalso
              rcases ignore with lower | ⟨conflict, _⟩
              · rw [awareState_commit, prev] at lower
                omega
              · rw [awareState_log, conflictIndex_end prev] at conflict
                simp at conflict
            · rw [awareState_log, acceptLog_end prev] at afterLog
              have none_ : sends.filterMap (requestFor leader peer) = [] := by
                rw [sent]
                simp [requestFor]
              refine ⟨leaderState, after, leaderKept, by rw [← toPeer]; exact afterFound,
                by rw [afterTerm, awareState_term, sync.current], by rw [afterLog]; exact extends_,
                ?_, ?_⟩
              · rw [ledger, queued_append, queued_batch, ← sendsEq', none_, List.append_nil,
                  afterLog, List.length_append]
                exact rest
              · refine noNack_after ledger sync.noNack fun envelope member nack => ?_
                rw [← sendsEq', sent] at member
                obtain ⟨_, _, response, payload, failure⟩ := nack
                rw [List.mem_singleton.mp member] at payload
                simp only [Message.appendEntriesResponse.injEq] at payload
                subst payload
                simp at failure
        | none =>
            have current :=
              term_settles quiet' peerIn (by rw [← toPeer]; exact actorFound') sync.current
                (Summary.term_le facts)
            have logSame : post.log = state.log := by
              by_contra changed
              obtain ⟨other, request, delivered', source, target, payload⟩ :=
                peer_log admissible stepped sync.leaderFound primary leaderTerm different
                  sync.found (by rw [← toPeer]; exact actorFound') sync.current current changed
              rw [eventEq] at delivered'
              injection delivered' with otherEq
              subst otherEq
              rw [requestFor_of source target payload] at found
              cases found
            refine ⟨
              leaderState,
              post,
              sync_keep admissible stepped ledger sync leaderKept
                (by rw [← toPeer]; exact actorFound') (fun other consumed => ?_)
                (fun envelope member => ⟨requestFor_source ?_, fun nack => ?_⟩) rfl
                (List.prefix_refl _) logSame current
            ⟩
            · rw [eventEq] at consumed
              simp only [Event.consumedPacket, Option.some.injEq] at consumed
              subst consumed
              exact found
            · rw [(Summary.sends facts envelope member).1, toPeer]
              exact different
            · obtain ⟨_, nackTarget, response, payload, _⟩ := nack
              obtain ⟨_, request, inputEq⟩ := (origins envelope member).1 response payload
              injection inputEq with sourceEq payloadEq
              have le : request.term <= state.currentTerm := by
                have := quiet.messages packet.envelope inNetwork sourceIn targetIn
                rw [payloadEq] at this
                rw [sync.current]
                exact this
              obtain ⟨_, sends, _, aeStep, sendsEq⟩ :=
                receive_step admissible stepped delivered payloadEq peerFound le
              rw [sendsEq, Option.some.injEq] at outEq
              have back := aeStep_target aeStep (by rw [outEq]; exact member)
              rw [requestFor_of (back.symm.trans nackTarget) toPeer payloadEq] at found
              cases found
      · have leaderKept :=
          others leader leaderState (fun h => toLeader h.symm) sync.leaderFound
        have peerKept := others peer state (fun h => toPeer h.symm) sync.found
        refine ⟨leaderState, state,
          sync_keep admissible stepped ledger sync leaderKept peerKept (skipOf toPeer)
            (fun envelope member => ⟨requestFor_source ?_, fun nack => ?_⟩) rfl
            (List.prefix_refl _) rfl sync.current⟩
        · rw [(Summary.sends facts envelope member).1]
          exact toLeader
        · exact toPeer ((Summary.sends facts envelope member).1.symm.trans nack.1)

/-- From a fresh start with every participant in sync with the primary, the
primary's AppendEntries in the window pass participants' log checks. -/
theorem window_matching_of_inSync {bounds : Bounds} {maxDelay : Real}
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
    (leaderIn : leader ∈ participants)
    (sync : InSync trace start leader term participants)
    : WindowMatching trace start duration leader term participants := by
  have quietAt
      : forall bound,
          (forall moment,
            moment < bound -> MatchesAt trace start duration leader term participants moment)
          -> forall index point,
              index <= bound
              -> Within trace start duration index
              -> trace.stateAt index = some point
              -> QuietAmong participants leader term (proto point) :=
    fun bound matching index point le within found =>
      (window_invariant_before admissible heartbeats elections bounded nonneg ratio freshLe
        initial members good active leaderIn (bound := bound) matching index point le within
        found).1.1
  have claim
      : forall index,
          (forall moment,
            moment < index -> MatchesAt trace start duration leader term participants moment)
          /\ forall point,
              Within trace start duration index
              -> trace.stateAt index = some point
              -> forall peer,
                  peer ∈ participants
                  -> Not (peer = leader)
                  -> exists leaderState state,
                      InSyncWith leader term peer point leaderState state := by
    intro index
    induction index with
    | zero =>
        refine ⟨fun _ lt => absurd lt (Nat.not_lt_zero _), fun point within found => ?_⟩
        have atStart : start = 0 := Nat.le_zero.mp within.1
        subst atStart
        exact fun peer => sync point peer found
    | succ index ih =>
        obtain ⟨earlier, syncAt⟩ := ih
        have matching
            : forall moment,
                moment < index + 1
                -> MatchesAt trace start duration leader term participants moment := by
          intro moment lt
          rcases Nat.lt_succ_iff_lt_or_eq.mp lt with lt | rfl
          · exact earlier moment lt
          · intro step packet request state within stepped
            have found := admissible.before stepped
            exact matches_at admissible stepped
              (quietAt moment earlier moment step.before le_rfl within found).quietTerm
              (syncAt step.before within found) step packet request state within stepped
        refine ⟨matching, fun point within found peer peerIn different => ?_⟩
        by_cases atStart : index + 1 = start
        · rw [atStart] at found
          exact sync point peer found peerIn different
        obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp found
        have afterStart : start <= index := by
          have := within.1
          omega
        have within' := within_of_le admissible within found afterStart (Nat.le_succ index)
        have before := admissible.before stepped
        obtain ⟨_, _, syncPeer⟩ := syncAt step.before within' before peer peerIn different
        exact sync_step admissible stepped within' good active leaderIn
          (quietAt (index + 1) matching index step.before (Nat.le_succ index) within'
            before).quietTerm
          (quietAt (index + 1) matching (index + 1) step.after le_rfl within
            found).quietTerm
          peerIn
          different syncPeer
  exact fun index => (claim (index + 1)).1 index (Nat.lt_succ_self index)

/-- `stable_window_fresh` with every participant in sync with the primary at the
start in place of `WindowMatching`. -/
theorem stable_window_inSync [HasTimers W] {bounds : Bounds} {maxDelay : Real}
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
    (sync : InSync trace start leader term participants)
    : StableWindow trace start duration leader term participants :=
  stable_window_fresh admissible timers bounded nonneg heartbeats ratio freshLe leaderIn
    initial members good active
    (window_matching_of_inSync admissible heartbeats
      (Liveness.electionScheduling_of_timerModel admissible.coherent admissible.timing
        timers)
      bounded nonneg ratio freshLe initial members good active leaderIn sync)

end Recorded

end CCFRaft.Proofs.Leadership
