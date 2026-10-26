module

public import CCFRaft.Proofs.Leadership.InitIncumbentKeep

@[expose] public section

set_option linter.unusedSectionVars false

/-!
Scheduled incumbent sends and the follower state their delivery establishes.
-/

namespace CCFRaft.Proofs.Leadership.InitIncumbent

open CCF CCF.MultiNodeTransitionSystem
open Model.Node CCFRaft.Liveness
open CCFRaft.Proofs.Safety CCFRaft.Proofs.Replication
open CCFRaft.Proofs.Liveness (Admissible)
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)

variable [Config.InitialConfiguration]
  {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W]
  {trace : Trace W Liveness.Event} {nodes : List NodeID}
  (admissible : Admissible Config.INITIAL_CONFIGURATION nodes trace)
  {start : Nat} {duration : Real} {participants members : Finset NodeID}
  {leader : NodeID} {term : Nat}

include admissible

/-- The incumbent owes every other participant a heartbeat. -/
theorem peer_due
    (good : GoodPeriod trace start duration participants)
    (active : Window.AnchorActive trace start duration participants)
    (membership
      : forall index point,
          Within trace start duration index
          -> trace.stateAt index = some point
          -> Membership participants members (proto point))
    (subset : participants ⊆ members) (leaderIn : leader ∈ participants)
    (leads
      : forall index point,
          Within trace start duration index
          -> trace.stateAt index = some point
          -> exists state,
              nodeState (proto point) leader = some state
              /\ state.currentTerm = term
              /\ state.role = .primary)
    {index : Nat} {point : W} (within : Within trace start duration index)
    (found : trace.stateAt index = some point) {peer : NodeID}
    (peerIn : peer ∈ participants) (different : Not (peer = leader))
    : PeerDue point leader peer := by
  obtain ⟨state, nodeFound, _, primary⟩ := leads index point within found
  have leaderLive := good.participantsLive index point leader within found leaderIn
  have quorum := good.quorum index point leader state within found leaderLive nodeFound
  have fixed := (membership index point within found).activeMembers
    (Concrete.mem_of_nodeState nodeFound) leaderIn
  have membersEq := fixed.resolve_left quorum.1
  refine ⟨leaderLive, good.participantsLive index point peer within found peerIn,
    state, nodeFound, primary, active index point leader state within found leaderIn nodeFound, ?_⟩
  simp only [eligiblePeers, Finset.mem_erase, Finset.mem_union]
  exact ⟨different, Or.inl (membersEq ▸ subset peerIn)⟩

/-- A scheduled send supplies a current-term packet by the heartbeat deadline. -/
theorem send_by
    (good : GoodPeriod trace start duration participants)
    (active : Window.AnchorActive trace start duration participants)
    (membership
      : forall index point,
          Within trace start duration index
          -> trace.stateAt index = some point
          -> Membership participants members (proto point))
    (subset : participants ⊆ members) (leaderIn : leader ∈ participants)
    (leads
      : forall index point,
          Within trace start duration index
          -> trace.stateAt index = some point
          -> exists state,
              nodeState (proto point) leader = some state
              /\ state.currentTerm = term
              /\ state.role = .primary)
    {heartbeat : Real} (heartbeats : trace.HeartbeatScheduling (some heartbeat))
    {first origin : W} (firstFound : trace.stateAt start = some first)
    {base : Nat} (originFound : trace.stateAt base = some origin)
    (within : Within trace start duration base)
    (room : time origin + heartbeat <= time first + duration)
    {peer : NodeID} (peerIn : peer ∈ participants) (different : Not (peer = leader))
    : exists sent packet request,
        base <= sent
        /\ trace.SentAt sent packet
        /\ packet.envelope.source = leader
        /\ packet.envelope.target = peer
        /\ packet.envelope.payload = .appendEntriesRequest request
        /\ request.term = term
        /\ packet.sentAt <= time origin + heartbeat := by
  have due := peer_due admissible good active membership subset leaderIn leads
    within originFound peerIn different
  obtain ⟨sent, point, later, found, deadline, resolves⟩ :=
    heartbeats leader peer base origin originFound due
  have early : time point <= time origin + heartbeat := deadline
  have bounded : Within trace start duration sent := by
    refine ⟨within.1.trans later, fun f p ff pf => ?_⟩
    rw [firstFound, Option.some.injEq] at ff
    rw [found, Option.some.injEq] at pf
    subst f p
    exact early.trans room
  rcases resolves with notDue | ⟨step, stepped, ends, fired⟩
  · exact (notDue (peer_due admissible good active membership subset leaderIn leads
      bounded found peerIn different)).elim
  have selected : step.action.action = some (.local leader (.sendEntries peer ends)) := by
    rw [fired]; rfl
  obtain ⟨tr, acts, output⟩ := transition_acts (admissible.step stepped selected)
  obtain ⟨actor, event⟩ := acts
  change tr.actor = leader at actor
  change tr.event = .internal (.sendEntries peer ends) at event
  have ran := tr.ran
  rw [actor, event] at ran
  obtain ⟨sentEnvelopes, emitted, pass⟩ :=
    sendEntries_pass leader tr.pre peer ends {} _ _ ran
  have nodeFound : nodeState (proto step.before) leader = some tr.pre := actor ▸ tr.found
  have beforeFound := admissible.before stepped
  rw [beforeFound, Option.some.injEq] at found
  subst point
  obtain ⟨state, stateFound, stateTerm, _⟩ := leads sent step.before bounded beforeFound
  rw [nodeFound, Option.some.injEq] at stateFound
  subst state
  have notRetired := active sent step.before leader tr.pre bounded beforeFound leaderIn nodeFound
  obtain ⟨batch, batchIn⟩ := passBatches_nonempty pass.valid
  have sentMem : batchEnvelope tr.pre leader peer batch ∈ tr.outputs.outgoing := by
    rw [emitted, List.nil_append, (pass.complete notRetired).2]
    exact List.mem_map.mpr ⟨batch, batchIn, rfl⟩
  obtain ⟨packet, sentAt, envelopeEq, sentTime⟩ :=
    admissible.sentAt_of_emitted stepped selected output sentMem
  exact ⟨
    sent,
    packet,
    makeAppendEntriesRequest tr.pre batch.1 batch.2,
    later,
    sentAt,
    by rw [envelopeEq]; rfl,
    by rw [envelopeEq]; rfl,
    by rw [envelopeEq]; rfl,
    stateTerm,
    by rw [sentTime]; exact early
  ⟩

/-- An incumbent's delivered AppendEntries resets its recipient's election timer. -/
theorem delivery_resets (matching : Window.Matching trace start duration participants)
    (low
      : forall index,
          Within trace start duration index -> Low trace participants index term)
    {index : Nat} {step : Execution.Step W Liveness.Event} {packet : Packet}
    {request : AppendEntriesRequest} (within : Within trace start duration index)
    (stepped : trace.stepAt index = some step) (delivered : step.action = .deliver packet)
    (member : packet.envelope.target ∈ participants)
    (different : Not (packet.envelope.target = packet.envelope.source))
    (payload : packet.envelope.payload = .appendEntriesRequest request)
    (requestTerm : request.term = term)
    : ElectionReset step packet.envelope.target := by
  have selected : step.action.action = some (.deliver packet.envelope) := by rw [delivered]; rfl
  obtain ⟨tr, acts, _⟩ := transition_acts (admissible.step stepped selected)
  have target : tr.actor = packet.envelope.target := acts.1
  have nodeFound : nodeState (proto step.before) packet.envelope.target = some tr.pre :=
    target ▸ tr.found
  have cap := low index within step.before _ tr.pre (admissible.before stepped) member nodeFound
  rw [ElectionReset, delivered, nodeFound]
  refine ⟨rfl, Or.inr ?_⟩
  rw [payload]
  by_cases raised : tr.pre.currentTerm < request.term
  · exact Or.inl raised
  right
  refine ⟨by omega, ?_⟩
  by_cases candidate : tr.pre.role = .candidate
  · exact Or.inl candidate
  by_cases preVote : tr.pre.role = .preVoteCandidate
  · exact Or.inr (Or.inl preVote)
  exact Or.inr
    (Or.inr
      (matching index step packet request tr.pre within stepped delivered
        member different payload nodeFound (by omega) candidate preVote))

/-- A delivery of the incumbent term makes its recipient a current-term follower. -/
theorem delivered_follower
    (low
      : forall index,
          Within trace start duration index -> Low trace participants index term)
    (roled
      : forall index point node state,
          Within trace start duration index
          -> trace.stateAt index = some point
          -> node ∈ participants
          -> nodeState (proto point) node = some state
          -> Not (state.role = .none))
    (leads
      : forall index point,
          Within trace start duration index
          -> trace.stateAt index = some point
          -> exists state,
              nodeState (proto point) leader = some state
              /\ state.currentTerm = term
              /\ state.role = .primary)
    {index : Nat} {step : Execution.Step W Liveness.Event} {packet : Packet}
    {request : AppendEntriesRequest} (within : Within trace start duration index)
    (stepped : trace.stepAt index = some step) (delivered : step.action = .deliver packet)
    (member : packet.envelope.target ∈ participants)
    (different : Not (packet.envelope.target = leader))
    (payload : packet.envelope.payload = .appendEntriesRequest request)
    (requestTerm : request.term = term)
    : exists state,
        nodeState (proto step.after) packet.envelope.target = some state
        /\ state.currentTerm = term
        /\ state.role = .follower := by
  have selected : step.action.action = some (.deliver packet.envelope) := by rw [delivered]; rfl
  obtain ⟨tr, acts, _⟩ := transition_acts (admissible.step stepped selected)
  have target : tr.actor = packet.envelope.target := acts.1
  have event : tr.event = .receive packet.envelope.source (.appendEntriesRequest request) := by
    rw [acts.2, payload]
  have nodeFound : nodeState (proto step.before) packet.envelope.target = some tr.pre :=
    target ▸ tr.found
  have beforeFound := admissible.before stepped
  have cap := low index within step.before _ tr.pre beforeFound member nodeFound
  obtain ⟨primary, primaryFound, primaryTerm, primaryRole⟩ := leads index step.before within beforeFound
  have notPrimary : tr.pre.currentTerm = request.term -> Not (tr.pre.role = .primary) := by
    intro eq role
    exact different (primary_unique admissible beforeFound primaryFound primaryRole primaryTerm
      nodeFound role (eq.trans requestTerm))
  have hasRole := roled index step.before _ tr.pre within beforeFound member nodeFound
  have ran := tr.ran
  rw [event] at ran
  obtain ⟨_, _, adopted, role⟩ :=
    append_follower tr.actor packet.envelope.source tr.pre request (by omega) notPrimary hasRole
      {} _ _ ran
  have postFound := Direct.nodeState_of_mem
    (Direct.keys_nodup (admissible.reachable (Trace.stateAt_succ_of_stepAt stepped))) tr.post_mem
  have nextWithin := admissible.within_after within stepped (by rw [delivered]; simp)
  have postRole := roled (index + 1) step.after _ tr.post nextWithin
    (Trace.stateAt_succ_of_stepAt stepped) (target ▸ member) postFound
  exact ⟨
    tr.post,
    target ▸ postFound,
    adopted.trans requestTerm,
    role.resolve_right postRole
  ⟩

/-- A current-term follower accepts its incumbent's next matching heartbeat. -/
theorem delivered_known (active : Window.AnchorActive trace start duration participants)
    (matching : Window.Matching trace start duration participants) {index : Nat}
    {step : Execution.Step W Liveness.Event} {packet : Packet}
    {request : AppendEntriesRequest} {state primary : NodeState}
    (within : Within trace start duration index)
    (stepped : trace.stepAt index = some step) (delivered : step.action = .deliver packet)
    (member : packet.envelope.target ∈ participants)
    (different : Not (packet.envelope.target = packet.envelope.source))
    (payload : packet.envelope.payload = .appendEntriesRequest request)
    (requestTerm : request.term = term)
    (nodeFound : nodeState (proto step.before) packet.envelope.target = some state)
    (stateTerm : state.currentTerm = term) (follower : state.role = .follower)
    (primaryFound : nodeState (proto step.before) packet.envelope.source = some primary)
    (primaryTerm : primary.currentTerm = term) (primaryRole : primary.role = .primary)
    : exists state,
        nodeState (proto step.after) packet.envelope.target = some state
        /\ state.currentTerm = term
        /\ state.role = .follower
        /\ state.primaryKnown = true := by
  have selected : step.action.action = some (.deliver packet.envelope) := by rw [delivered]; rfl
  obtain ⟨rest, ctx, acts, _⟩ := ctx_at admissible stepped selected
  have target : ctx.actor = packet.envelope.target := acts.1
  have event : ctx.event = .receive packet.envelope.source (.appendEntriesRequest request) := by
    change ctx.tr.event = _
    rw [acts.2, payload]
  have eq := ctx.now_pre (target ▸ now_of_found (rest := rest) nodeFound)
  subst state
  have lead : Lead nodes (proto step.before :: rest) packet.envelope.source term primary :=
    ⟨ctx.prior, now_of_found primaryFound, primaryRole, primaryTerm⟩
  obtain ⟨envelope, queued, _, _, payload'⟩ := ctx.received event
  have requestOk := lead.request queued payload' requestTerm
  have logMatch := matching index step packet request ctx.pre within stepped delivered member
    different payload nodeFound (by omega) (by simp [follower]) (by simp [follower])
  have bound : request.prevLogIndex <= ctx.pre.log.length := by
    by_contra beyond
    have zero := termAt_of_length_lt (by omega : ctx.pre.log.length < request.prevLogIndex)
    have positive := termAt_pos lead.inv lead.now (by omega : 0 < request.prevLogIndex)
      requestOk.2.2.1
    rw [zero, requestOk.2.2.2.1] at logMatch
    omega
  have observed : observeTerm ctx.pre (.appendEntriesRequest request) = ctx.pre := by
    simp [observeTerm, updateTerm, Message.term, stateTerm, requestTerm]
  have aware : awareState ctx.pre request = ctx.pre := by simp [awareState, follower]
  have ran := ctx.tr.ran
  change (Model.Node.step (Capabilities.record ctx.actor) ctx.actor ctx.pre ctx.event).run {}
    = some (ctx.post, ctx.tr.outputs) at ran
  rw [event] at ran
  change (handleAppendEntriesRequest (Capabilities.record ctx.actor) ctx.actor packet.envelope.source
    (observeTerm ctx.pre (.appendEntriesRequest request)) request).run {} = _ at ran
  rw [observed] at ran
  obtain ⟨_, _, shape, _, termEq⟩ :=
    ae_evidence ctx.actor packet.envelope.source ctx.pre request {} _ _ ran
  rw [aware] at shape termEq
  have postFound := found_of_now ctx.exec ctx.post_now
  have nextWithin := admissible.within_after within stepped (by rw [delivered]; simp)
  refine ⟨ctx.post, target ▸ postFound, termEq.trans stateTerm, ?_⟩
  rcases shape with ⟨_, reject⟩ | (⟨role, known⟩ | retired)
  · have notReject : Not (request.term < ctx.pre.currentTerm
        \/ Not (appendEntryMatchesLog ctx.pre request)) := by
      simp [stateTerm, requestTerm, appendEntryMatchesLog, bound, logMatch]
    exact (notReject reject).elim
  · exact ⟨role.trans follower, known⟩
  · exact (active (index + 1) step.after ctx.actor ctx.post nextWithin
      (Trace.stateAt_succ_of_stepAt stepped) (target ▸ member) postFound retired).elim

end CCFRaft.Proofs.Leadership.InitIncumbent
