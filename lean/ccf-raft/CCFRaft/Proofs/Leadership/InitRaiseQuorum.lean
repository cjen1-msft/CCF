module

public import CCFRaft.Proofs.Leadership.InitRaisePolling

@[expose] public section

set_option linter.unusedSectionVars false

/-!
A polling node cannot remain capped once every participant's granted response
has arrived.
-/

namespace CCFRaft.Proofs.Leadership.InitRaise

open CCF CCF.MultiNodeTransitionSystem
open Model.Node CCFRaft.Liveness
open CCFRaft.Proofs.Safety CCFRaft.Proofs.Replication
open CCFRaft.Proofs.Liveness (Admissible)
open HasProtocol (proto)

variable [Config.InitialConfiguration]
  {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W]
  {trace : Trace W Liveness.Event} {nodes : List NodeID}
  (admissible
    : Admissible (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) trace)

include admissible

/-- An eligible pre-vote delivery sends its granted response as a tracked packet. -/
theorem request_gets_grant {index : Nat} {step : Execution.Step W Liveness.Event}
    {packet : Packet} {request : RequestVoteRequest} {state : NodeState}
    (stepped : trace.stepAt index = some step) (delivered : step.action = .deliver packet)
    (payload : packet.envelope.payload = .requestPreVoteRequest request)
    (stateFound : nodeState (proto step.before) packet.envelope.target = some state)
    (term : request.term = state.currentTerm) (fresh : voteLogUpToDate state request)
    (unknown : state.primaryKnown = false)
    : exists reply,
        trace.SentAt index reply
        /\ reply.envelope.source = packet.envelope.target
        /\ reply.envelope.target = packet.envelope.source
        /\ reply.envelope.payload
            = .requestPreVoteResponse
                { term := state.currentTerm, voteGranted := true } := by
  have selected : step.action.action = some (.deliver packet.envelope) := by rw [delivered]; rfl
  obtain ⟨tr, ⟨actorEq, eventEq⟩, output⟩ := transition_acts (admissible.step stepped selected)
  have preEq : tr.pre = state := by
    have pre := tr.found
    rw [actorEq, stateFound, Option.some.injEq] at pre
    exact pre.symm
  have ran : (receive (Capabilities.record packet.envelope.target) packet.envelope.target
      packet.envelope.source state (.requestPreVoteRequest request)).run {}
      = some (tr.post, tr.outputs) := by
    simpa only [actorEq, eventEq, preEq, payload, Model.Node.step] using tr.ran
  obtain ⟨sent, outputs, result⟩ := request_granted packet.envelope.target state packet.envelope.source
    request term fresh unknown {} _ _ ran
  have out : tr.outputs.outgoing =
      [{ source := packet.envelope.target, target := packet.envelope.source, payload := .requestPreVoteResponse { term := state.currentTerm, voteGranted := true } }] := by
    simpa [outputs] using result.2
  obtain ⟨reply, replySent, replyEq, _⟩ :=
    admissible.sentAt_of_emitted stepped selected output (by rw [out]; exact List.mem_singleton_self _)
  exact ⟨reply, replySent, by rw [replyEq], by rw [replyEq], by rw [replyEq]⟩

/-- Delivering a granted eligible pre-vote counts it unless the receiver raises its term. -/
theorem grant_counted {index : Nat} {step : Execution.Step W Liveness.Event}
    {packet : Packet} {response : RequestVoteResponse} {before after : NodeState}
    (stepped : trace.stepAt index = some step)
    (delivered : step.action = .deliver packet)
    (payload : packet.envelope.payload = .requestPreVoteResponse response)
    (beforeFound : nodeState (proto step.before) packet.envelope.target = some before)
    (afterFound : nodeState (proto step.after) packet.envelope.target = some after)
    (role : before.role = .preVoteCandidate)
    (peer : packet.envelope.source ∈ eligiblePeers before packet.envelope.target)
    (term : response.term = before.currentTerm) (granted : response.voteGranted = true)
    (cap : after.currentTerm <= before.currentTerm)
    : packet.envelope.source ∈ after.preVotesGranted := by
  have selected : step.action.action = some (.deliver packet.envelope) := by rw [delivered]; rfl
  obtain ⟨tr, ⟨actorEq, eventEq⟩, _⟩ := transition_acts (admissible.step stepped selected)
  have preEq : tr.pre = before := by
    have pre := tr.found
    rw [actorEq, beforeFound, Option.some.injEq] at pre
    exact pre.symm
  have postEq : tr.post = after := by
    have post := Direct.nodeState_of_mem
      (Direct.keys_nodup (admissible.reachable (Trace.stateAt_succ_of_stepAt stepped))) tr.post_mem
    rw [actorEq, afterFound, Option.some.injEq] at post
    exact post.symm
  have ran : (receive (Capabilities.record packet.envelope.target) packet.envelope.target
      packet.envelope.source before (.requestPreVoteResponse response)).run {}
      = some (after, tr.outputs) := by
    simpa only [actorEq, eventEq, preEq, postEq, payload, Model.Node.step] using tr.ran
  obtain ⟨_, _, counted⟩ := response_counted packet.envelope.target before packet.envelope.source
    response role peer term granted {} _ _ ran
  exact counted cap

/-- A complete participant pre-vote contradicts remaining below the next term. -/
theorem quorum_contradiction {start since last term : Nat} {duration : Real}
    {participants members : Finset NodeID} {first point : W}
    {node : NodeID} {initial state : NodeState}
    (good : GoodPeriod trace start duration participants)
    (subset : participants ⊆ members)
    (afterStart : start <= since)
    (firstFound : trace.stateAt since = some first)
    (initialFound : nodeState (proto first) node = some initial)
    (initialTerm : initial.currentTerm = term) (member : node ∈ participants)
    (initialRole : initial.role = .preVoteCandidate)
    (initialVote : node ∈ initial.preVotesGranted)
    (initialQuorum : Not (hasQuorum initial.activeConfigurations initial.preVotesGranted))
    (low
      : forall index,
          Within trace start duration index -> Low trace participants index term)
    (membership
      : forall index point state,
          since <= index
          -> Within trace start duration index
          -> trace.stateAt index = some point
          -> nodeState (proto point) node = some state
          -> state.activeMembers = members)
    (noTimeout
      : forall index step,
          since <= index
          -> index < last
          -> trace.stepAt index = some step
          -> Not (step.action = .local node (.timeout .election)))
    (old
      : forall index step packet request,
          since <= index
          -> index < last
          -> Within trace start duration index
          -> trace.stepAt index = some step
          -> step.action = .deliver packet
          -> packet.envelope.target = node
          -> packet.envelope.payload = .appendEntriesRequest request
          -> request.term < term)
    (grants
      : forall voter,
          voter ∈ participants
          -> Not (voter = node)
          -> exists index step packet response,
              since <= index
              /\ index < last
              /\ trace.stepAt index = some step
              /\ step.action = .deliver packet
              /\ packet.envelope.source = voter
              /\ packet.envelope.target = node
              /\ packet.envelope.payload = .requestPreVoteResponse response
              /\ response.term = term
              /\ response.voteGranted = true)
    (later : since <= last) (within : Within trace start duration last)
    (found : trace.stateAt last = some point)
    (stateFound : nodeState (proto point) node = some state)
    : False := by
  have polling := polling_later admissible good afterStart firstFound initialFound initialTerm
    member initialRole initialQuorum low noTimeout old later within found stateFound
  have allVotes : participants ⊆ state.preVotesGranted := by
    intro voter voterIn
    by_cases same : voter = node
    · subst voter
      exact polling.2.1 initialVote
    · obtain ⟨index, step, packet, response, afterSince, beforeLast, stepped, delivered,
        sourceEq, targetEq, payload, responseTerm, granted⟩ := grants voter voterIn same
      have beforeWithin := within_before admissible within found
        (afterStart.trans afterSince) beforeLast.le
      have afterWithin := within_before admissible within found
        (by omega : start <= index + 1) beforeLast
      obtain ⟨before, beforeFound, beforeTerm⟩ := top_stays admissible firstFound initialFound initialTerm
        member afterSince (admissible.before stepped) (low index beforeWithin)
      obtain ⟨after, afterFound, afterTerm⟩ := top_stays admissible firstFound initialFound initialTerm
        member (by omega) (Trace.stateAt_succ_of_stepAt stepped) (low (index + 1) afterWithin)
      have beforePolling := polling_later admissible good afterStart firstFound initialFound initialTerm
        member initialRole initialQuorum low
        (fun i s lower upper at_ => noTimeout i s lower (by omega) at_)
        (fun i s p r lower upper win at_ action target payload =>
          old i s p r lower (by omega) win at_ action target payload)
        afterSince beforeWithin (admissible.before stepped) beforeFound
      have afterPolling := polling_later admissible good afterStart firstFound initialFound initialTerm
        member initialRole initialQuorum low
        (fun i s lower upper at_ => noTimeout i s lower (by omega) at_)
        (fun i s p r lower upper win at_ action target payload =>
          old i s p r lower (by omega) win at_ action target payload)
        (by omega) afterWithin (Trace.stateAt_succ_of_stepAt stepped) afterFound
      have membersEq := membership index step.before before afterSince beforeWithin
        (admissible.before stepped) beforeFound
      have peer : packet.envelope.source ∈ eligiblePeers before packet.envelope.target := by
        rw [sourceEq, targetEq]
        exact Finset.mem_erase.mpr ⟨same, Finset.mem_union_left _
          (by rw [membersEq]; exact subset voterIn)⟩
      have counted := grant_counted admissible stepped delivered payload
        (targetEq ▸ beforeFound) (targetEq ▸ afterFound) beforePolling.1 peer
        (responseTerm.trans beforeTerm.symm) granted (by omega)
      rw [sourceEq] at counted
      have grows := polling_later admissible good (by omega : start <= index + 1)
        (Trace.stateAt_succ_of_stepAt stepped) afterFound afterTerm member
        afterPolling.1 afterPolling.2.2 low
        (fun i s lower upper at_ => noTimeout i s (by omega) upper at_)
        (fun i s p r lower upper win at_ action target payload =>
          old i s p r (by omega) upper win at_ action target payload)
        beforeLast within found stateFound
      exact grows.2.1 counted
  have live := good.participantsLive last point node within found member
  have quorum := good.quorum last point node state within found live stateFound
  exact polling.2.2 (CCFRaft.Proofs.StablePrimary.hasQuorum_mono quorum
    (fun voter voted => allVotes (Finset.mem_inter.mp voted).2))

end CCFRaft.Proofs.Leadership.InitRaise
