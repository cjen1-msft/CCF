module

public import CCFRaft.Proofs.Duel.ElectedAnchor

@[expose] public section

/-!
# The elected case of a duel round

NOT IMPORTED BY `Properties`. A primary of `term + 1` elected early in a round
settles its voters into an anchored start by four delays after the round starts.
The facts about the round's caps and packets (`Round.RoundBase.capped_from` and
`Round.RoundBase.packets`) are hypotheses here, proved in `Duel.Round`.
Only the packet bound on granted pre-vote responses is needed here; adoption
is proved for the voters rather than required of every participant. The proof
looks only at the round's first four delays (`RoundShort`).
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
open CCFRaft.Proofs.Liveness (Admissible)
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Replication

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W] [Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event} {electionTimeout maxDelay jump : Real} {start : Nat}
  {duration : Real} {participants members : Finset NodeID} {c term : Nat}

/-! ## The elected case -/

/-- An election of `term + 1` early in the round settles its voters into an anchored
start by `time c + 4 * maxDelay`. The anchor contains the primary and its voters.
Only the round's first four delays need be in the window. -/
theorem RoundShort.handoff_settle
    (setup
      : RoundShort nodes trace electionTimeout maxDelay jump start duration participants
          members c term)
    {index : Nat} {origin point : W} {leader : NodeID} {state : NodeState}
    (originFound : trace.stateAt c = some origin)
    (lateGrants
      : forall index point packet,
          c <= index
          -> trace.stateAt index = some point
          -> time point <= time origin + 4 * maxDelay
          -> packet ∈ pending point
          -> packet.envelope.source ∈ participants
          -> packet.envelope.target ∈ participants
          -> packet.envelope.payload
              = .requestPreVoteResponse { term := term + 1, voteGranted := true }
          -> time origin + electionTimeout / 2 <= packet.sentAt)
    (capped
      : forall index point,
          c <= index
          -> trace.stateAt index = some point
          -> time point <= time origin + 4 * maxDelay
          -> Capped trace participants c term index)
    (indexLe : c <= index)
    (found : trace.stateAt index = some point)
    (early : time point <= time origin + 3 * maxDelay) (member : leader ∈ participants)
    (leaderFound : nodeState (proto point) leader = some state)
    (primary : state.role = .primary) (termEq : state.currentTerm = term + 1)
    : HandoffBy trace participants c (4 * maxDelay)
        (electionTimeout / 2 - 4 * maxDelay) := by
  classical
  obtain ⟨win, step, action, rest, ctx, winLe, winIndex, stepped, selected, acts, out,
      actorEq, winPrimary, winTerm, fresh, won⟩ :=
    Elected.first_win setup originFound indexLe found member leaderFound primary termEq
  subst leader
  have winBefore := setup.admissible.before stepped
  have winAfter := Trace.stateAt_succ_of_stepAt stepped
  have afterEarly : time step.after <= time origin + 3 * maxDelay :=
    (setup.admissible.time_le (by omega : win + 1 <= index) winAfter found).trans early
  have beforeEarly : time step.before <= time origin + 3 * maxDelay :=
    (setup.admissible.timing.next stepped).1.trans afterEarly
  have afterShort : time step.after <= time origin + 4 * maxDelay := by
    linarith [setup.nonnegative]
  have beforeShort : time step.before <= time origin + 4 * maxDelay := by
    linarith [setup.nonnegative]
  have postFound := found_of_now ctx.exec ctx.post_now
  have winMembership := Elected.membership setup originFound winLe winBefore beforeShort
  have postMembership := Elected.membership setup originFound (by omega) winAfter afterShort
  have postWithin := Elected.within setup originFound (by omega) winAfter afterShort
  have postNonempty := (setup.period.quorum (win + 1) step.after ctx.actor ctx.post postWithin
    winAfter (setup.period.participantsLive (win + 1) step.after ctx.actor postWithin winAfter member)
    postFound).1
  have peers : ctx.post.activeMembers = members := by
    rcases postMembership.activeMembers ctx.post_now member with empty | same
    · exact (postNonempty empty).elim
    · exact same
  obtain ⟨candidate, campaign, quorum, _, candidateTerm, candidateVote, _, _, _⟩ :=
    Wins.facts won
  have candidateHigh : candidate.currentTerm = term + 1 := candidateTerm.symm.trans winTerm
  have votersIn : candidate.votesGranted ⊆ participants :=
    Elected.campaign_subset setup originFound ctx winLe stepped beforeShort selected acts member
      campaign candidateHigh
      (fun role te => Elected.candidate_subset setup originFound win step.before ctx.actor ctx.pre
        winLe winBefore beforeShort member ctx.tr.found te role)
  have voters : forall node, node ∈ candidate.votesGranted
      -> exists voter, nodeState (proto step.after) node = some voter
        /\ voter.currentTerm = term + 1 /\ voter.votedFor = some ctx.actor := by
    intro node nodeIn
    have granted := ctx.campaign_votes campaign candidateTerm candidateVote node nodeIn
    rw [candidateHigh] at granted
    obtain ⟨voter, now, high, vote⟩ := Elected.granted_current ctx.exec granted
      (fun voter now =>
        (capped (win + 1) step.after (by omega) winAfter afterShort).2
          (win + 1) step.after node voter (by omega) le_rfl winAfter (votersIn nodeIn)
          (found_of_now ctx.exec now))
    exact ⟨voter, found_of_now ctx.exec now, high, vote⟩
  have winKnown : ctx.post.primaryKnown = true := by
    rcases Elected.ElectedStep.known (Elected.LocalTransition.electedStep ctx.tr) winPrimary with
      known | ⟨role, te, _⟩ | retired
    · exact known
    · exact (fresh ⟨role, te.trans winTerm⟩).elim
    · exact (setup.active (win + 1) step.after ctx.actor ctx.post postWithin winAfter member
        postFound retired).elim
  obtain ⟨stop, crossing, stopLe, crossed, near, far⟩ :=
    Elected.boundary setup originFound (4 * maxDelay) (by linarith [setup.nonnegative])
  have stopFound := setup.admissible.before crossed
  have winStop : win < stop := by
    by_contra h
    have order := setup.admissible.time_le (by omega : stop + 1 <= win + 1)
      (Trace.stateAt_succ_of_stepAt crossed) winAfter
    linarith [setup.nonnegative]
  have horizon : forall i p, i <= stop -> trace.stateAt i = some p
      -> time p <= time origin + 4 * maxDelay := by
    intro i p le pf
    have order := setup.admissible.time_le le pf stopFound
    linarith
  have stopEarly := horizon stop crossing.before le_rfl stopFound
  have leaderAt := Elected.known_kept setup originFound capped (by omega : c <= win + 1)
    winAfter member postFound winTerm winKnown (Or.inr winPrimary)
  obtain ⟨endLeader, endLeaderFound, endLeaderTerm, endLeaderKnown, endLeaderRole⟩ :=
    leaderAt stop crossing.before (by omega) stopFound stopEarly
  rw [winPrimary] at endLeaderRole
  obtain ⟨endRest, endExec⟩ := history_at setup.admissible stopFound
  let anchor := insert ctx.actor candidate.votesGranted
  have anchorSubset : anchor ⊆ participants := by
    intro node nodeIn
    rcases Finset.mem_insert.mp nodeIn with rfl | voter
    · exact member
    · exact votersIn voter
  have anchorLeader : ctx.actor ∈ anchor := Finset.mem_insert_self _ _
  have votersSubset : candidate.votesGranted ⊆ anchor := Finset.subset_insert _ _
  obtain ⟨blocked, quorumFor⟩ := Elected.fixed_quorum quorum
    (winMembership ctx.actor ctx.pre ctx.pre_now member).1 votersSubset
  have stopWithin := Elected.within setup originFound stopLe stopFound stopEarly
  have stopMembership := Elected.membership setup originFound stopLe stopFound stopEarly
  have nonemptyAtStop : forall node local_, node ∈ participants
      -> (node, local_) ∈ (proto crossing.before).nodes
      -> local_.activeConfigurations ≠ [] := by
    intro node local_ member now
    exact (setup.period.quorum stop crossing.before node local_ stopWithin stopFound
      (setup.period.participantsLive stop crossing.before node stopWithin stopFound member)
      (found_of_now endExec now)).1
  have settled : forall node, node ∈ anchor
      -> exists local_, (node, local_) ∈ (proto crossing.before).nodes
        /\ local_.currentTerm = term + 1 /\ local_.primaryKnown = true
        /\ (local_.role = .follower \/ local_.role = .primary) := by
    intro node nodeIn
    rcases Finset.mem_insert.mp nodeIn with rfl | voterIn
    · exact ⟨endLeader, now_of_found (rest := endRest) endLeaderFound,
        endLeaderTerm, endLeaderKnown, Or.inr endLeaderRole⟩
    by_cases same : node = ctx.actor
    · subst node
      exact ⟨endLeader, now_of_found (rest := endRest) endLeaderFound,
        endLeaderTerm, endLeaderKnown, Or.inr endLeaderRole⟩
    have nodeIn := votersIn voterIn
    have eligible : node ∈ eligiblePeers ctx.post ctx.actor := by
      unfold eligiblePeers
      refine Finset.mem_erase.mpr ⟨same, Finset.mem_union_left _ ?_⟩
      rw [peers]
      exact setup.subset nodeIn
    obtain ⟨request, sent, requestTerm⟩ :=
      Elected.ElectedStep.heartbeats (Elected.LocalTransition.electedStep ctx.tr)
        winPrimary (fun old => fresh ⟨old.1, old.2.trans winTerm⟩) node eligible
    obtain ⟨packet, packetSent, envelopeEq, sentTime⟩ :=
      setup.admissible.sentAt_of_emitted stepped selected out sent
    have packetSource : packet.envelope.source = ctx.actor :=
      congrArg (fun e : Model.Envelope => e.source) envelopeEq
    have packetTarget : packet.envelope.target = node :=
      congrArg (fun e : Model.Envelope => e.target) envelopeEq
    have packetPayload : packet.envelope.payload = .appendEntriesRequest request :=
      congrArg (fun e : Model.Envelope => e.payload) envelopeEq
    obtain ⟨deliveryIndex, deliveryStep, afterWin, beforeStop, delivered, delivery⟩ :=
      Elected.delivered_before setup originFound winLe winStop packetSent crossed near far
        (sentTime ▸ beforeEarly) (packetSource ▸ member) (packetTarget ▸ nodeIn)
    have deliveryFound := setup.admissible.before delivered
    have deliveryEarly := horizon deliveryIndex deliveryStep.before (by omega) deliveryFound
    have acceptedEarly := horizon (deliveryIndex + 1) deliveryStep.after (by omega)
      (Trace.stateAt_succ_of_stepAt delivered)
    obtain ⟨voter, voterFound, voterTerm, voterVote⟩ := voters node voterIn
    obtain ⟨voter, voterFound, voterTerm, voterVote⟩ :=
      Elected.vote_kept setup originFound capped (by omega : c <= win + 1) winAfter
        nodeIn voterFound voterTerm voterVote deliveryIndex deliveryStep.before
        (by omega) deliveryFound deliveryEarly
    obtain ⟨primary, primaryFound, primaryTerm, _, primaryRole⟩ :=
      leaderAt deliveryIndex deliveryStep.before (by omega) deliveryFound deliveryEarly
    rw [winPrimary] at primaryRole
    obtain ⟨deliveryRest, deliveryExec⟩ := history_at setup.admissible deliveryFound
    have lead : Lead nodes (proto deliveryStep.before :: deliveryRest) ctx.actor (term + 1) primary :=
      ⟨deliveryExec, now_of_found primaryFound, primaryRole, primaryTerm⟩
    have follower := Elected.voter_follower setup originFound lead (by omega) deliveryFound
      deliveryEarly nodeIn same voterFound voterTerm voterVote
    obtain ⟨accepted, acceptedFound, acceptedTerm, acceptedKnown, acceptedRole⟩ :=
      Elected.heartbeat_accepted setup originFound (by omega) delivered delivery acceptedEarly
        (packetTarget ▸ nodeIn) (by rw [packetTarget, packetSource]; exact same)
        packetPayload (requestTerm.trans winTerm) (packetTarget ▸ voterFound) voterTerm follower
        ⟨primary, packetSource ▸ primaryFound, primaryRole, primaryTerm⟩
    rw [packetTarget] at acceptedFound
    obtain ⟨last, lastFound, lastTerm, lastKnown, lastRole⟩ :=
      Elected.known_kept setup originFound capped (by omega : c <= deliveryIndex + 1)
        (Trace.stateAt_succ_of_stepAt delivered) nodeIn acceptedFound acceptedTerm acceptedKnown
        (Or.inl acceptedRole) stop crossing.before (by omega) stopFound stopEarly
    exact ⟨last, now_of_found (rest := endRest) lastFound,
      lastTerm, lastKnown, Or.inl (lastRole.trans acceptedRole)⟩
  have noGrants := Elected.no_grants setup originFound lateGrants stopLe stopFound stopEarly
  refine ⟨stop, ctx.actor, term + 1, anchor, origin, crossing.before,
    stopLe, originFound, stopFound, near, ?_⟩
  constructor
  · refine ⟨crossing.before, stopFound, ?_, ?_, ?_, stopMembership.blocks blocked⟩
    · refine ⟨?_, ?_, endLeader, now_of_found (rest := endRest) endLeaderFound,
        endLeaderRole, endLeaderTerm⟩
      · intro node local_ now member
        exact (capped stop crossing.before stopLe stopFound stopEarly).2 stop crossing.before
          node local_ stopLe le_rfl stopFound member (found_of_now endExec now)
      · intro e queued sourceIn _
        exact Elected.capped_messages setup stopFound
          (capped stop crossing.before stopLe stopFound stopEarly) e queued sourceIn
    · intro packet queued sourceIn targetIn
      exact Elected.no_proposals setup originFound stopLe stopFound stopEarly packet.envelope
        (setup.admissible.pending_mem_network stopFound queued) sourceIn targetIn
    · refine ⟨anchorSubset, anchorLeader, ?_, ?_, settled, ?_, ?_⟩
      · intro local_ now
        exact quorumFor local_.activeConfigurations (nonemptyAtStop ctx.actor local_ member now)
          (stopMembership ctx.actor local_ now member).1
      · intro local_ now node nodeIn _
        rcases stopMembership.latest now member with empty | latest
        · exact (nonemptyAtStop ctx.actor local_ member now empty).elim
        · rw [latest]
          exact setup.subset (anchorSubset nodeIn)
      · intro e queued sourceIn targetIn
        exact noGrants e queued (anchorSubset sourceIn) (Finset.mem_sdiff.mp targetIn).1
      · intro node local_ now member role te
        exact (Elected.no_pre_vote setup originFound stop crossing.before node local_
          stopLe stopFound (by linarith [setup.ratio]) member (found_of_now endExec now) te role).elim
  · intro first i later node local_ firstFound le stepped timeout nodeFound nodeIn te
    rw [stopFound, Option.some.injEq] at firstFound
    subst first
    have fresh := Racing.term_fresh setup.admissible setup.timers originFound
      (fun n s m f => setup.round.low origin n s originFound m f)
      i later.before node local_ (by omega) (setup.admissible.before stepped)
      (anchorSubset nodeIn) nodeFound te
    have due := ((setup.timers.next stepped) node).2.2 timeout
    linarith

end CCFRaft.Proofs.Duel.Round
