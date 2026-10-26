module

public import CCFRaft.Proofs.Duel.ElectedSettle

@[expose] public section

set_option linter.unusedSectionVars false

namespace CCFRaft.Proofs.Duel.Elected

open CCF CCF.MultiNodeTransitionSystem
open Model.Node CCFRaft.Liveness
open CCFRaft.Proofs.Safety CCFRaft.Proofs.Replication
open CCFRaft.Proofs.Liveness (Admissible)
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)
open HasNetwork (pending)
open HasTimers (deadline)
open CCFRaft.Proofs.Duel.Round

/-- A majority in fixed membership remains a majority after adding voters,
and blocks every disjoint majority. -/
theorem fixed_quorum {configurations : List Configuration}
    {members voters anchor : Finset NodeID} (quorum : hasQuorum configurations voters)
    (fixed : forall config, config ∈ configurations -> config.nodes = members)
    (subset : voters ⊆ anchor)
    : Blocked anchor members
      /\ forall other : List Configuration,
          other ≠ []
          -> (forall config, config ∈ other -> config.nodes = members)
          -> hasQuorum other anchor := by
  obtain ⟨nonempty, all⟩ := quorum
  obtain ⟨config, configIn⟩ := List.exists_mem_of_ne_nil _ nonempty
  have majority := of_decide_eq_true (List.all_eq_true.mp all config configIn)
  unfold hasConfigurationMajority at majority
  rw [fixed config configIn] at majority
  have count : (voters ∩ members).card <= (anchor ∩ members).card :=
    Finset.card_le_card (Finset.inter_subset_inter subset (Finset.Subset.refl _))
  have card := Finset.card_sdiff_add_card_inter members anchor
  rw [Finset.inter_comm members anchor] at card
  refine ⟨by unfold Blocked; omega, ?_⟩
  intro other nonempty fixed
  refine ⟨nonempty, List.all_eq_true.mpr ?_⟩
  intro config configIn
  apply decide_eq_true
  unfold hasConfigurationMajority
  rw [fixed config configIn]
  omega

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W]
  [HasNetwork W] [HasTimers W] [Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event} {E d jump duration : Real} {start c term : Nat}
  {participants members : Finset NodeID}
  (setup : RoundSetup nodes trace E d jump start duration participants members c term)
  {origin : W} (originFound : trace.stateAt c = some origin)

include setup originFound

/-- A voter other than the primary cannot campaign or lead in the same term. -/
theorem voter_follower {index : Nat} {point : W} {rest : History}
    {leader node : NodeID} {primary voter : NodeState}
    (lead : Lead nodes (proto point :: rest) leader (term + 1) primary)
    (le : c <= index) (found : trace.stateAt index = some point)
    (early : time point < time origin + E / 2) (member : node ∈ participants)
    (different : node ≠ leader)
    (voterFound : nodeState (proto point) node = some voter)
    (termEq : voter.currentTerm = term + 1) (vote : voter.votedFor = some leader)
    : voter.role = .follower := by
  have now : Now (proto point :: rest) node voter := now_of_found voterFound
  have none := no_none setup originFound index point node voter le found early member
    voterFound termEq
  have preVote := no_pre_vote setup originFound index point node voter le found early member
    voterFound termEq
  have candidate : Not (voter.role = .candidate) := by
    intro role
    have voted := (lead.inv.candidate node voter now role).2.1
    rw [vote, Option.some.injEq] at voted
    exact different voted.symm
  have primary : Not (voter.role = .primary) := by
    intro role
    have led := lead.inv.leader_led node voter now role
    rw [termEq] at led
    exact different (lead.unique led)
  cases role : voter.role <;> simp_all

/-- The first heartbeat's matching term implies its predecessor index exists,
so a voter accepts the newly elected primary. -/
theorem heartbeat_accepted {index : Nat} {step : Execution.Step W Liveness.Event}
    {packet : Packet} {request : AppendEntriesRequest} {voter : NodeState}
    (le : c <= index) (stepped : trace.stepAt index = some step)
    (delivery : step.action = .deliver packet)
    (early : time step.after < time origin + E / 2)
    (member : packet.envelope.target ∈ participants)
    (different : packet.envelope.target ≠ packet.envelope.source)
    (payload : packet.envelope.payload = .appendEntriesRequest request)
    (requestTerm : request.term = term + 1)
    (voterFound : nodeState (proto step.before) packet.envelope.target = some voter)
    (voterTerm : voter.currentTerm = term + 1) (role : voter.role = .follower)
    (leaderFound
      : exists primary,
          nodeState (proto step.before) packet.envelope.source = some primary
          /\ primary.role = .primary
          /\ primary.currentTerm = term + 1)
    : exists after,
        nodeState (proto step.after) packet.envelope.target = some after
        /\ after.currentTerm = term + 1
        /\ after.primaryKnown = true
        /\ after.role = .follower := by
  have selected : step.action.action = some (.deliver packet.envelope) := by
    rw [delivery]; rfl
  obtain ⟨rest, ctx, acts, _⟩ := ctx_at setup.admissible stepped selected
  obtain ⟨actorEq, eventEq⟩ := acts
  change ctx.actor = packet.envelope.target at actorEq
  change ctx.event = .receive packet.envelope.source packet.envelope.payload at eventEq
  have voterEq := ctx.now_pre (actorEq ▸ (now_of_found (rest := rest) voterFound))
  subst voter
  have event : ctx.event =
      .receive packet.envelope.source (.appendEntriesRequest request) := by
    rw [eventEq, payload]
  obtain ⟨e, queued, sourceEq, targetEq, payloadEq⟩ := ctx.received event
  obtain ⟨primary, primaryFound, primaryRole, primaryTerm⟩ := leaderFound
  have lead : Lead nodes (proto step.before :: rest) packet.envelope.source (term + 1) primary :=
    ⟨ctx.prior, now_of_found primaryFound, primaryRole, primaryTerm⟩
  have requestOk := lead.request queued payloadEq requestTerm
  have bounded := within setup originFound le (setup.admissible.before stepped)
    (le_trans (setup.admissible.timing.next stepped).1 early.le)
  have matching := setup.matching index step packet request ctx.pre bounded stepped delivery
    member different payload voterFound (by omega) (by simp [role]) (by simp [role])
  have bound : request.prevLogIndex <= ctx.pre.log.length := by
    by_contra beyond
    have zero := termAt_of_length_lt (by omega : ctx.pre.log.length < request.prevLogIndex)
    have positive := termAt_pos lead.inv lead.now
      (by omega : 0 < request.prevLogIndex) requestOk.2.2.1
    rw [zero, requestOk.2.2.2.1] at matching
    omega
  have accepted := ElectedStep.accept (LocalTransition.electedStep ctx.tr)
    packet.envelope.source request event role
    (voterTerm.trans requestTerm.symm) bound matching
  have postFound := found_of_now ctx.exec ctx.post_now
  rcases accepted with ⟨known, role, termEq⟩ | retired
  · exact ⟨ctx.post, actorEq ▸ postFound, termEq.trans requestTerm, known, role⟩
  · exact (setup.active (index + 1) step.after ctx.actor ctx.post
      (within setup originFound (Nat.le_succ_of_le le)
        (Trace.stateAt_succ_of_stepAt stepped) early.le)
      (Trace.stateAt_succ_of_stepAt stepped) (actorEq ▸ member) postFound retired).elim

end CCFRaft.Proofs.Duel.Elected
