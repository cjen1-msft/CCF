module

public import CCFRaft.Proofs.Leadership.AnchorNode
public import CCFRaft.Liveness.Assumptions.Anchor
public import CCFRaft.Proofs.Direct.AppendOnly
public import CCFRaft.Proofs.Leadership.Membership

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# One step keeps an anchored term quiet

`QuietAmong.step` without its pre-vote clause, for an anchor. A participant
moves past the term only by a fresh campaign in it, and a fresh campaign needs a
quorum of pre-votes, which meets the anchor when every active configuration of
the participant is blocked by it. An anchor node knows the primary, so it grants
no pre-vote, and it keeps knowing the primary and its role unless it times out,
fails a quorum check, sees a newer term, is asked to campaign, or retires.
-/

namespace CCFRaft.Proofs.Leadership

open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Replication

/-- A quorum of configurations all blocked by `anchor` meets it. -/
theorem quorum_meets {configurations : List Configuration} {voters anchor : Finset NodeID}
    (quorum : hasQuorum configurations voters)
    (blocked
      : forall configuration,
          configuration ∈ configurations -> Blocked anchor configuration.nodes)
    : exists voter, voter ∈ voters /\ voter ∈ anchor := by
  obtain ⟨nonempty, all⟩ := quorum
  obtain ⟨configuration, member⟩ := List.exists_mem_of_ne_nil _ nonempty
  have majority := of_decide_eq_true (List.all_eq_true.mp all configuration member)
  have block := blocked configuration member
  unfold hasConfigurationMajority at majority
  unfold Blocked at block
  by_contra none_
  push Not at none_
  have sub : voters ∩ configuration.nodes ⊆ configuration.nodes \ anchor := by
    intro node member
    obtain ⟨voter, inNodes⟩ := Finset.mem_inter.mp member
    exact Finset.mem_sdiff.mpr ⟨inNodes, none_ node voter⟩
  have := Finset.card_le_card sub
  omega

/-- A granted pre-vote response of `term` is that response. -/
theorem grantedResponse {response : RequestVoteResponse} {term : Nat}
    (termEq : response.term = term) (granted : response.voteGranted = true)
    : response = { term, voteGranted := true } := by
  cases response
  simp_all

/-- A quorum of the active configurations of a configuration history stays a
quorum as the commit index grows. -/
theorem quorum_of_commit {log log' : List Entry} {small large : Nat}
    (history : configurationHistory log' = configurationHistory log) (le : small <= large)
    {voters : Finset NodeID} (quorum : hasQuorum (activeConfigurations log small) voters)
    : hasQuorum (activeConfigurations log' large) voters := by
  obtain ⟨nonempty, all⟩ := quorum
  unfold activeConfigurations at nonempty all ⊢
  dsimp only at nonempty all ⊢
  rw [history]
  have mono := length_filter_index_mono (configurationHistory log) le
  generalize configurationHistory log = configurations at nonempty all mono ⊢
  have bound := List.length_filter_le
    (fun configuration : Configuration => decide (configuration.index <= large))
    configurations
  generalize (configurations.filter fun configuration => configuration.index <= small).length
    = few at nonempty all mono ⊢
  generalize (configurations.filter fun configuration => configuration.index <= large).length
    = many at mono bound ⊢
  have split : configurations.drop (many - 1)
      = (configurations.drop (few - 1)).drop (many - 1 - (few - 1)) := by
    rw [List.drop_drop]
    congr 1
    omega
  refine ⟨?_, List.all_eq_true.mpr fun configuration member => ?_⟩
  · have := mt List.drop_eq_nil_iff.mpr nonempty
    rw [Ne, List.drop_eq_nil_iff]
    omega
  · rw [split] at member
    exact List.all_eq_true.mp all configuration (List.mem_of_mem_drop member)

variable [Config.InitialConfiguration]

section Step

variable {nodes : List NodeID} {after before : Model.State} {rest : History}
  (c : Ctx nodes after before rest) {participants anchor : Finset NodeID}
  {leader : NodeID} {term : Nat} (quiet : QuietTerm participants leader term before)
  (anchored : Anchor participants anchor leader term before)
  (blocked
    : forall node local_,
        (node, local_) ∈ before.nodes
        -> node ∈ participants
        -> forall configuration,
            configuration ∈ local_.activeConfigurations
            -> Blocked anchor configuration.nodes)
  (isolated
    : c.actor ∈ participants
      -> forall source message,
          c.event = .receive source message -> source ∈ participants)
  (timeout
    : c.actor ∈ anchor
      -> c.event = .internal (.timeout .election)
      -> c.pre.currentTerm < term)
  (proposed
    : c.actor ∈ participants
      -> forall source, Not (c.event = .receive source (.proposeRequestVoteRequest term)))

include c quiet

/-- The primary, as the head of the history before the step. -/
theorem QuietTerm.lead
    : exists local_, Lead nodes (before :: rest) leader term local_ := by
  obtain ⟨local_, now, primary, termEq⟩ := quiet.leader
  exact ⟨local_, c.prior, now, primary, termEq⟩

/-- A participant receives no message past the term. -/
theorem QuietTerm.not_raised (actorIn : c.actor ∈ participants)
    (isolated
      : forall source message, c.event = .receive source message -> source ∈ participants)
    (preTerm : c.pre.currentTerm = term)
    : Not (Raised c.pre c.event) := by
  rintro ⟨source, message, eventEq, lt⟩
  obtain ⟨envelope, pending, sourceEq, targetEq, payload⟩ := c.received eventEq
  have := quiet.messages envelope pending (sourceEq ▸ isolated _ _ eventEq)
    (targetEq ▸ actorIn)
  rw [payload] at this
  omega

/-- A participant outside the anchor receives no granted pre-vote of the term
from it. -/
theorem Anchor.no_grant_received
    (anchored : Anchor participants anchor leader term before)
    (actorIn : c.actor ∈ participants \ anchor) {source : NodeID}
    {response : RequestVoteResponse}
    (eventEq : c.event = .receive source (.requestPreVoteResponse response))
    (termEq : response.term = term) (granted : response.voteGranted = true)
    : source ∉ anchor := by
  intro inAnchor
  obtain ⟨envelope, pending, sourceEq, targetEq, payload⟩ := c.received eventEq
  refine anchored.noGrants envelope pending (sourceEq ▸ inAnchor) (targetEq ▸ actorIn) ?_
  rw [payload, grantedResponse termEq granted]

/-- A step of the primary keeps the configuration history of its log, when it
receives only from participants and appends no configuration. -/
theorem QuietTerm.history_keep (leaderIn : leader ∈ participants)
    (same : c.actor = leader)
    (isolated
      : forall source message, c.event = .receive source message -> source ∈ participants)
    (plain
      : forall contents,
          c.event = .internal (.append contents)
          -> forall content, content ∈ contents -> content.metadata.configuration = none)
    : configurationHistory c.post.log = configurationHistory c.pre.log := by
  obtain ⟨local_, lead⟩ := QuietTerm.lead c quiet
  have now : Now (before :: rest) c.actor local_ := by
    rw [same]
    exact lead.now
  have localEq := c.now_pre now
  have primary : c.pre.role = .primary := localEq ▸ lead.primary
  have termEq : c.pre.currentTerm = term := localEq ▸ lead.term
  have ran := c.tr.ran
  cases eventEq : c.tr.event with
  | internal input =>
      rw [eventEq] at ran
      by_cases appending : exists contents, input = .append contents
      · obtain ⟨contents, rfl⟩ := appending
        obtain ⟨log, _⟩ := CommitLiveness.append_log c.tr.actor c.tr.pre contents _ _ _ ran
        show configurationHistory c.tr.post.log = _
        rw [log]
        refine configurationHistory_append_none fun entry member => ?_
        obtain ⟨content, contentIn, rfl⟩ := List.mem_map.mp member
        exact plain contents eventEq content contentIn
      · have kept := act_log c.tr.actor c.tr.pre input primary
          (fun contents eq => appending ⟨contents, eq⟩) _ _ _ ran
        show configurationHistory c.tr.post.log = _
        rw [kept]
  | receive source message =>
      rw [eventEq] at ran
      have kept := receive_log c.tr.actor c.tr.pre source message primary
        (fun request payloadEq => by
          obtain ⟨envelope, pending, sourceEq, targetEq, payload⟩ :=
            c.received (eventEq.trans (by rw [payloadEq]))
          have targetLeader : envelope.target = leader := targetEq.trans same
          have le := quiet.messages envelope pending
            (sourceEq ▸ isolated source message eventEq) (targetLeader ▸ leaderIn)
          rw [payload] at le
          have notTerm : Not (request.term = term) := fun current =>
            (lead.request pending payload current).2.1 targetLeader
          change request.term <= term at le
          have termEq' : c.tr.pre.currentTerm = term := termEq
          omega) _ _ _ ran
      show configurationHistory c.tr.post.log = _
      rw [kept]

/-- An anchor node is settled in the term before the step. -/
theorem Anchor.pre_settled (anchored : Anchor participants anchor leader term before)
    (actorIn : c.actor ∈ anchor)
    : c.pre.currentTerm = term
      /\ c.pre.primaryKnown = true
      /\ (c.pre.role = .follower \/ c.pre.role = .primary) := by
  obtain ⟨local_, now, termEq, known, role⟩ := anchored.settled _ actorIn
  have localEq : local_ = c.pre := c.now_pre now
  subst localEq
  exact ⟨termEq, known, role⟩

/-- A pre-vote candidate is outside the anchor. -/
theorem Anchor.pre_outside (anchored : Anchor participants anchor leader term before)
    (actorIn : c.actor ∈ participants) (preVote : c.pre.role = .preVoteCandidate)
    : c.actor ∈ participants \ anchor := by
  refine Finset.mem_sdiff.mpr ⟨actorIn, fun inAnchor => ?_⟩
  obtain ⟨_, _, role⟩ := Anchor.pre_settled c quiet anchored inAnchor
  rcases role with role | role <;> rw [role] at preVote <;> cases preVote

include anchored blocked isolated timeout proposed

/-- A participant's term after its step stays within the term. -/
theorem Anchor.post_term (actorIn : c.actor ∈ participants)
    : c.post.currentTerm <= term := by
  have preLe := quiet.terms _ _ c.pre_now actorIn
  have step := LocalTransition.anchorStep c.tr
  rcases Summary.term_cause c.sum with le | ⟨eq, cause⟩ | ⟨source, message, eq, le⟩
  · omega
  · by_contra beyond
    have preTerm : c.pre.currentTerm = term := by omega
    have notRaised := QuietTerm.not_raised c quiet actorIn (isolated actorIn) preTerm
    have up : c.pre.currentTerm < c.post.currentTerm := by omega
    obtain ⟨fromTimeout, fromResponse⟩ := step.fresh up notRaised
    rcases cause with timeoutEq | ⟨source, response, eventEq, preVote⟩ | ⟨source, eventEq⟩
    · obtain ⟨voter, voterIn, inAnchor⟩ := quorum_meets (fromTimeout timeoutEq)
        (blocked _ _ c.pre_now actorIn)
      rw [Finset.mem_singleton.mp voterIn] at inAnchor
      have := timeout inAnchor timeoutEq
      omega
    · obtain ⟨termEq, granted, quorum⟩ := fromResponse source response eventEq
      obtain ⟨voter, voterIn, inAnchor⟩ := quorum_meets quorum
        (blocked _ _ c.pre_now actorIn)
      rcases Finset.mem_insert.mp voterIn with rfl | old
      · exact Anchor.no_grant_received c quiet anchored
          (Anchor.pre_outside c quiet anchored actorIn preVote) eventEq
          (termEq.trans preTerm) granted inAnchor
      · exact Finset.disjoint_left.mp
          (anchored.notCounted _ _ c.pre_now actorIn preVote preTerm) old inAnchor
    · exact proposed actorIn source (preTerm ▸ eventEq)
  · obtain ⟨envelope, pending, sourceEq, targetEq, payload⟩ := c.received eq
    have := quiet.messages envelope pending (sourceEq ▸ isolated actorIn _ _ eq)
      (targetEq ▸ actorIn)
    rw [payload] at this
    omega

/-- Only the primary can propose a vote in the term, and it does not. -/
theorem QuietTerm.no_proposal
    (nominate : c.actor = leader -> Not (c.event = .internal .nominateSuccessor))
    (retired : c.actor ∈ anchor -> Not (c.post.isRetiredCommitted c.actor))
    {envelope : Model.Envelope} (sent : envelope ∈ c.sent)
    : Not (envelope.payload = .proposeRequestVoteRequest term) := by
  intro payload
  obtain ⟨_, ok⟩ := Summary.sends c.sum envelope sent
  rw [payload] at ok
  obtain ⟨termEq, origin⟩ := ok
  obtain ⟨local_, lead⟩ := QuietTerm.lead c quiet
  have led := c.post_led (origin.imp (fun primary => ⟨primary.1, primary.2.1⟩) id)
  rw [← termEq] at led
  have inv : Inv (after :: before :: rest) :=
    good_of_exec c.exec _ (List.suffix_refl _) (List.cons_ne_nil _ _)
  have same : c.actor = leader :=
    inv.election_safety _ _ _ led (lead.led.mono c.suffix_tail)
  have actorIn : c.actor ∈ anchor := same ▸ anchored.leaderIn
  have pre : local_ = c.pre := c.now_pre (same ▸ lead.now)
  rcases origin with ⟨_, _, cause⟩ | wins
  · rcases cause with eventEq | retired'
    · exact nominate same eventEq
    · exact retired actorIn retired'
  · obtain ⟨candidate, campaign, _, _, postTerm, _⟩ := Wins.facts wins
    have bound := Anchor.post_term c quiet anchored blocked isolated timeout proposed
      (anchored.subset actorIn)
    rcases campaign.2.2.2 with ⟨_, freshTerm, _⟩ | kept
    · have := lead.term
      rw [pre] at this
      omega
    · have := lead.primary
      rw [pre, kept.1] at this
      cases this

/-- A step keeps the term quiet among participants when every message a
participant receives comes from a participant and is no proposal for the term,
and no anchor node times out in the term, fails a quorum check or retires. -/
theorem QuietTerm.step
    (check : c.actor ∈ anchor -> Not (c.event = .internal (.timeout .checkQuorum)))
    (retired : c.actor ∈ anchor -> Not (c.post.isRetiredCommitted c.actor))
    : QuietTerm participants leader term after := by
  have postLe : c.actor ∈ participants -> c.post.currentTerm <= term := fun actorIn =>
    Anchor.post_term c quiet anchored blocked isolated timeout proposed actorIn
  have inv : Inv (after :: before :: rest) :=
    good_of_exec c.exec _ (List.suffix_refl _) (List.cons_ne_nil _ _)
  have leaderIn : leader ∈ participants := anchored.subset anchored.leaderIn
  refine ⟨
    fun node local_ now nodeIn => ?_,
    fun envelope queued sourceIn targetIn => ?_,
    ?_
  ⟩
  · rcases c.now_after now with ⟨same, rfl⟩ | ⟨_, old⟩
    · exact postLe (same ▸ nodeIn)
    · exact quiet.terms _ _ old nodeIn
  · rcases c.tr.mem_network queued with old | new
    · exact quiet.messages envelope old sourceIn targetIn
    · obtain ⟨sourceEq, ok⟩ := Summary.sends c.sum envelope new
      have postLe := postLe (sourceEq ▸ sourceIn)
      have logLe := termAt_le_term inv c.post_now
      cases h : envelope.payload with
      | appendEntriesRequest request =>
          simp only [h] at ok
          have := ok.1.2.1
          simp only [Message.term]
          omega
      | appendEntriesResponse response =>
          simp only [h] at ok
          simp only [Message.term]
          rcases ok.1 with eq | ⟨index, eq⟩
          · omega
          · have := logLe index
            omega
      | requestVoteRequest request =>
          simp only [h] at ok
          have := ok.1
          simp only [Message.term]
          omega
      | requestVoteResponse response =>
          simp only [h] at ok
          have := ok.1
          simp only [Message.term]
          omega
      | requestPreVoteRequest request =>
          simp only [h, Message.term] at ok ⊢
          omega
      | requestPreVoteResponse response =>
          simp only [h, Message.term] at ok ⊢
          omega
      | proposeRequestVoteRequest proposed =>
          simp only [h] at ok
          have := ok.1
          simp only [Message.term]
          omega
  · obtain ⟨local_, lead⟩ := QuietTerm.lead c quiet
    by_cases same : c.actor = leader
    · have pre : local_ = c.pre := c.now_pre (same ▸ lead.now)
      have preTerm : c.pre.currentTerm = term := pre ▸ lead.term
      have prePrimary : c.pre.role = .primary := pre ▸ lead.primary
      have termEq : c.post.currentTerm = c.pre.currentTerm := by
        have := c.term_le
        have := postLe (same ▸ leaderIn)
        omega
      have actorIn : c.actor ∈ anchor := same ▸ anchored.leaderIn
      refine ⟨c.post, same ▸ c.post_now, ?_, termEq.trans preTerm⟩
      rcases Summary.role_keep c.sum prePrimary termEq with primary | retired' | eventEq
          | ⟨source, request, eventEq, requestTerm⟩
      · exact primary
      · exact (retired actorIn retired').elim
      · exact (check actorIn eventEq).elim
      · obtain ⟨envelope, pending, _, target, payload⟩ := c.received eventEq
        have := (lead.request pending payload (requestTerm.trans preTerm)).2.1
        exact (this (target.trans same)).elim
    · exact ⟨local_, c.now_other (Ne.symm same) lead.now, lead.primary, lead.term⟩

/-- A step keeps the anchor under the hypotheses of `QuietTerm.step`, when the
primary appends no configuration. -/
theorem Anchor.step
    (check : c.actor ∈ anchor -> Not (c.event = .internal (.timeout .checkQuorum)))
    (retired : c.actor ∈ anchor -> Not (c.post.isRetiredCommitted c.actor))
    (plain
      : forall contents,
          c.event = .internal (.append contents)
          -> forall content, content ∈ contents -> content.metadata.configuration = none)
    : Anchor participants anchor leader term after := by
  have actorStep := LocalTransition.anchorStep c.tr
  have postLe : c.actor ∈ participants -> c.post.currentTerm <= term := fun actorIn =>
    Anchor.post_term c quiet anchored blocked isolated timeout proposed actorIn
  have leaderIn : leader ∈ participants := anchored.subset anchored.leaderIn
  have history : c.actor = leader
      -> configurationHistory c.post.log = configurationHistory c.pre.log := fun same =>
    QuietTerm.history_keep c quiet leaderIn same (isolated (same ▸ leaderIn)) plain
  have preLeader : c.actor = leader -> (leader, c.pre) ∈ before.nodes := fun same => by
    rw [← same]
    exact c.pre_now
  refine ⟨anchored.subset, anchored.leaderIn, fun local_ now => ?_,
    fun local_ now node nodeIn different => ?_, fun node nodeIn => ?_,
    fun envelope queued sourceIn targetIn payload => ?_,
    fun node local_ now nodeIn preVote termEq => ?_⟩
  · rcases c.now_after now with ⟨same, rfl⟩ | ⟨_, old⟩
    · exact quorum_of_commit (history same.symm)
        (CCFRaft.Proofs.Direct.extends_step c.tr.ran).1
        (anchored.quorum _ (preLeader same.symm))
    · exact anchored.quorum _ old
  · rcases c.now_after now with ⟨same, rfl⟩ | ⟨_, old⟩
    · have member := anchored.members _ (preLeader same.symm) node nodeIn different
      unfold NodeState.activeConfigurations at member ⊢
      rw [latest_active] at member ⊢
      rwa [history same.symm]
    · exact anchored.members _ old node nodeIn different
  · obtain ⟨local_, now, termEq, known, role⟩ := anchored.settled node nodeIn
    by_cases same : node = c.actor
    · rw [same] at nodeIn now ⊢
      have actorIn : c.actor ∈ participants := anchored.subset nodeIn
      have localEq : local_ = c.pre := c.now_pre now
      subst localEq
      have notRaised := QuietTerm.not_raised c quiet actorIn (isolated actorIn) termEq
      have postTerm : c.post.currentTerm = term := by
        have := c.term_le
        have := postLe actorIn
        omega
      refine ⟨c.post, c.post_now, postTerm, ?_⟩
      rcases actorStep.keep known role with latched | exempt
      · rcases latched with ⟨roleEq, knownEq⟩ | retired'
        · exact ⟨knownEq.trans known, roleEq ▸ role⟩
        · exact (retired nodeIn retired').elim
      · rcases exempt with eventEq | eventEq | up | ⟨source, eventEq⟩
        · have := timeout nodeIn eventEq
          omega
        · exact (check nodeIn eventEq).elim
        · exact (notRaised up).elim
        · exact (proposed actorIn source (termEq ▸ eventEq)).elim
    · exact ⟨local_, c.now_other same now, termEq, known, role⟩
  · rcases c.tr.mem_network queued with old | new
    · exact anchored.noGrants envelope old sourceIn targetIn payload
    · obtain ⟨sourceEq, _⟩ := Summary.sends c.sum envelope new
      have actorIn : c.actor ∈ anchor := sourceEq ▸ sourceIn
      obtain ⟨preTerm, known, _⟩ := Anchor.pre_settled c quiet anchored actorIn
      rcases actorStep.grants envelope new _ payload rfl with unknown | up
      · rw [known] at unknown
        cases unknown
      · exact QuietTerm.not_raised c quiet (anchored.subset actorIn)
          (isolated (anchored.subset actorIn)) preTerm up
  · rcases c.now_after now with ⟨same, rfl⟩ | ⟨_, old⟩
    · have actorIn : c.actor ∈ participants := same ▸ nodeIn
      obtain ⟨keptTerm, cause⟩ := Summary.pre_vote c.sum preVote
      have preTerm : c.pre.currentTerm = term := keptTerm.symm.trans termEq
      refine Finset.disjoint_left.mpr fun voter voterIn inAnchor => ?_
      rcases actorStep.counts voter voterIn with ⟨eventEq, rfl⟩ | ⟨notTimeout, old⟩
          | ⟨response, eventEq, responseTerm, granted⟩
      · have := timeout inAnchor eventEq
        omega
      · rcases cause with prePreVote | eventEq
        · exact Finset.disjoint_left.mp
            (anchored.notCounted _ _ c.pre_now actorIn prePreVote preTerm) old inAnchor
        · exact notTimeout eventEq
      · have actorOut : c.actor ∈ participants \ anchor := by
          rcases cause with prePreVote | eventEq'
          · exact Anchor.pre_outside c quiet anchored actorIn prePreVote
          · refine Finset.mem_sdiff.mpr ⟨actorIn, fun inAnchor' => ?_⟩
            have := timeout inAnchor' eventEq'
            omega
        exact Anchor.no_grant_received c quiet anchored actorOut eventEq
          (responseTerm.trans preTerm) granted inAnchor
    · exact anchored.notCounted _ _ old nodeIn preVote termEq

end Step

end CCFRaft.Proofs.Leadership
