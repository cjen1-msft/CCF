module

public import CCFRaft.Proofs.Leadership.Quiet
public import CCFRaft.Liveness.Assumptions.Window

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# A term quiet among participants

`Quiet.step` restricted to a set of participants. A step changes only its
actor's state and sends only from its actor, so a step of a non-participant
cannot break a clause about participants. A participant moves past the term only
by an election timeout in it, a pre-vote candidacy in it, or a message from past
it or a proposal for it; when every message a participant receives comes from a
participant, the first is ruled out by the clause about messages between
participants, and the second is a premise of the step, discharged over the packet
ledger (`NoProposals`). Election safety, already proven, still shows that only
the primary can propose a vote in the term.
-/

namespace CCFRaft.Proofs.Leadership

open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Replication

variable [Config.InitialConfiguration]

section Step

variable {nodes : List NodeID} {after before : Model.State} {rest : History}
  (c : Ctx nodes after before rest) {participants : Finset NodeID} {leader : NodeID}
  {term : Nat} (quiet : QuietAmong participants leader term before)
  (leaderIn : leader ∈ participants)

include c quiet

/-- The primary, as the head of the history before the step. -/
theorem QuietAmong.lead
    : exists local_, Lead nodes (before :: rest) leader term local_ := by
  obtain ⟨local_, now, primary, termEq⟩ := quiet.leader
  exact ⟨local_, c.prior, now, primary, termEq⟩

/-- A participant's term after its step stays within the quiet term. -/
theorem QuietAmong.post_term (actorIn : c.actor ∈ participants)
    (timeout : c.event = .internal (.timeout .election) -> c.pre.currentTerm < term)
    (isolated
      : forall source message, c.event = .receive source message -> source ∈ participants)
    (proposed
      : forall source, Not (c.event = .receive source (.proposeRequestVoteRequest term)))
    : c.post.currentTerm <= term := by
  have preLe := quiet.terms _ _ c.pre_now actorIn
  rcases Summary.term_cause c.sum with le | ⟨eq, cause⟩ | ⟨source, message, eq, le⟩
  · omega
  · rcases cause with timeoutEq | ⟨_, _, _, pre⟩ | ⟨source, eventEq⟩
    · have := timeout timeoutEq
      omega
    · have := quiet.preVotes _ _ c.pre_now actorIn pre
      omega
    · have different : Not (c.pre.currentTerm = term) := fun same =>
        proposed source (same ▸ eventEq)
      omega
  · obtain ⟨envelope, pending, sourceEq, targetEq, payload⟩ := c.received eq
    have := quiet.messages envelope pending (sourceEq ▸ isolated _ _ eq) (targetEq ▸ actorIn)
    rw [payload] at this
    omega

include leaderIn

/-- Only the primary can propose a vote in the quiet term, and it does not. -/
theorem QuietAmong.no_proposal
    (timeout : c.event = .internal (.timeout .election) -> c.pre.currentTerm < term)
    (isolated
      : c.actor ∈ participants
        -> forall source message,
            c.event = .receive source message -> source ∈ participants)
    (proposed
      : c.actor ∈ participants
        -> forall source,
            Not (c.event = .receive source (.proposeRequestVoteRequest term)))
    (nominate : c.actor = leader -> Not (c.event = .internal .nominateSuccessor))
    (member : c.actor = leader -> Not (c.post.isRetiredCommitted leader))
    {envelope : Model.Envelope} (sent : envelope ∈ c.sent)
    : Not (envelope.payload = .proposeRequestVoteRequest term) := by
  intro payload
  obtain ⟨_, ok⟩ := Summary.sends c.sum envelope sent
  rw [payload] at ok
  obtain ⟨termEq, origin⟩ := ok
  obtain ⟨local_, lead⟩ := QuietAmong.lead c quiet
  have led := c.post_led (origin.imp (fun primary => ⟨primary.1, primary.2.1⟩) id)
  rw [← termEq] at led
  have inv : Inv (after :: before :: rest) :=
    good_of_exec c.exec _ (List.suffix_refl _) (List.cons_ne_nil _ _)
  have same : c.actor = leader :=
    inv.election_safety _ _ _ led (lead.led.mono c.suffix_tail)
  have actorIn : c.actor ∈ participants := same ▸ leaderIn
  have pre : local_ = c.pre := c.now_pre (same ▸ lead.now)
  rcases origin with ⟨_, _, cause⟩ | wins
  · rcases cause with eventEq | retired
    · exact nominate same eventEq
    · exact member same (same ▸ retired)
  · obtain ⟨candidate, campaign, _, _, postTerm, _⟩ := Wins.facts wins
    have bound := QuietAmong.post_term c quiet actorIn timeout (isolated actorIn)
      (proposed actorIn)
    rcases campaign.2.2.2 with ⟨_, freshTerm, _⟩ | kept
    · have := lead.term
      rw [pre] at this
      omega
    · have := lead.primary
      rw [pre, kept.1] at this
      cases this

/-- A step keeps a state quiet among participants if every message a participant
receives comes from a participant and is no proposal for the term, and the step
is not an election timeout of a participant in the term, nor the primary
retiring or failing its quorum check. -/
theorem QuietAmong.step
    (timeout
      : c.actor ∈ participants
        -> c.event = .internal (.timeout .election)
        -> c.pre.currentTerm < term)
    (isolated
      : c.actor ∈ participants
        -> forall source message,
            c.event = .receive source message -> source ∈ participants)
    (proposed
      : c.actor ∈ participants
        -> forall source,
            Not (c.event = .receive source (.proposeRequestVoteRequest term)))
    (check : c.actor = leader -> Not (c.event = .internal (.timeout .checkQuorum)))
    (member : c.actor = leader -> Not (c.post.isRetiredCommitted leader))
    : QuietAmong participants leader term after := by
  have postLe : c.actor ∈ participants -> c.post.currentTerm <= term := fun actorIn =>
    QuietAmong.post_term c quiet actorIn (timeout actorIn) (isolated actorIn)
      (proposed actorIn)
  have inv : Inv (after :: before :: rest) :=
    good_of_exec c.exec _ (List.suffix_refl _) (List.cons_ne_nil _ _)
  refine ⟨
    fun node local_ now nodeIn => ?_,
    fun node local_ now nodeIn preVote => ?_,
    fun envelope queued sourceIn targetIn => ?_,
    ?_
  ⟩
  · rcases c.now_after now with ⟨same, rfl⟩ | ⟨_, old⟩
    · exact postLe (same ▸ nodeIn)
    · exact quiet.terms _ _ old nodeIn
  · rcases c.now_after now with ⟨same, rfl⟩ | ⟨_, old⟩
    · have actorIn : c.actor ∈ participants := same ▸ nodeIn
      obtain ⟨termEq, cause⟩ := Summary.pre_vote c.sum preVote
      rw [termEq]
      rcases cause with pre | eventEq
      · exact quiet.preVotes _ _ c.pre_now actorIn pre
      · exact timeout actorIn eventEq
    · exact quiet.preVotes _ _ old nodeIn preVote
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
  · obtain ⟨local_, lead⟩ := QuietAmong.lead c quiet
    by_cases same : c.actor = leader
    · have pre : local_ = c.pre := c.now_pre (same ▸ lead.now)
      have preTerm : c.pre.currentTerm = term := pre ▸ lead.term
      have prePrimary : c.pre.role = .primary := pre ▸ lead.primary
      have termEq : c.post.currentTerm = c.pre.currentTerm := by
        have := c.term_le
        have := postLe (same ▸ leaderIn)
        omega
      refine ⟨c.post, same ▸ c.post_now, ?_, termEq.trans preTerm⟩
      rcases Summary.role_keep c.sum prePrimary termEq with primary | retired | eventEq
          | ⟨source, request, eventEq, requestTerm⟩
      · exact primary
      · exact (member same (same ▸ retired)).elim
      · exact (check same eventEq).elim
      · obtain ⟨envelope, pending, _, target, payload⟩ := c.received eventEq
        have := (lead.request pending payload (requestTerm.trans preTerm)).2.1
        exact (this (target.trans same)).elim
    · exact ⟨local_, c.now_other (Ne.symm same) lead.now, lead.primary, lead.term⟩

end Step

end CCFRaft.Proofs.Leadership
