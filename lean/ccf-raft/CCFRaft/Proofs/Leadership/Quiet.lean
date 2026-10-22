module

public import CCFRaft.Proofs.Replication.Step

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# A quiet term

While no node can move past the primary's term, the primary keeps its role. A
node moves past the term only by a fresh campaign from it, or by receiving a
message from past it. A fresh campaign from the term needs an election timeout, a
pre-vote candidacy in the term, which only an election timeout starts, or a vote
proposal for the term, which only the primary sends. So a state is quiet if no
node or message is past the term, no pre-vote candidate or vote proposal is in
it, and the primary still leads it. This file shows that a step keeps a state
quiet, unless it is an election timeout in the term or the primary nominates a
successor, retires, or fails its quorum check.
-/

namespace CCFRaft.Proofs.Leadership

open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Replication

/-- An election timeout runs only on a node that may start an election. -/
theorem startElection_guard (self : NodeID) (state : NodeState)
    : Sends (fun _ _ => canStartElection state self)
        (startElection (Capabilities.record self) state self) := by
  unfold startElection
  refine Sends.bind' Sends.guard' fun _ sent ⟨can, empty⟩ => ?_
  subst empty
  unfold becomePreVoteCandidate
  dsimp only
  refine Sends.ite' (fun _ => Sends.mono (becomeCandidate_sends self _) fun _ _ _ => can)
    fun _ => ?_
  exact Sends.bind' (broadcast_sends self _ _) fun _ _ _ => Sends.pure' can

variable [Config.InitialConfiguration]

section Step

variable {nodes : List NodeID} {after before : Model.State} {rest : History}
  (c : Ctx nodes after before rest) {leader : NodeID} {term : Nat}
  (quiet : Quiet leader term before)

include c quiet

/-- The primary, as the head of the history before the step. -/
theorem Quiet.lead : exists local_, Lead nodes (before :: rest) leader term local_ := by
  obtain ⟨local_, now, primary, termEq⟩ := quiet.leader
  exact ⟨local_, c.prior, now, primary, termEq⟩

/-- The actor's term after the step stays within the quiet term. -/
theorem Quiet.post_term
    (timeout : c.event = .internal (.timeout .election) -> c.pre.currentTerm < term)
    : c.post.currentTerm <= term := by
  have preLe := quiet.terms _ _ c.pre_now
  rcases Summary.term_cause c.sum with le | ⟨eq, cause⟩ | ⟨source, message, eq, le⟩
  · omega
  · rcases cause with timeoutEq | ⟨_, _, _, pre⟩ | ⟨source, eventEq⟩
    · have := timeout timeoutEq
      omega
    · have := quiet.preVotes _ _ c.pre_now pre
      omega
    · obtain ⟨envelope, pending, _, _, payload⟩ := c.received eventEq
      have different : Not (c.pre.currentTerm = term) := fun same =>
        quiet.proposals envelope pending (by rw [payload, same])
      omega
  · obtain ⟨envelope, pending, _, _, payload⟩ := c.received eq
    have := quiet.messages envelope pending
    rw [payload] at this
    omega

/-- Only the primary can propose a vote in the quiet term, and it does not. -/
theorem Quiet.no_proposal
    (timeout : c.event = .internal (.timeout .election) -> c.pre.currentTerm < term)
    (nominate : c.actor = leader -> Not (c.event = .internal .nominateSuccessor))
    (member : c.actor = leader -> Not (c.post.isRetiredCommitted leader))
    {envelope : Model.Envelope} (sent : envelope ∈ c.sent)
    : Not (envelope.payload = .proposeRequestVoteRequest term) := by
  intro payload
  obtain ⟨_, ok⟩ := Summary.sends c.sum envelope sent
  rw [payload] at ok
  obtain ⟨termEq, origin⟩ := ok
  obtain ⟨local_, lead⟩ := Quiet.lead c quiet
  have led := c.post_led (origin.imp (fun primary => ⟨primary.1, primary.2.1⟩) id)
  rw [← termEq] at led
  have inv : Inv (after :: before :: rest) :=
    good_of_exec c.exec _ (List.suffix_refl _) (List.cons_ne_nil _ _)
  have same : c.actor = leader :=
    inv.election_safety _ _ _ led (lead.led.mono c.suffix_tail)
  have pre : local_ = c.pre := c.now_pre (same ▸ lead.now)
  rcases origin with ⟨_, _, cause⟩ | wins
  · rcases cause with eventEq | retired
    · exact nominate same eventEq
    · exact member same (same ▸ retired)
  · obtain ⟨candidate, campaign, _, _, postTerm, _⟩ := Wins.facts wins
    have bound := Quiet.post_term c quiet timeout
    rcases campaign.2.2.2 with ⟨_, freshTerm, _⟩ | kept
    · have := lead.term
      rw [pre] at this
      omega
    · have := lead.primary
      rw [pre, kept.1] at this
      cases this

/-- A step keeps a state quiet, unless it times out an election in the term, or
the primary nominates a successor, retires, or fails its quorum check. -/
theorem Quiet.step
    (timeout : c.event = .internal (.timeout .election) -> c.pre.currentTerm < term)
    (nominate : c.actor = leader -> Not (c.event = .internal .nominateSuccessor))
    (check : c.actor = leader -> Not (c.event = .internal (.timeout .checkQuorum)))
    (member : c.actor = leader -> Not (c.post.isRetiredCommitted leader))
    : Quiet leader term after := by
  have postLe := Quiet.post_term c quiet timeout
  have inv : Inv (after :: before :: rest) :=
    good_of_exec c.exec _ (List.suffix_refl _) (List.cons_ne_nil _ _)
  refine ⟨fun node local_ now => ?_, fun node local_ now preVote => ?_,
    fun envelope queued => ?_, fun envelope queued => ?_, ?_⟩
  · rcases c.now_after now with ⟨_, rfl⟩ | ⟨_, old⟩
    · exact postLe
    · exact quiet.terms _ _ old
  · rcases c.now_after now with ⟨_, rfl⟩ | ⟨_, old⟩
    · obtain ⟨termEq, cause⟩ := Summary.pre_vote c.sum preVote
      rw [termEq]
      rcases cause with pre | eventEq
      · exact quiet.preVotes _ _ c.pre_now pre
      · exact timeout eventEq
    · exact quiet.preVotes _ _ old preVote
  · rcases c.tr.mem_network queued with old | new
    · exact quiet.messages envelope old
    · obtain ⟨_, ok⟩ := Summary.sends c.sum envelope new
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
  · rcases c.tr.mem_network queued with old | new
    · exact quiet.proposals envelope old
    · exact Quiet.no_proposal c quiet timeout nominate member new
  · obtain ⟨local_, lead⟩ := Quiet.lead c quiet
    by_cases same : c.actor = leader
    · have pre : local_ = c.pre := c.now_pre (same ▸ lead.now)
      have preTerm : c.pre.currentTerm = term := pre ▸ lead.term
      have prePrimary : c.pre.role = .primary := pre ▸ lead.primary
      have termEq : c.post.currentTerm = c.pre.currentTerm := by
        have := c.term_le
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
