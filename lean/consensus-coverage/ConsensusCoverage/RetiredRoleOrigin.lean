module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.FullProfile
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.RetiredRoleOrigin

open CCF Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open Consensus.Proofs.Direct

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

-- A new .none role is caused by recording a commit, either in a primary
-- advance (a signature of its term) or when accepting AppendEntries.
private def Origin (before : NodeState) (event : Event) (post : NodeState) : Prop :=
  post.role = .none →
    (before.role = .none ∧ post.currentTerm = before.currentTerm) ∨
    (∃ j, 0 < j ∧ j ≤ post.log.length ∧ termAt post.log j = post.currentTerm) ∨
    ∃ source request, event = .receive source (.appendEntriesRequest request) ∧
      request.term = post.currentTerm

private theorem unchanged {pre evt st} (role : st.role = pre.role)
    (term : st.currentTerm = pre.currentTerm) : Origin pre evt st :=
  fun h => .inl ⟨role ▸ h, term⟩

private theorem active {pre evt st} (role : st.role ≠ .none) : Origin pre evt st :=
  fun h => (role h).elim

private theorem advance {pre evt mid post self} (prior : Origin pre evt mid)
    (advanced : Advance self mid post) : Origin pre evt post := by
  rcases advanced with rfl | ⟨log, term, _, _, _, _, grew, eq, _⟩
  · exact prior
  · obtain ⟨bound, sig, atJ, _⟩ := highestCommittableIndex_spec mid self (eq ▸ grew)
    intro _
    exact .inr (.inl ⟨_, Nat.lt_of_le_of_lt (Nat.zero_le _) (eq ▸ grew), log ▸ bound,
      by rw [log, term]; exact atJ⟩)

private theorem result {α} {P : α → List Model.Envelope → Prop} {m : NodeEffect α}
    (h : Sends P m) {Q : α → Prop} (get : ∀ a sent, P a sent → Q a) : Keeps Q m := by
  intro out a out' ran
  obtain ⟨sent, _, ok⟩ := h out a out' ran
  exact get a sent ok

private theorem campaign {pre evt} (self : NodeID) (st : NodeState) :
    Keeps (Origin pre evt) (becomeCandidate (Capabilities.record self) st self) := by
  refine result (becomeCandidate_sends self st) ?_
  rintro _ _ (⟨rfl, _⟩ | ⟨_, adv, _⟩)
  · exact active (by intro eq; cases eq)
  · exact advance (active (by simp [primaryState])) adv

private theorem old_or_aware (p : NodeState) (m : Message) (evt : Event) :
    Origin p evt (observeTerm p m) := by
  cases m <;> intro h <;> simp only [observeTerm, updateTerm] at * <;>
    (repeat' split at *) <;> simp_all [becomeAwareOfNewTerm]

private theorem keep_fields {pre evt a b} (prior : Origin pre evt a)
    (role : b.role = a.role) (term : b.currentTerm = a.currentTerm) (log : b.log = a.log) :
    Origin pre evt b := by
  intro gone
  simpa only [term, log] using prior (role ▸ gone)

private theorem batch_fields {pre : NodeState} {st next sent self}
    (same : st.role = pre.role ∧ st.currentTerm = pre.currentTerm)
    (batch : BatchState self st next sent) :
    next.role = pre.role ∧ next.currentTerm = pre.currentTerm := by
  obtain ⟨⟨_, _, rfl, _⟩, _⟩ := batch
  exact same

private theorem batch_start (self : NodeID) (st : NodeState) : BatchState self st st [] :=
  ⟨⟨[], st.sentIndex, by simp, by simp⟩, by simp⟩

private theorem local_step (self : NodeID) (p : NodeState) (input : Input) :
    Keeps (Origin p (.internal input)) (act (Capabilities.record self) self p input) := by
  cases input with
  | append contents =>
    unfold act appendBatch
    apply Keeps.seq'
    intro _
    refine Keeps.bind' (Keeps.foldlM' (P := fun st =>
      st.role = p.role ∧ st.currentTerm = p.currentTerm) (fun st entry h => ?_)
        contents p ⟨rfl, rfl⟩) fun mid h =>
      result (advanceCommit_sends self mid) (fun _ _ done => advance (unchanged h.1 h.2) done.1)
    refine Keeps.bind' (result (appendEntry_batch self st st [] entry.content (batch_start ..))
      (fun _ _ batch => batch_fields h batch))
      fun appended h => ?_
    exact Keeps.foldlM' (fun cur (peer, idx) same =>
      result (sendEntries_batch self cur cur [] peer idx (batch_start ..)) fun _ _ batch =>
        batch_fields same batch)
      entry.flushes appended h
  | sendEntries peer idx =>
    unfold act sendEntries
    exact Keeps.seq' fun _ => Keeps.seq' fun _ => Keeps.pure' (unchanged rfl rfl)
  | nominateSuccessor =>
    exact result (nominate_sends self p) fun _ _ h => h.1 ▸ unchanged rfl rfl
  | initAsBackup => exact Keeps.seq' fun _ => Keeps.pure' (active (by intro eq; cases eq))
  | timeout k =>
    cases k with
    | checkQuorum => exact Keeps.seq' fun _ => Keeps.pure' (active (by intro eq; cases eq))
    | election =>
      unfold act startElection becomePreVoteCandidate
      exact Keeps.seq' fun _ => Keeps.ite' (fun _ => campaign _ _)
        fun _ => Keeps.seq' fun _ => Keeps.pure' (active (by intro eq; cases eq))

private theorem receive_step (self src : NodeID) (p : NodeState) (m : Message) :
    Keeps (Origin p (.receive src m)) (receive (Capabilities.record self) self src p m) := by
  unfold receive
  refine Keeps.ite' (fun _ => Keeps.pure' (unchanged rfl rfl)) fun _ => ?_
  have old := old_or_aware p m (.receive src m)
  cases m with
  | requestVoteRequest =>
    unfold handleRequestVoteRequest
    apply Keeps.seq'
    intro _
    split <;> exact Keeps.pure' (keep_fields old rfl rfl rfl)
  | requestPreVoteRequest => exact Keeps.seq' fun _ => Keeps.pure' old
  | proposeRequestVoteRequest => exact Keeps.ite' (fun _ => campaign _ _) fun _ => Keeps.pure' old
  | requestPreVoteResponse =>
    unfold handleRequestPreVoteResponse
    exact Keeps.ite' (fun _ => Keeps.ite' (fun _ => campaign _ _)
      fun _ => Keeps.pure' (keep_fields old rfl rfl rfl)) fun _ => Keeps.pure' old
  | requestVoteResponse =>
    unfold handleRequestVoteResponse
    refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' old
    refine result (electIfQuorum_sends self _) ?_
    rintro _ _ (⟨rfl, _⟩ | ⟨_, _, adv, _⟩)
    · exact keep_fields old rfl rfl rfl
    · exact advance (active (by simp [primaryState])) adv
  | appendEntriesResponse =>
    unfold handleAppendEntriesResponse
    refine Keeps.ite' (fun _ => Keeps.pure' old) fun _ => ?_
    refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (keep_fields old rfl rfl rfl)
    refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' old
    refine result (advanceCommit_sends self _) ?_
    intro _ _ h
    refine advance ?_ h.1
    exact keep_fields old rfl rfl rfl
  | appendEntriesRequest req =>
    let z := observeTerm p (.appendEntriesRequest req)
    have le : req.term ≤ z.currentTerm := by
      rcases observe_bumping p (message := .appendEntriesRequest req) trivial with ⟨_, eq⟩ | ⟨le, eq⟩
      · simp only [z, eq]; exact Nat.le_refl _
      · rw [show z = p from eq]; exact le
    by_cases eq : req.term = z.currentTerm
    · exact result (aeReply self src z req le) fun _ _ reply _ =>
        .inr (.inr ⟨src, req, rfl, eq.trans reply.1.symm⟩)
    · have lt := Nat.lt_of_le_of_ne le eq
      change Keeps _ (handleAppendEntriesRequest _ self src z req)
      simp [handleAppendEntriesRequest, eq, lt]
      exact Keeps.seq' fun _ => Keeps.pure' old

private theorem step [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t) :
    Origin c.pre c.event c.post := by
  have proof (p : NodeState) (e : Event) : Keeps (Origin p e)
      (Node.step (Capabilities.record c.actor) c.actor p e) := by
    cases e with
    | internal i => exact local_step _ _ i
    | receive src msg => exact receive_step _ src _ msg
  exact proof _ _ {} _ _ c.tr.ran

end ConsensusCoverage.RetiredRoleOrigin
