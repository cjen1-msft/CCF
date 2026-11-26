module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.FullProfile
import all ConsensusCoverage.FullProfile
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.VoteRequestRoute

open CCF Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private def Routed (e : Model.Envelope) : Prop :=
  ∀ r, e.payload = .requestVoteRequest r → e.source ≠ e.target

private abbrev Safe {α} (m : NodeEffect α) := Sends (fun _ sent => ∀ e ∈ sent, Routed e) m

private theorem pure_safe {α} (x : α) : Safe (pure x) := Sends.pure' (by simp)

private theorem bind_safe {α β} {m : NodeEffect α} {k : α → NodeEffect β}
    (first : Safe m) (rest : ∀ x, Safe (k x)) : Safe (m >>= k) :=
  Sends.bind' first fun x _ old => (rest x).mono fun _ _ new e mem =>
    (List.mem_append.mp mem).elim (old e) (new e)

private theorem fold_safe {α β} {f : α → β → NodeEffect α}
    (each : ∀ a b, Safe (f a b)) (items : List β) (init : α) :
    Safe (items.foldlM f init) := by
  induction items generalizing init with
  | nil => exact pure_safe _
  | cons x xs ih => exact bind_safe (each init x) ih

private theorem send_safe {self target : NodeID} {msg : Message}
    (ok : Routed ⟨self, target, msg⟩) : Safe ((Capabilities.record self : Caps).send msg target) :=
  (Sends.send _ _ _).mono fun _ _ eq _ mem => (List.mem_singleton.mp (eq ▸ mem)).symm ▸ ok

private theorem beat_routed {self term commit log e} (beat : AEFrom self term commit log e) :
    Routed e := by
  obtain ⟨_, _, _, payload, _⟩ := beat
  intro r eq
  simp [payload] at eq

private theorem nominated_routed {term} {e : Model.Envelope}
    (payload : e.payload = .proposeRequestVoteRequest term) : Routed e := by
  intro r eq
  simp [payload] at eq

private theorem advance_safe (self : NodeID) (st : NodeState) :
    Safe (advanceCommit (Capabilities.record self) st self) :=
  (advanceCommit_sends self st).mono fun _ _ h e mem =>
    nominated_routed (h.2 e mem).2

private theorem quorum_safe (self : NodeID) (st : NodeState) :
    Safe (electIfQuorum (Capabilities.record self) self st) := by
  apply (electIfQuorum_sends self st).mono
  rintro _ sent (⟨_, rfl⟩ | ⟨_, _, _, started⟩) e mem
  · contradiction
  · rcases started e mem with nom | beat
    · exact nominated_routed nom.2
    · exact beat_routed beat

private theorem broadcast_safe (self : NodeID) (st : NodeState) (msg : Message) :
    Safe (broadcastToOthers (Capabilities.record self) self st msg) :=
  (broadcast_sends self st msg).mono fun _ _ h e mem _ _ =>
    fun eq => (h e mem).2.1 (eq.symm.trans (h e mem).1)

private theorem campaign_safe (self : NodeID) (st : NodeState) :
    Safe (becomeCandidate (Capabilities.record self) st self) := by
  unfold becomeCandidate
  exact bind_safe (quorum_safe _ _) fun _ => bind_safe (broadcast_safe _ _ _) fun _ => pure_safe _

private theorem batch_start (self : NodeID) (st : NodeState) : BatchState self st st [] :=
  ⟨⟨[], st.sentIndex, by simp, by simp⟩, by simp⟩

private theorem batch_safe {self st next sent} (batch : BatchState self st next sent) :
    ∀ e ∈ sent, Routed e := fun e m => beat_routed (batch.2 e m)

private theorem sendEntries_safe (self : NodeID) (st : NodeState) (peer endIndex) :
    Safe (sendEntries (Capabilities.record self) self st peer endIndex) :=
  (sendEntries_batch self st st [] peer endIndex (batch_start ..)).mono fun _ _ h => batch_safe h

private theorem append_safe (self : NodeID) (st : NodeState) (entries) :
    Safe (appendBatch (Capabilities.record self) self st entries) := by
  unfold appendBatch
  apply Sends.guard_bind
  intro _
  refine bind_safe (fold_safe (fun state entry => ?_) _ _) fun _ => advance_safe _ _
  refine bind_safe ((appendEntry_batch self state state [] entry.content (batch_start ..)).mono
    (fun _ _ h => batch_safe h)) fun _ => ?_
  exact fold_safe (fun state (peer, idx) => sendEntries_safe self state peer idx) _ _

private theorem step_safe (self : NodeID) (st : NodeState) (evt : Event) :
    Safe (Node.step (Capabilities.record self) self st evt) := by
  cases evt with
  | internal input =>
    cases input with
    | append => exact append_safe _ _ _
    | sendEntries => exact sendEntries_safe _ _ _ _
    | nominateSuccessor =>
      exact (nominate_sends self st).mono fun _ _ h e mem =>
        nominated_routed (h.2.2 e mem).2
    | initAsBackup => exact Sends.guard_bind fun _ => pure_safe _
    | timeout k =>
      cases k with
      | checkQuorum => exact Sends.guard_bind fun _ => pure_safe _
      | election =>
        apply Sends.guard_bind
        intro _
        unfold becomePreVoteCandidate
        exact Sends.ite' (fun _ => campaign_safe _ _) fun _ =>
          bind_safe (broadcast_safe _ _ _) fun _ => pure_safe _
  | receive source msg =>
    cases msg <;> simp only [Node.step, receive]
    case requestVoteResponse =>
      apply Sends.ite' (fun _ => pure_safe _)
      intro _
      unfold handleRequestVoteResponse
      exact Sends.ite' (fun _ => quorum_safe _ _) fun _ => pure_safe _
    case requestPreVoteResponse =>
      apply Sends.ite' (fun _ => pure_safe _)
      intro _
      unfold handleRequestPreVoteResponse
      exact Sends.ite' (fun _ => Sends.ite' (fun _ => campaign_safe _ _) fun _ => pure_safe _)
        fun _ => pure_safe _
    case appendEntriesResponse =>
      apply Sends.ite' (fun _ => pure_safe _)
      intro _
      unfold handleAppendEntriesResponse
      repeat' first | exact pure_safe _ | exact advance_safe _ _ | apply Sends.ite' <;> intro _
    case proposeRequestVoteRequest =>
      unfold handleProposeRequestVoteRequest
      apply Sends.ite' (fun _ => pure_safe _)
      intro _
      exact Sends.ite' (fun _ => campaign_safe _ _) fun _ => pure_safe _
    case requestVoteRequest =>
      unfold handleRequestVoteRequest
      exact bind_safe (send_safe (by intro _ eq; cases eq)) fun _ => pure_safe _
    case requestPreVoteRequest =>
      unfold handleRequestPreVoteRequest
      exact bind_safe (send_safe (by intro _ eq; cases eq)) fun _ => pure_safe _
    case appendEntriesRequest req =>
      have le : req.term ≤ (observeTerm st (.appendEntriesRequest req)).currentTerm := by
        rcases observe_bumping st (message := .appendEntriesRequest req) trivial with ⟨_, eq⟩ | ⟨le, eq⟩
        · rw [eq]; exact Nat.le_refl _
        · rw [eq]; exact le
      apply (aeReply self source _ req le).mono
      intro _ _ reply e mem r eq
      rcases reply.2.2.2.2.2 with ⟨_, _, nacks⟩ | ⟨_, _, _, _, _, out, sent, _, _, payload⟩
      · obtain ⟨_, _, payload, _⟩ := nacks e mem
        simp [payload] at eq
      · obtain rfl := List.mem_singleton.mp (sent ▸ mem)
        simp [payload] at eq

/-- A vote request in an initialized network always goes to another node. -/
public theorem folded {cfg nodes f} (run : FullProfile.Folded cfg nodes f)
    {e : Model.Envelope} (pending : e ∈ (FullProfile.current f).network) {r}
    (request : e.payload = .requestVoteRequest r) : e.source ≠ e.target := by
  letI : Config.InitialConfiguration := ⟨cfg⟩
  induction run with
  | @initial initial init =>
    change e ∈ initial.network at pending
    simp [init.2.2.2.1] at pending
  | step prior ran ih =>
    obtain ⟨tr⟩ := LocalTransition.ofStep ran
    rcases tr.mem_network pending with old | sent
    · exact ih old
    · obtain ⟨_, eq, routed⟩ := step_safe tr.actor tr.pre tr.event {} _ _ tr.ran
      apply routed e _ r request
      simpa [eq] using sent

end ConsensusCoverage.VoteRequestRoute
