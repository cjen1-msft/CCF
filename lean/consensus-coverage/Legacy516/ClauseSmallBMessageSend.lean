module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseSmallB
public import ConsensusCoverage.EventSupport
import all ConsensusCoverage.EventSupport
import all ConsensusCoverage.ReducedQuestions
import all ConsensusCoverage.ReadersAtoms
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.ClauseSmallB.MessageSend

open CCF CCF.MultiNodeTransitionSystem
open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open ActionProfile EventSupport

set_option maxHeartbeats 0
set_option maxRecDepth 8192
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private abbrev E := Model.Envelope
private def Only (ks : List Tag) (es : List E) : Prop :=
  ∀ e ∈ es, messageTag e.payload ∈ ks

private abbrev SendsOnly (ks : List Tag) {α : Type} (m : NodeEffect α) :=
  Sends (fun _ => Only ks) m

private theorem only_append {ks} {xs ys : List E} (x : Only ks xs) (y : Only ks ys) :
    Only ks (xs ++ ys) :=
  fun e h => (List.mem_append.mp h).elim (x e) (y e)

private theorem liftOnly {ks ls} {α : Type} {m : NodeEffect α} (h : SendsOnly ks m)
    (sub : ∀ k ∈ ks, k ∈ ls) : SendsOnly ls m :=
  Sends.mono h fun _ _ sent e mem => sub _ (sent e mem)

private theorem pureOnly (ks : List Tag) {α : Type} (x : α) :
    SendsOnly ks (pure x) := Sends.pure' (by simp [Only])

private theorem bindOnly {ks} {α β : Type} {m : NodeEffect α} {f : α → NodeEffect β}
    (h : SendsOnly ks m) (k : ∀ a, SendsOnly ks (f a)) : SendsOnly ks (m >>= f) :=
  Sends.bind' h fun a _ sent =>
    Sends.mono (k a) fun _ _ later => only_append sent later

private theorem guardOnly {ks} {c : Prop} [Decidable c] :
    SendsOnly ks (guard c : NodeEffect Unit) :=
  Sends.mono Sends.guard' fun _ _ h => by simp [h.2, Only]

private theorem sendOnly {ks} (self target : NodeID) (msg : Message)
    (h : messageTag msg ∈ ks) : SendsOnly ks ((Capabilities.record self).send msg target) :=
  Sends.mono (Sends.send self target msg) fun _ _ eq e mem => by
    simp only [eq, List.mem_singleton] at mem
    subst e
    exact h

private theorem foldOnly {ks} {α γ : Type} {f : α → γ → NodeEffect α}
    (h : ∀ a item, SendsOnly ks (f a item)) (xs : List γ) (a : α) :
    SendsOnly ks (xs.foldlM f a) := by
  have folded := Sends.foldlM' (I := fun (_ : α) => Only ks)
    (fun a sent item old => Sends.mono (h a item) fun _ _ new => only_append old new)
    xs a [] (by simp [Only])
  exact Sends.mono folded fun _ _ ht => by simpa using ht

private theorem advanceOnly (self : NodeID) (st : NodeState) :
    SendsOnly [.proposeRequestVoteRequest] (advanceCommit (Capabilities.record self) st self) :=
  Sends.mono (advanceCommit_sends self st) fun _ _ h e mem => by
    rw [(h.2 e mem).2]
    simp [messageTag]

private theorem leaderStartOnly {self term st e} (h : LeaderStart self term st e) :
    messageTag e.payload ∈ [Tag.appendEntriesRequest, .proposeRequestVoteRequest] := by
  obtain ⟨_, eq⟩ | ae := h
  · rw [eq]
    simp [messageTag]
  · obtain ⟨q, eq, _⟩ := ae.ok
    rw [eq]
    simp [messageTag]

private theorem electOnly (self : NodeID) (st : NodeState) :
    SendsOnly [.appendEntriesRequest, .proposeRequestVoteRequest]
      (electIfQuorum (Capabilities.record self) self st) :=
  Sends.mono (electIfQuorum_sends self st) fun _ _ h e mem => by
    obtain ⟨_, empty⟩ | ⟨_, _, _, outgoing⟩ := h
    · simp [empty] at mem
    · exact leaderStartOnly (outgoing e mem)

private theorem candidateOnly (self : NodeID) (st : NodeState) :
    SendsOnly [.appendEntriesRequest, .proposeRequestVoteRequest, .requestVoteRequest]
      (becomeCandidate (Capabilities.record self) st self) :=
  Sends.mono (becomeCandidate_sends self st) fun _ _ h e mem => by
    obtain ⟨_, outgoing⟩ | ⟨_, _, outgoing⟩ := h
    · rw [(outgoing e mem).2]; simp [messageTag]
    · obtain from_ | ⟨_, eq⟩ := outgoing e mem
      · have yes := leaderStartOnly from_
        simp only [List.mem_cons] at yes ⊢
        grind only
      · rw [eq]; simp [messageTag]

private theorem nominateOnly (self : NodeID) (st : NodeState) :
    SendsOnly [.proposeRequestVoteRequest] (nominateSuccessor (Capabilities.record self) st self) :=
  Sends.mono (nominate_sends self st) fun _ _ h e mem => by
    rw [(h.2.2 e mem).2]
    simp [messageTag]

private abbrev appendKinds : List Tag := [.appendEntriesRequest, .proposeRequestVoteRequest]

private theorem entriesOnly (self : NodeID) (st : NodeState) (dst stop : Nat) :
    SendsOnly [.appendEntriesRequest] (sendEntries (Capabilities.record self) self st dst stop) := by
  unfold sendEntries
  exact bindOnly guardOnly fun _ => bindOnly (sendOnly _ _ _ (by simp [messageTag])) fun _ => pureOnly _ _

private theorem appendOnly (self : NodeID) (st : NodeState) (items : List AppendEntryInput) :
    SendsOnly appendKinds (appendBatch (Capabilities.record self) self st items) := by
  unfold appendBatch
  refine bindOnly guardOnly fun _ => bindOnly (foldOnly ?_ _ _) fun a =>
    liftOnly (advanceOnly self a) (by decide)
  intro a item
  refine bindOnly ?_ fun b => foldOnly (fun s (peer, n) =>
    liftOnly (entriesOnly self s peer n) (by decide)) item.flushes b
  have start : BatchState self a a [] := ⟨⟨[], a.sentIndex, by simp, by simp⟩, by simp⟩
  apply Sends.mono (appendEntry_batch self a a [] item.content start)
  intro _ sent result e mem
  obtain ⟨_, beats⟩ := result
  obtain ⟨q, eq, _⟩ := beats e (by simpa using mem) |>.2.2
  rw [eq]
  simp [messageTag]

private theorem aeOnly (self src : NodeID) (st : NodeState) (q : AppendEntriesRequest) :
    SendsOnly [.appendEntriesResponse]
      (handleAppendEntriesRequest (Capabilities.record self) self src st q) := by
  unfold handleAppendEntriesRequest
  dsimp only
  generalize (if q.term = st.currentTerm ∧ (st.role = .candidate ∨ st.role = .preVoteCandidate)
    then becomeAwareOfNewTerm st q.term else st) = z
  refine Sends.ite' (fun _ => ?_) (fun _ => ?_)
  · split <;> exact bindOnly (sendOnly _ _ _ (by simp [messageTag])) fun _ => pureOnly _ _
  · exact Sends.ite' (fun _ => pureOnly _ _) fun _ =>
      bindOnly (sendOnly _ _ _ (by simp [messageTag])) fun _ => pureOnly _ _

private theorem ackOnly (self src : NodeID) (st : NodeState) (r : AppendEntriesResponse) :
    SendsOnly [.proposeRequestVoteRequest]
      (handleAppendEntriesResponse (Capabilities.record self) self st src r) := by
  unfold handleAppendEntriesResponse
  split
  · exact pureOnly _ _
  · split
    · split
      · exact advanceOnly _ _
      · exact pureOnly _ _
    · exact pureOnly _ _

private abbrev candidateKinds : List Tag :=
  [.appendEntriesRequest, .proposeRequestVoteRequest, .requestVoteRequest]

private abbrev timeoutKinds : List Tag :=
  [.appendEntriesRequest, .proposeRequestVoteRequest, .requestVoteRequest, .requestPreVoteRequest]

private theorem timeoutModes (self : NodeID) (st : NodeState) (k : TimeoutKind) :
    Sends (fun _ sent => Only candidateKinds sent ∨ Only [.requestPreVoteRequest] sent)
      (act (Capabilities.record self) self st (.timeout k)) := by
  cases k
  · unfold act startElection becomePreVoteCandidate
    refine Sends.guard_bind fun _ => Sends.ite' (fun _ => ?_) fun _ => ?_
    · exact Sends.mono (candidateOnly self _) fun _ _ sent => .inl sent
    · refine Sends.mono (bindOnly (Sends.mono (broadcast_sends self _ _) ?_)
          fun _ => pureOnly [.requestPreVoteRequest] _) (fun _ _ sent => .inr sent)
      intro _ _ sent e mem
      rw [(sent e mem).2.2]
      simp [messageTag]
  · unfold act checkQuorum
    exact Sends.guard_bind fun _ => Sends.pure' (.inl (by simp [Only]))

private theorem timeoutOnly (self : NodeID) (st : NodeState) (k : TimeoutKind) :
    SendsOnly timeoutKinds (act (Capabilities.record self) self st (.timeout k)) := by
  apply Sends.mono (timeoutModes self st k)
  intro _ _ h e mem
  obtain campaign | prevote := h
  · exact (by decide : ∀ tag ∈ candidateKinds, tag ∈ timeoutKinds)
      (messageTag e.payload) (campaign e mem)
  · exact (by decide : ∀ tag ∈ ([.requestPreVoteRequest] : List Tag), tag ∈ timeoutKinds)
      (messageTag e.payload) (prevote e mem)

private theorem voteResponseOnly (self src : NodeID) (st : NodeState) (r : RequestVoteResponse) :
    SendsOnly appendKinds (handleRequestVoteResponse (Capabilities.record self) self st src r) := by
  unfold handleRequestVoteResponse
  exact Sends.ite' (fun _ => electOnly _ _) (fun _ => pureOnly _ _)

private theorem preVoteResponseOnly (self src : NodeID) (st : NodeState) (r : RequestVoteResponse) :
    SendsOnly candidateKinds (handleRequestPreVoteResponse (Capabilities.record self) self st src r) := by
  unfold handleRequestPreVoteResponse
  exact Sends.ite' (fun _ => Sends.ite' (fun _ => candidateOnly _ _) (fun _ => pureOnly _ _))
    (fun _ => pureOnly _ _)

/-- Conservative kind support, including sends from synchronous promotion and
    the non-bumping nomination emitted by a commit. -/
public def allowedOutput : Tag → List Tag
  | .append => appendKinds
  | .sendEntries => [.appendEntriesRequest]
  | .timeout => timeoutKinds
  | .nominateSuccessor => [.proposeRequestVoteRequest]
  | .initAsBackup => []
  | .appendEntriesRequest => [.appendEntriesResponse]
  | .appendEntriesResponse => [.proposeRequestVoteRequest]
  | .requestVoteRequest => [.requestVoteResponse]
  | .requestVoteResponse => appendKinds
  | .requestPreVoteRequest => [.requestPreVoteResponse]
  | .requestPreVoteResponse | .proposeRequestVoteRequest => candidateKinds

private theorem eventOnly (self : NodeID) (pre : NodeState) (ev : Event) :
    SendsOnly (allowedOutput (eventTag ev)) (Model.Node.step (Capabilities.record self) self pre ev) := by
  cases ev with
  | internal i =>
    cases i with
    | append entries => exact appendOnly self pre entries
    | sendEntries dst stop => exact entriesOnly self pre dst stop
    | timeout k => exact timeoutOnly self pre k
    | nominateSuccessor => exact nominateOnly self pre
    | initAsBackup entries =>
      change SendsOnly [] (initAsBackup pre entries)
      unfold initAsBackup
      exact bindOnly guardOnly fun _ => pureOnly _ _
  | receive src msg =>
    change SendsOnly (allowedOutput (messageTag msg)) (Model.Node.receive (Capabilities.record self) self src pre msg)
    unfold Model.Node.receive
    refine Sends.ite' (fun _ => pureOnly _ _) fun _ => ?_
    cases msg
    · exact aeOnly _ _ _ _
    · exact ackOnly _ _ _ _
    · unfold handleRequestVoteRequest
      exact bindOnly (sendOnly _ _ _ (by simp [messageTag, allowedOutput])) fun _ => pureOnly _ _
    · exact voteResponseOnly _ _ _ _
    · unfold handleRequestPreVoteRequest
      exact bindOnly (sendOnly _ _ _ (by simp [messageTag, allowedOutput])) fun _ => pureOnly _ _
    · exact preVoteResponseOnly _ _ _ _
    · unfold handleProposeRequestVoteRequest
      exact Sends.ite' (fun _ => candidateOnly _ _) (fun _ => pureOnly _ _)

private theorem context_only [Config.InitialConfiguration] {f t} (c : Ctx f t) :
    Only (allowedOutput (eventTag c.event)) c.sent := by
  obtain ⟨new, eq, ok⟩ := eventOnly c.actor c.pre c.event {} _ _ c.tr.ran
  simpa [show c.sent = c.tr.outputs.outgoing from rfl, eq] using ok

private theorem install_fresh (s : Step) (h : actionTag s.act = .initAsBackup) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    (Ctx.pre s.context).currentTerm = 0 := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have tag := actionTag_eq s.context
  rw [(s.context_eq s.context).mpr rfl, h] at tag
  let c := s.context
  change .initAsBackup = eventTag c.event at tag
  obtain ⟨entries, ev⟩ : ∃ entries, c.event = .internal (.initAsBackup entries) := by
    cases e : c.event with
    | internal i =>
      rw [e] at tag
      cases i <;> simp [eventTag, inputTag] at tag
      exact ⟨_, rfl⟩
    | receive src m =>
      rw [e] at tag
      cases m <;> simp [eventTag, messageTag] at tag
  have ran := c.tr.ran
  change ((Model.Node.step (Capabilities.record c.actor) c.actor c.pre c.event).run {}) = _ at ran
  rw [ev] at ran
  by_cases fresh : c.pre.isFresh
  · exact fresh.2.1
  · simp [Model.Node.step, act, initAsBackup, guard, fresh] at ran

public def payloadTag (msg : Message) : Tag := actionTag (.deliver ⟨0, 0, msg⟩)

private theorem from_payload (s : Step) (msg : Message)
    (mem : msg ∈ ReducedQuestions.freshPayloads s.before s.after.network) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    ∃ e ∈ s.context.sent, e.payload = msg := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have current : s.frame.current = s.before := s.current_eq
  obtain ⟨e, eq, rfl⟩ := List.mem_map.mp mem
  have ⟨after_, fresh⟩ := List.mem_filter.mp eq
  obtain old | out := s.context.tr.mem_network after_
  · rw [current] at old
    simp [old] at fresh
  · exact ⟨e, out, rfl⟩

public theorem timeout_mode (s : Step) (h : actionTag s.act = .timeout) :
    let fresh := ReducedQuestions.freshPayloads s.before s.after.network
    (∀ m ∈ fresh, payloadTag m ∈ [.appendEntriesRequest, .proposeRequestVoteRequest, .requestVoteRequest]) ∨
      (∀ m ∈ fresh, payloadTag m = .requestPreVoteRequest) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have tag := actionTag_eq c
  rw [(s.context_eq s.context).mpr rfl, h] at tag
  change .timeout = eventTag c.event at tag
  obtain ⟨k, ev⟩ : ∃ k, c.event = .internal (.timeout k) := by
    cases e : c.event with
    | internal i =>
      rw [e] at tag
      cases i <;> simp [eventTag, inputTag] at tag
      exact ⟨_, rfl⟩
    | receive src m =>
      rw [e] at tag
      cases m <;> simp [eventTag, messageTag] at tag
  have ran := c.tr.ran
  change ((Model.Node.step (Capabilities.record c.actor) c.actor c.pre c.event).run {}) = _ at ran
  rw [ev] at ran
  obtain ⟨new, eq, modes⟩ := timeoutModes c.actor c.pre k {} _ _ ran
  have actual : Only candidateKinds c.sent ∨ Only [.requestPreVoteRequest] c.sent := by
    simpa [show c.sent = c.tr.outputs.outgoing from rfl, eq] using modes
  rcases actual with left | right
  · left
    intro m mem
    obtain ⟨e, he, rfl⟩ := from_payload s m mem
    exact left e he
  · right
    intro m mem
    obtain ⟨e, he, rfl⟩ := from_payload s m mem
    exact List.mem_singleton.mp (right e he)

public theorem fresh_kind (s : Step) (msg : Message)
    (mem : msg ∈ ReducedQuestions.freshPayloads s.before s.after.network) :
    payloadTag msg ∈ allowedOutput (actionTag s.act) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have tag := actionTag_eq s.context
  rw [(s.context_eq s.context).mpr rfl] at tag
  rw [tag]
  obtain ⟨e, he, rfl⟩ := from_payload s msg mem
  exact context_only s.context e he

end ConsensusCoverage.ClauseSmallB.MessageSend
