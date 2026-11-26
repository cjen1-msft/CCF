module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.LeaderEffect
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.ReadersIndex

open CCF Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open ConsensusCoverage.ReadersAtoms ConsensusCoverage.GuardedDomain

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

theorem append_matchIndex (self : NodeID) (state : NodeState) (contents : List AppendEntryInput) :
    Sends (fun after _ => after.matchIndex = state.matchIndex)
      (act (Capabilities.record self) self state (.append contents)) := by
  simp only [act, appendBatch]
  refine Sends.bind' Sends.guard' fun _ _ ⟨_, empty⟩ => ?_
  subst empty
  have start : BatchState self state state [] :=
    ⟨⟨[], state.sentIndex, by simp, by simp⟩, by simp⟩
  refine Sends.bind' (Sends.mono (Sends.foldlM' (I := BatchState self state)
      (fun value sent item batch =>
        Sends.bind' (appendEntry_batch self state value sent item.content batch)
          fun appended later kept =>
            (Sends.foldlM'
              (fun value sent (destination, endIndex) batch =>
                sendEntries_batch self state value sent destination endIndex batch)
              item.flushes appended (sent ++ later) kept).mono
              fun _ _ done => by simpa [List.append_assoc] using done)
      contents state [] start) fun _ _ done => by simpa using done)
    fun appended _ batch => ?_
  refine (advanceCommit_sends self appended).mono fun _ _ ⟨advance, _⟩ => ?_
  obtain ⟨_, _, eq, _⟩ := batch.1
  simpa only [eq] using advance.matchIndex

theorem observe_match (pre : NodeState) (msg : Message) :
    (observeTerm pre msg).matchIndex = pre.matchIndex := by
  have update (term : Nat) : (updateTerm pre term).matchIndex = pre.matchIndex := by
    by_cases bump : pre.currentTerm < term <;> simp [updateTerm, becomeAwareOfNewTerm, bump]
  cases msg <;> simp only [observeTerm]
  all_goals first | exact update _ | solve | split <;> first | exact update _ | rfl

theorem receive_primary_match (self source : NodeID) (pre : NodeState) (msg : Message)
    (primary : pre.role = .primary) (peer : NodeID) (other : peer ≠ source) :
    Sends (fun post _ => post.matchIndex peer = pre.matchIndex peer)
      (receive (Capabilities.record self) self source pre msg) := by
  have progress := (LeaderEffect.observe_progress pre msg).2
  have same := congrFun (observe_match pre msg) peer
  have notRole {role : Role} (notPrimary : role ≠ .primary) (notFollower : role ≠ .follower) :
      (observeTerm pre msg).role ≠ role := by
    rcases progress with eq | eq
    · simp [eq, primary, Ne.symm notPrimary]
    · simp [eq, Ne.symm notFollower]
  cases msg <;> simp only [receive]
  all_goals try refine Sends.ite' (fun _ => Sends.pure' rfl) (fun _ => ?_)
  · rename_i request stopped
    have le : request.term ≤ (observeTerm pre (.appendEntriesRequest request)).currentTerm := by
      rcases observe_bumping pre (message := .appendEntriesRequest request) (by trivial) with
        ⟨_, eq⟩ | ⟨le, eq⟩
      · rw [eq]
        exact Nat.le_refl _
      · rw [eq]
        exact le
    exact (aeReply self source _ request le).mono fun _ _ result =>
      (congrFun result.2.2.1 peer).trans same
  · unfold handleAppendEntriesResponse
    refine Sends.ite' (fun _ => Sends.pure' same) fun _ => ?_
    refine Sends.ite' (fun _ => ?_) fun _ => Sends.pure' same
    refine Sends.ite' (fun _ => ?_) (fun _ => Sends.pure' same)
    refine (advanceCommit_sends self _).mono fun _ _ h => ?_
    rw [h.1.matchIndex]
    change Function.update _ source _ peer = _
    rw [Function.update_of_ne other]
    exact same
  · unfold handleRequestVoteRequest
    refine Sends.bind' (Sends.send _ _ _) fun _ _ _ => ?_
    split <;> exact Sends.pure' same
  · unfold handleRequestVoteResponse
    exact Sends.ite' (fun h => (notRole (by decide) (by decide) h.1).elim)
      (fun _ => Sends.pure' same)
  · unfold handleRequestPreVoteRequest
    exact Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' same
  · unfold handleRequestPreVoteResponse
    exact Sends.ite' (fun h => (notRole (by decide) (by decide) h.1).elim)
      (fun _ => Sends.pure' same)
  · unfold handleProposeRequestVoteRequest
    exact Sends.ite' (fun h => by
      have roles := h.2.1
      simp [observeTerm, primary] at roles) (fun _ => Sends.pure' same)

theorem step_primary_match (self : NodeID) (pre : NodeState) (event : Event)
    (primary : pre.role = .primary) (peer : NodeID)
    (other : ∀ source msg, event = .receive source msg → peer ≠ source) :
    Sends (fun post _ => post.matchIndex peer = pre.matchIndex peer)
      (Model.Node.step (Capabilities.record self) self pre event) := by
  cases event with
  | receive source msg =>
    exact receive_primary_match self source pre msg primary peer (other _ _ rfl)
  | internal input =>
    simp only [Model.Node.step]
    cases input with
    | append contents =>
      exact (append_matchIndex self pre contents).mono fun _ _ eq => congrFun eq peer
    | sendEntries target endIndex =>
      unfold act sendEntries
      refine Sends.guard_bind fun _ => ?_
      exact Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' rfl
    | timeout kind =>
      cases kind
      · unfold act startElection
        refine Sends.guard_bind fun can => ?_
        have roles := can.1
        simp [primary] at roles
      · unfold act checkQuorum
        exact Sends.guard_bind fun _ => Sends.pure' rfl
    | nominateSuccessor =>
      exact (nominate_sends self pre).mono fun _ _ h => congrArg (fun st => st.matchIndex peer) h.1
    | initAsBackup entries =>
      unfold act initAsBackup
      refine Sends.guard_bind fun fresh => ?_
      have role := fresh.1.1
      simp [primary] at role

public def sameMatch (x : XView) : Bool :=
  match x.event with
  | .receive source _ => x.base.post.matchIndex source == x.base.pre.matchIndex source
  | .internal _ => true

theorem sameMatch_iff [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    {x : XView} {c : Ctx f t} (ok : x.Matches c)
    (primary : x.base.pre.role = .primary) :
    sameMatch x = true ↔ x.base.post.matchIndex = x.base.pre.matchIndex := by
  constructor
  · intro yes
    funext peer
    by_cases received : ∃ msg, x.event = .receive peer msg
    · obtain ⟨msg, eq⟩ := received
      simpa [sameMatch, eq] using yes
    · have other : ∀ n msg, x.event = .receive n msg → peer ≠ n := by
        rintro n msg eq rfl
        exact received ⟨msg, eq⟩
      obtain ⟨_, _, same⟩ := step_primary_match x.base.actor x.base.pre x.event primary peer other
        _ _ _ (X.run_eq ok)
      exact same
  · intro eq
    simp [sameMatch, eq]
    split <;> simp

def configurationSupport (content : EntryContent) : List NodeID :=
  content.metadata.configuration.toList.flatMap Finset.val

def appendSupport (contents : List AppendEntryInput) : List NodeID :=
  contents.flatMap fun item => configurationSupport item.content ++ item.flushes.map Prod.fst

theorem appendEntryOutside (self peer : NodeID) (state : NodeState) (content : EntryContent)
    (outside : peer ∉ configurationSupport content) :
    Sends (fun after _ => after.sentIndex peer = state.sentIndex peer)
      (appendEntry (Capabilities.record self) self state content) := by
  unfold appendEntry
  simp only [pure_bind]
  repeat' first
    | refine Sends.ite' (fun _ => ?_) fun _ => ?_
    | refine Sends.guard_bind fun _ => ?_
  all_goals
    split
    · exact Sends.pure' rfl
    · rename_i nodes eq
      have notNode : peer ∉ nodes := by
        change peer ∉ nodes.val
        simpa [configurationSupport, eq] using outside
      refine Sends.guard_bind fun _ => ?_
      refine Sends.bind' (Sends.forIn' (R := fun _ => True) fun _ _ _ =>
        Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' (by simp)) fun _ _ _ => Sends.pure' ?_
      dsimp only
      rw [ite_eq_right]
      intro added
      exact notNode (Finset.mem_sdiff.mp (Finset.mem_erase.mp added).2).1

theorem sendEntryOutside (self peer destination : NodeID) (limit : Nat) (state : NodeState)
    (outside : peer ≠ destination) :
    Sends (fun after _ => after.sentIndex peer = state.sentIndex peer)
      (sendEntries (Capabilities.record self) self state destination limit) := by
  unfold sendEntries
  refine Sends.guard_bind fun _ => ?_
  refine Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' ?_
  exact Function.update_of_ne outside _ _

theorem flushesOutside (self peer : NodeID) (flushes : List (NodeID × Nat))
    (outside : peer ∉ flushes.map Prod.fst) (state : NodeState) :
    Sends (fun after _ => after.sentIndex peer = state.sentIndex peer)
      (flushes.foldlM (fun st (destination, limit) =>
        sendEntries (Capabilities.record self) self st destination limit) state) := by
  induction flushes generalizing state with
  | nil => exact Sends.pure' rfl
  | cons f rest ih =>
    simp only [List.map_cons, List.mem_cons, not_or] at outside
    simp only [List.foldlM_cons]
    refine Sends.bind' (sendEntryOutside self peer f.1 f.2 state outside.1) fun mid _ same => ?_
    exact (ih outside.2 mid).mono fun _ _ eq => eq.trans same

theorem appendBatchOutside (self peer : NodeID) (state : NodeState) (contents : List AppendEntryInput)
    (outside : peer ∉ appendSupport contents) :
    Sends (fun after _ => after.sentIndex peer = state.sentIndex peer)
      (appendBatch (Capabilities.record self) self state contents) := by
  have batch (entries : List AppendEntryInput) (pre : NodeState) (no : peer ∉ appendSupport entries) :
      Sends (fun after _ => after.sentIndex peer = pre.sentIndex peer)
        (entries.foldlM (fun cur item => do
          let next ← appendEntry (Capabilities.record self) self cur item.content
          item.flushes.foldlM (fun st (destination, limit) =>
            sendEntries (Capabilities.record self) self st destination limit) next) pre) := by
    induction entries generalizing pre with
    | nil => exact Sends.pure' rfl
    | cons e rest ih =>
      simp only [appendSupport, List.flatMap_cons, List.mem_append, not_or] at no
      simp only [List.foldlM_cons]
      refine Sends.bind' (Q := fun mid _ => mid.sentIndex peer = pre.sentIndex peer)
        (Sends.bind' (appendEntryOutside self peer pre e.content no.1.1)
          fun next _ a => (flushesOutside self peer e.flushes no.1.2 next).mono
            fun _ _ b => b.trans a)
        fun mid _ same => ?_
      exact (ih mid no.2).mono fun _ _ eq => eq.trans same
  unfold appendBatch
  refine Sends.guard_bind fun _ => ?_
  refine Sends.bind' (batch contents state outside) fun mid _ same => ?_
  exact (advanceCommit_sends self mid).mono fun _ _ a =>
    (congrFun a.1.sentIndex peer).trans same

def eventSentSupport : Event → List NodeID
  | .receive source _ => [source]
  | .internal (.append contents) => appendSupport contents
  | .internal (.sendEntries to _) => [to]
  | .internal _ => []

theorem stepSentOutside (self peer : NodeID) (pre : NodeState) (event : Event)
    (primary : pre.role = .primary) (outside : peer ∉ eventSentSupport event) :
    Sends (fun post _ => post.sentIndex peer = pre.sentIndex peer)
      (Model.Node.step (Capabilities.record self) self pre event) := by
  cases event with
  | receive source msg =>
    exact LeaderEffect.receive_sentIndex self source pre msg primary peer (by simpa [eventSentSupport] using outside)
  | internal input =>
    cases input with
    | append contents => exact appendBatchOutside self peer pre contents outside
    | sendEntries destination limit =>
      exact sendEntryOutside self peer destination limit pre (by simpa [eventSentSupport] using outside)
    | timeout kind =>
      cases kind
      · unfold Model.Node.step act startElection
        refine Sends.guard_bind fun can => ?_
        have roles := can.1
        simp [primary] at roles
      · unfold Model.Node.step act checkQuorum
        exact Sends.guard_bind fun _ => Sends.pure' rfl
    | nominateSuccessor =>
      exact (nominate_sends self pre).mono fun _ _ h => congrArg (fun st => st.sentIndex peer) h.1
    | initAsBackup entries =>
      unfold Model.Node.step act initAsBackup
      refine Sends.guard_bind fun fresh => ?_
      have role := fresh.1.1
      simp [primary] at role

public def sameSent (x : XView) : Bool :=
  (eventSentSupport x.event).all fun n => x.base.post.sentIndex n == x.base.pre.sentIndex n

theorem sameSent_iff [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    {x : XView} {c : Ctx f t} (ok : x.Matches c) (primary : x.base.pre.role = .primary) :
    sameSent x = true ↔ x.base.post.sentIndex = x.base.pre.sentIndex := by
  rw [sameSent, List.all_eq_true]
  constructor
  · intro yes
    funext peer
    by_cases mem : peer ∈ eventSentSupport x.event
    · exact beq_iff_eq.mp (yes peer mem)
    obtain ⟨_, _, same⟩ := stepSentOutside x.base.actor peer x.base.pre x.event primary mem _ _ _ (X.run_eq ok)
    exact same
  · intro eq peer _
    simp [eq]

theorem eq_symm_cert {α : Sort u} {a b : α} {v : Bool} (read : v = true ↔ a = b) :
    v = true ↔ b = a := read.trans ⟨Eq.symm, Eq.symm⟩

def eventMatchSupport : Event → List NodeID
  | .receive source _ => [source]
  | .internal _ => []

def patchEq (support : List NodeID) (post pre : NodeID → Nat)
    (key : NodeID) (val : Nat) : Bool :=
  let patched := Function.update pre key val
  (key :: support).all fun n => post n == patched n

private theorem patchEq_iff {support : List NodeID} {pre post : NodeID → Nat}
    (off : ∀ n, n ∉ support → post n = pre n) (key : NodeID) (val : Nat) :
    patchEq support post pre key val = true ↔ post = Function.update pre key val := by
  rw [patchEq, List.all_eq_true]
  constructor
  · intro test
    funext peer
    by_cases mem : peer ∈ key :: support
    · exact beq_iff_eq.mp (test peer mem)
    · have ne : peer ≠ key := fun eq => mem (eq ▸ List.mem_cons_self)
      have no : peer ∉ support := fun h => mem (List.mem_cons_of_mem _ h)
      rw [Function.update_of_ne ne]
      exact off peer no
  · intro eq peer _
    rw [eq]
    exact beq_self_eq_true _

public def patchedMatch (x : XView) (key : NodeID) (val : Nat) : Bool :=
  patchEq (eventMatchSupport x.event) x.base.post.matchIndex x.base.pre.matchIndex key val

public def patchedSent (x : XView) (key : NodeID) (val : Nat) : Bool :=
  patchEq (eventSentSupport x.event) x.base.post.sentIndex x.base.pre.sentIndex key val

theorem patchedMatch_iff [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    {x : XView} {c : Ctx f t} (ok : x.Matches c) (primary : x.base.pre.role = .primary)
    (key : NodeID) (val : Nat) :
    patchedMatch x key val = true ↔
      x.base.post.matchIndex = Function.update x.base.pre.matchIndex key val := by
  apply patchEq_iff
  intro peer no
  have off (s : NodeID) (m : Message) (h : x.event = .receive s m) : peer ≠ s :=
    fun eq => no (by simp [h, eventMatchSupport, eq])
  obtain ⟨_, _, eq⟩ :=
    step_primary_match x.base.actor x.base.pre x.event primary peer off _ _ _ (X.run_eq ok)
  exact eq

theorem patchedSent_iff [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    {x : XView} {c : Ctx f t} (ok : x.Matches c) (primary : x.base.pre.role = .primary)
    (key : NodeID) (val : Nat) :
    patchedSent x key val = true ↔
      x.base.post.sentIndex = Function.update x.base.pre.sentIndex key val := by
  apply patchEq_iff
  intro peer off
  obtain ⟨_, _, eq⟩ :=
    stepSentOutside x.base.actor peer x.base.pre x.event primary off _ _ _ (X.run_eq ok)
  exact eq

theorem observe_sent (pre : NodeState) (msg : Message) :
    (observeTerm pre msg).sentIndex = pre.sentIndex := by
  have update (term : Nat) : (updateTerm pre term).sentIndex = pre.sentIndex := by
    by_cases bump : pre.currentTerm < term <;> simp [updateTerm, becomeAwareOfNewTerm, bump]
  cases msg <;> simp only [observeTerm]
  all_goals first | exact update _ | solve | split <;> first | exact update _ | rfl

end ConsensusCoverage.ReadersIndex
