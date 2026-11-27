module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public meta import ConsensusCoverage.ReachPath
public import ConsensusCoverage.ActionProfile
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

/-!
Exact snapshot readers for `leader_led`'s changed primary and `led_cur`'s
election ending in a primary.
The shared `origin_cases` questions also cover calls that do not require a post-step primary, so these tests are not readers for those questions.
-/

namespace ConsensusCoverage.LeaderEffect

open CCF Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

set_option autoImplicit false
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private def ordinaryEq (a b : NodeState) : Bool :=
  a.role == b.role && a.currentTerm == b.currentTerm && a.log == b.log &&
    a.commitIndex == b.commitIndex && a.isNewFollower == b.isNewFollower &&
    a.votedFor == b.votedFor && a.primaryKnown == b.primaryKnown &&
    decide (a.votesGranted = b.votesGranted) && decide (a.preVotesGranted = b.preVotesGranted) &&
    a.retiredCommittedIndex == b.retiredCommittedIndex

private def probes (s t : Model.State) : List NodeID :=
  s.network.map (·.source) ++ t.network.map (·.target)

private def sameNode (peers : List NodeID) (a b : NodeState) : Bool :=
  ordinaryEq a b && peers.all fun peer =>
    a.sentIndex peer == b.sentIndex peer && a.matchIndex peer == b.matchIndex peer

private theorem and_true {a b : Bool} : (a && b) = true ↔ a = true ∧ b = true := by
  simp

/-- Some post-state primary has no identical node-state entry in the pre-state.
Network endpoints supply the finite probes for the function-valued progress fields. -/
@[expose] public def changedPrimary (s t : Model.State) : Bool :=
  let peers := probes s t
  t.nodes.any fun (node, post) =>
    post.role == .primary && !(s.nodes.any fun (old, pre) => old == node && sameNode peers pre post)

private theorem ordinaryEq_fields {a b : NodeState} (eq : ordinaryEq a b = true) :
    a.role = b.role ∧ a.currentTerm = b.currentTerm ∧ a.log = b.log ∧
    a.commitIndex = b.commitIndex ∧ a.isNewFollower = b.isNewFollower ∧
    a.votedFor = b.votedFor ∧ a.primaryKnown = b.primaryKnown ∧
    a.votesGranted = b.votesGranted ∧ a.preVotesGranted = b.preVotesGranted ∧
    a.retiredCommittedIndex = b.retiredCommittedIndex := by
  simp only [ordinaryEq, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at eq
  grind

private theorem eq_of_fields {a b : NodeState} (eq : ordinaryEq a b = true)
    (sent : a.sentIndex = b.sentIndex) (matched : a.matchIndex = b.matchIndex) :
    a = b := by
  obtain ⟨_, _, _, _, _, _, _, _, _, _⟩ := ordinaryEq_fields eq
  cases a; cases b
  congr

private theorem sameNode_refl (peers : List NodeID) (a : NodeState) :
    sameNode peers a a = true := by
  simp [sameNode, ordinaryEq]

private theorem fromLeader_sentIndex (self : NodeID) (st : NodeState)
    (request : AppendEntriesRequest) :
    (handleAppendEntiresFromPrimary self st request).1.sentIndex = st.sentIndex := by
  obtain ⟨_, _, _, eq, _⟩ := Ledger.handleAppendEntiresFromPrimary_eq self st request
  rw [eq]

private theorem aeRequest_sentIndex (self source : NodeID) (st : NodeState)
    (request : AppendEntriesRequest) :
    Sends (fun post _ => post.sentIndex = st.sentIndex)
      (handleAppendEntriesRequest (Capabilities.record self) self source st request) := by
  unfold handleAppendEntriesRequest
  dsimp only
  generalize hw : (if request.term = st.currentTerm
      ∧ (st.role = .candidate ∨ st.role = .preVoteCandidate) then
    becomeAwareOfNewTerm st request.term else st) = w
  have progress : w.sentIndex = st.sentIndex := by
    rw [← hw]
    split <;> rfl
  refine Sends.ite' (fun _ => ?_) (fun _ => ?_)
  · refine Sends.ite' (fun _ => ?_) (fun _ => ?_)
    all_goals exact Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' progress
  · refine Sends.ite' (fun _ => Sends.pure' progress) (fun _ => ?_)
    split
    all_goals
      refine Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' ?_
      rw [fromLeader_sentIndex]
      exact progress

private theorem appended_log_length (self : NodeID) (st : NodeState) (content : EntryContent) :
    Sends (fun post _ => post.log.length = st.log.length + 1)
      (appendEntry (Capabilities.record self) self st content) := by
  unfold appendEntry
  simp only [pure_bind]
  repeat' first
    | exact Sends.pure' (by simp)
    | refine Sends.ite' (fun _ => ?_) (fun _ => ?_)
    | refine Sends.guard_bind fun _ => ?_
  all_goals
    split
    · exact Sends.pure' (by simp)
    · refine Sends.guard_bind fun _ => ?_
      refine Sends.bind' (Sends.forIn' (R := fun _ => True) fun _ _ _ =>
        Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' (by simp)) fun _ _ _ =>
          Sends.pure' (by simp)

private theorem sendEntries_progress (self : NodeID) (st : NodeState) (target endIndex : Nat) :
    Sends (fun post sent => post.log = st.log ∧
      ∀ peer, post.sentIndex peer = st.sentIndex peer ∨ ∃ e ∈ sent, e.target = peer)
      (sendEntries (Capabilities.record self) self st target endIndex) := by
  unfold sendEntries
  refine Sends.guard_bind fun _ => ?_
  refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' ⟨rfl, ?_⟩
  intro peer
  by_cases same : peer = target
  · exact Or.inr ⟨⟨self, target, .appendEntriesRequest (makeAppendEntriesRequest st target endIndex)⟩,
      by simp [eq], same.symm⟩
  · exact Or.inl (Function.update_of_ne same _ _)

private theorem appendBatch_grows (self : NodeID) (st : NodeState) (entries : List AppendEntryInput) :
    Sends (fun post _ => st.log.length < post.log.length)
      (appendBatch (Capabilities.record self) self st entries) := by
  unfold appendBatch
  refine Sends.guard_bind fun ⟨_, _, nonempty⟩ => ?_
  have batch (es : List AppendEntryInput) (pre : NodeState) :
      Sends (fun post _ => post.log.length = pre.log.length + es.length)
        (es.foldlM (fun state item => do
          let state ← appendEntry (Capabilities.record self) self state item.content
          item.flushes.foldlM (fun state (target, endIndex) =>
            sendEntries (Capabilities.record self) self state target endIndex) state) pre) := by
    induction es generalizing pre with
    | nil => exact Sends.pure' (by simp)
    | cons item rest ih =>
      simp only [List.foldlM_cons]
      refine Sends.bind' (Q := fun post _ => post.log.length = pre.log.length + 1) ?_
        (fun flushed _ flushedLen => ?_)
      · refine Sends.bind' (appended_log_length self pre item.content) fun appended _ len => ?_
        refine (Sends.foldlM' (I := fun state _ => state.log.length = appended.log.length)
        (fun state _ item same =>
          (sendEntries_progress self state item.1 item.2).mono fun _ _ result =>
            (congrArg List.length result.1).trans same) item.flushes appended [] rfl).mono
          fun _ _ same => same.trans len
      · exact (ih flushed).mono fun _ _ result => by
          simp only [List.length_cons]
          omega
  refine Sends.bind' (batch entries st) fun next _ len => ?_
  refine (advanceCommit_sends self next).mono fun post _ result => ?_
  rw [result.1.log, len]
  exact Nat.lt_add_of_pos_right (List.length_pos_iff.mpr nonempty)

private theorem observe_progress (pre : NodeState) (msg : Message) :
    (observeTerm pre msg).sentIndex = pre.sentIndex ∧
      ((observeTerm pre msg).role = pre.role ∨ (observeTerm pre msg).role = .follower) := by
  have update (term : Nat) :
      (updateTerm pre term).sentIndex = pre.sentIndex ∧
        ((updateTerm pre term).role = pre.role ∨ (updateTerm pre term).role = .follower) := by
    by_cases bump : pre.currentTerm < term <;> simp [updateTerm, becomeAwareOfNewTerm, bump]
  cases msg <;> simp only [observeTerm]
  all_goals first
    | exact update _
    | solve | split <;> first | exact update _ | simp
    | simp

private theorem receive_sentIndex (self source : NodeID) (pre : NodeState) (msg : Message)
    (primary : pre.role = .primary) (peer : NodeID) (other : peer ≠ source) :
    Sends (fun post _ => post.sentIndex peer = pre.sentIndex peer)
      (receive (Capabilities.record self) self source pre msg) := by
  have progress := observe_progress pre msg
  have same := congrFun progress.1 peer
  have notRole {role : Role} (notPrimary : role ≠ .primary) (notFollower : role ≠ .follower) :
      (observeTerm pre msg).role ≠ role := by
    rcases progress.2 with eq | eq
    · simp [eq, primary, Ne.symm notPrimary]
    · simp [eq, Ne.symm notFollower]
  cases msg <;> simp only [receive]
  all_goals try
    refine Sends.ite' (fun _ => Sends.pure' rfl) (fun _ => ?_)
  · exact (aeRequest_sentIndex self source _ _).mono fun _ _ h => (congrFun h peer).trans same
  · unfold handleAppendEntriesResponse
    refine Sends.ite' (fun _ => Sends.pure' same) fun _ => ?_
    refine Sends.ite' (fun _ => ?_) fun _ => Sends.pure' (by
      change Function.update _ source _ peer = _
      rw [Function.update_of_ne other]
      exact same)
    refine Sends.ite' (fun _ => ?_) (fun _ => Sends.pure' same)
    exact (advanceCommit_sends self _).mono fun _ _ h => (congrFun h.1.sentIndex peer).trans same
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

/-- In a step starting at a primary, if the log is unchanged, a send-index change
names either a source of a received message or a target of an emitted message. -/
private theorem step_sentIndex (self : NodeID) (pre : NodeState) (event : Event)
    (primary : pre.role = .primary) (peer : NodeID)
    (other : ∀ source msg, event = .receive source msg → peer ≠ source) :
    Sends (fun post sent => post.log = pre.log →
      (∀ e ∈ sent, e.target ≠ peer) → post.sentIndex peer = pre.sentIndex peer)
      (Model.Node.step (Capabilities.record self) self pre event) := by
  cases event with
  | receive source msg =>
    exact (receive_sentIndex self source pre msg primary peer (other _ _ rfl)).mono
      fun _ _ eq _ _ => eq
  | internal input =>
    simp only [Model.Node.step]
    cases input with
    | append entries =>
      exact (appendBatch_grows self pre entries).mono fun _ _ grow log _ =>
        (Nat.lt_irrefl _ (log ▸ grow)).elim
    | sendEntries target endIndex =>
      exact (sendEntries_progress self pre target endIndex).mono fun _ _ result _ no =>
        (result.2 peer).elim id (fun ⟨e, mem, eq⟩ => (no e mem eq).elim)
    | timeout kind =>
      cases kind
      · unfold act startElection
        refine Sends.guard_bind fun can => ?_
        have roles := can.1
        simp [primary] at roles
      · unfold act checkQuorum
        exact Sends.guard_bind fun _ => Sends.pure' fun _ _ => rfl
    | nominateSuccessor =>
      exact (nominate_sends self pre).mono fun _ _ result _ _ => congrArg (fun st => st.sentIndex peer) result.1
    | initAsBackup entries =>
      unfold act initAsBackup
      refine Sends.guard_bind fun fresh => ?_
      have role := fresh.1.1
      simp [primary] at role

private theorem sameNode_actor_iff [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) (primary : c.post.role = .primary) :
    sameNode (probes f.current t) c.pre c.post = true ↔ c.pre = c.post := by
  constructor
  · intro test
    obtain ⟨fields, checked⟩ := and_true.mp test
    have ⟨role, term, log, _⟩ := ordinaryEq_fields fields
    have prePrimary := role.trans primary
    have receive_visible {source : NodeID} {msg : Message} (eq : c.event = .receive source msg) :
        source ∈ probes f.current t := by
      obtain ⟨e, mem, src, _, _⟩ := c.received eq
      exact List.mem_append_left _ (List.mem_map.mpr ⟨e, mem, src⟩)
    apply eq_of_fields fields <;> funext peer
    · by_cases visible : peer ∈ probes f.current t
      · exact beq_iff_eq.mp (and_true.mp (List.all_eq_true.mp checked peer visible)).1
      · have received (source : NodeID) (msg : Message) (eq : c.event = .receive source msg) :
          peer ≠ source := fun same => visible (same ▸ receive_visible eq)
        obtain ⟨sent, sentEq, progress⟩ :=
          step_sentIndex c.actor c.pre c.event prePrimary peer received _ _ _ c.tr.ran
        have sentEq : c.sent = sent := by simpa using sentEq
        refine (progress log.symm (fun e mem eq => visible (List.mem_append_right _ ?_))).symm
        have afterMem : e ∈ t.network := by
          rw [c.tr.networkEq]
          change e ∈ c.tr.pending ++ c.sent
          rw [sentEq]
          exact List.mem_append_right _ mem
        exact List.mem_map.mpr ⟨e, afterMem, eq⟩
    · by_cases visible : peer ∈ probes f.current t
      · exact beq_iff_eq.mp (and_true.mp (List.all_eq_true.mp checked peer visible)).2
      · rcases Summary.matchIndex c.sum primary prePrimary term.symm with
          same | ⟨source, _, event, _, _, updated⟩
        · exact (congrFun same peer).symm
        · have other : peer ≠ source := fun eq => visible (eq ▸ receive_visible event)
          rw [updated, Function.update_of_ne other]
  · rintro eq
    rw [eq]
    exact sameNode_refl _ _

private theorem sameNode_iff [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) {n : NodeID} {pre post : NodeState}
    (old : Now f n pre) (now : Now (f.advance t) n post) (primary : post.role = .primary) :
    sameNode (probes f.current t) pre post = true ↔ pre = post := by
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, prev⟩
  · rw [c.now_pre old]
    exact sameNode_actor_iff c primary
  · have eq := c.inv.unique n pre post old prev
    simp [eq, sameNode_refl]

private theorem changedPrimary_mem [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) :
    changedPrimary f.current t = true ↔
      ∃ node post, Now (f.advance t) node post ∧ post.role = .primary ∧ ¬ Now f node post := by
  constructor
  · intro test
    obtain ⟨⟨node, post⟩, now, both⟩ := List.any_eq_true.mp test
    obtain ⟨primary, fresh⟩ := and_true.mp both
    refine ⟨node, post, now, beq_iff_eq.mp primary, ?_⟩
    intro old
    have found : (f.current.nodes.any fun (old, pre) =>
        old == node && sameNode (probes f.current t) pre post) = true :=
      List.any_eq_true.mpr ⟨(node, post), old,
        and_true.mpr ⟨beq_self_eq_true _, sameNode_refl _ _⟩⟩
    exact Bool.noConfusion (found ▸ fresh)
  · rintro ⟨node, post, now, primary, fresh⟩
    refine List.any_eq_true.mpr ⟨(node, post), now, and_true.mpr ⟨beq_iff_eq.mpr primary, ?_⟩⟩
    rw [Bool.not_eq_true', Bool.eq_false_iff]
    intro test
    obtain ⟨⟨old, pre⟩, mem, bits⟩ := List.any_eq_true.mp test
    obtain ⟨idEq, fields⟩ := and_true.mp bits
    have same := beq_iff_eq.mp idEq
    subst old
    have eq := (sameNode_iff c mem now primary).mp fields
    exact fresh (eq ▸ mem)

private def incumbent (pre post : NodeState) : Prop :=
  pre.role = .primary ∧ post.currentTerm = pre.currentTerm

/-- Some post-state primary was not already primary in that term. -/
@[expose] public def wonPrimary (before after : Model.State) : Bool :=
  after.nodes.any fun (node, post) =>
    post.role == .primary && !(before.nodes.any fun (old, pre) =>
      old == node && pre.role == .primary && post.currentTerm == pre.currentTerm)

private theorem wonPrimary_mem (before after : Model.State) :
    wonPrimary before after = true ↔ ∃ node post, (node, post) ∈ after.nodes ∧
      post.role = .primary ∧
      ¬∃ pre, (node, pre) ∈ before.nodes ∧ incumbent pre post := by
  simp only [wonPrimary, incumbent, List.any_eq_true, Prod.exists, Bool.and_eq_true, beq_iff_eq,
    Bool.not_eq_true', Bool.eq_false_iff]
  grind

/-- The changed primary was already primary in this term. -/
@[expose] public def changedIncumbent (s t : Model.State) : Bool :=
  changedPrimary s t && !wonPrimary s t

private theorem changedPrimary_actor [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) :
    changedPrimary f.current t = true ↔ c.post.role = .primary ∧ ¬ Now f c.actor c.post := by
  rw [changedPrimary_mem c]
  constructor
  · rintro ⟨node, post, now, primary, fresh⟩
    rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, old⟩
    · exact ⟨primary, fresh⟩
    · exact (fresh old).elim
  · exact fun ⟨primary, fresh⟩ => ⟨c.actor, c.post, c.post_now, primary, fresh⟩

private theorem wonPrimary_actor [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) :
    wonPrimary f.current t = true ↔ c.post.role = .primary ∧ ¬ incumbent c.pre c.post := by
  rw [wonPrimary_mem]
  constructor
  · rintro ⟨node, post, now, primary, fresh⟩
    rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, old⟩
    · exact ⟨primary, fun h => fresh ⟨c.pre, c.pre_now, h⟩⟩
    · exact (fresh ⟨post, old, primary, rfl⟩).elim
  · rintro ⟨primary, fresh⟩
    refine ⟨c.actor, c.post, c.post_now, primary, ?_⟩
    rintro ⟨pre, old, h⟩
    exact fresh (c.now_pre old ▸ h)

private theorem wins_not_incumbent [Config.InitialConfiguration]
    {self : NodeID} {pre post : NodeState} {event : Event}
    (wins : Wins self pre event post) : ¬ incumbent pre post := by
  rintro ⟨role, term⟩
  obtain ⟨_, campaign, _, eq, _⟩ := wins.facts
  rcases campaign.2.2.2 with ⟨_, fresh, _⟩ | ⟨candidate, _⟩
  · omega
  · simp [role] at candidate

private theorem leaderReach_iff [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) :
    (reach% SolvedWitnesses.step_leader_led_now_after_inl[0]) f t c c c.actor c.post ↔
      changedPrimary f.current t = true := by
  rw [changedPrimary_actor c]
  reach_unfold SolvedWitnesses.step_leader_led_now_after_inl[0]
  have now := c.post_now
  grind

private theorem changedPrimary_solved [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) :
    changedPrimary f.current t = true ↔ SolvedWitnesses.step_leader_led_now_after_inl f t c := by
  constructor
  · intro changed
    exact ⟨(leaderReach_iff c).mpr changed, c.post_now, ((changedPrimary_actor c).mp changed).1⟩
  · exact fun h => (leaderReach_iff c).mp h.1

private theorem wonPrimary_wins [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) :
    wonPrimary f.current t = true ↔ c.post.role = .primary ∧ Wins c.actor c.pre c.event c.post := by
  rw [wonPrimary_actor c]
  constructor
  · rintro ⟨primary, fresh⟩
    exact ⟨primary, (Summary.leader c.sum primary).resolve_left fresh⟩
  · rintro ⟨primary, wins⟩
    exact ⟨primary, wins_not_incumbent wins⟩

private theorem wonPrimary_solved [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) :
    wonPrimary f.current t = true ↔ SolvedWitnesses.step_led_cur_role_inl f t c := by
  constructor
  · intro won
    obtain ⟨primary, fresh⟩ := (wonPrimary_actor c).mp won
    have elect := c.wins_elect ((wonPrimary_wins c).mp won).2
    have led : Led (f.advance t) c.actor c.post.currentTerm :=
      .inr ⟨_, _, .inr ⟨f.current, rfl, elect⟩⟩
    have path : (reach% SolvedWitnesses.step_led_cur_role_inl[0])
        f t c c c.actor c.post c.post.currentTerm := by
      reach_unfold SolvedWitnesses.step_led_cur_role_inl[0]
      refine ⟨c.post_now, led, fun old => ?_, rfl⟩
      have eq := c.now_pre old.1
      exact fresh ⟨eq ▸ primary, congrArg (·.currentTerm) eq⟩
    obtain ⟨_, _, _, campaign, _, role, keep, floor⟩ := c.electStep elect
    exact ⟨_, path, elect, ⟨campaign, role, keep, floor⟩, ⟨campaign, role, keep, floor⟩,
      ⟨campaign, role, keep, floor⟩, campaign, ⟨role, keep, floor⟩, ⟨role, keep, floor⟩,
      role, ⟨keep, floor⟩, c.post_now, led, elect, c.post_now, primary, c.post_now, led⟩
  · rintro ⟨_, _, elect, _, _, _, _, _, _, _, _, _, _, _, _, primary, _, _⟩
    apply (wonPrimary_actor c).mpr
    refine ⟨primary, fun ⟨role, term⟩ => ?_⟩
    obtain ⟨_, _, _, lt | ⟨_, candidate⟩, _⟩ := c.electStep elect
    · omega
    · simp [role] at candidate

private structure Reader where
  branch : Classes.StepBranch
  read : Model.State → Model.State → Bool
  correct : ∀ [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t),
    read f.current t = true ↔ PinnedClasses.sig c branch

private def readers : List Reader :=
  [⟨.leader_led_now_after_inl, changedPrimary, fun c =>
    (changedPrimary_solved c).trans (SolvedWitnesses.sig_iff c .leader_led_now_after_inl).symm⟩,
   ⟨.led_cur_role_inl, wonPrimary, fun c =>
    (wonPrimary_solved c).trans (SolvedWitnesses.sig_iff c .led_cur_role_inl).symm⟩]

@[expose] public def covered : List Classes.StepBranch := readers.map Reader.branch

public theorem covered_nodup : covered.Nodup := by decide

/-- Unsupported branches return `none`, not `some false`. -/
@[expose] public def read? (before after : Model.State) (b : Classes.StepBranch) : Option Bool :=
  (readers.find? fun r => decide (r.branch = b)).map (fun r => r.read before after)

public theorem read?_correct (s : ActionProfile.Step) (b : Classes.StepBranch) (value : Bool) :
    read? s.before s.after b = some value ↔
      b ∈ covered ∧ value = ActionProfile.label s (.step b) := by
  unfold read?
  cases h : readers.find? (fun r => decide (r.branch = b)) with
  | none =>
    have notCovered : b ∉ covered := by
      intro mem
      obtain ⟨r, mem, eq⟩ := List.mem_map.mp mem
      have no := List.find?_eq_none.mp h r mem
      simp [eq] at no
    simp [notCovered]
  | some r =>
    have eq : r.branch = b :=
      of_decide_eq_true (List.find?_some (p := fun r : Reader => decide (r.branch = b)) h)
    subst b
    have mem : r.branch ∈ covered := List.mem_map.mpr ⟨r, List.mem_of_find?_eq_some h, rfl⟩
    have exactRead := @Reader.correct r ⟨s.cfg⟩ s.frame s.after s.context
    have current : s.frame.current = s.before := s.current_eq
    rw [current] at exactRead
    change _ ↔ ActionProfile.holds s (.step r.branch) at exactRead
    have label : r.read s.before s.after = ActionProfile.label s (.step r.branch) :=
      Bool.eq_iff_iff.mpr (exactRead.trans (ActionProfile.label_true s (.step r.branch)).symm)
    simp only [Option.map_some, Option.some.injEq, label, mem, true_and, eq_comm]

/-- A total Boolean reader on the supported branch subtype. -/
@[expose] public def answer (before after : Model.State)
    (b : {b : Classes.StepBranch // b ∈ covered}) : Bool :=
  (read? before after b.val).getD false

public theorem answer_eq (s : ActionProfile.Step) (b : {b : Classes.StepBranch // b ∈ covered}) :
    answer s.before s.after b = ActionProfile.label s (.step b.val) := by
  have h := (read?_correct s b.val _).mpr ⟨b.property, rfl⟩
  simp [answer, h]

public theorem answer_iff (s : ActionProfile.Step) (b : {b : Classes.StepBranch // b ∈ covered}) :
    answer s.before s.after b = true ↔ ActionProfile.holds s (.step b.val) := by
  rw [answer_eq]
  exact ActionProfile.label_true s _

end ConsensusCoverage.LeaderEffect
