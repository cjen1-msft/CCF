module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.FullProfile
public import ConsensusCoverage.PairQuestions
import all ConsensusCoverage.Classes
import all ConsensusCoverage.FullProfile
import all ConsensusCoverage.PairQuestions
import all Consensus.Proofs.SafetyInvariant

/-! Exact snapshot readers for the `leader_led` step branches. -/

namespace ConsensusCoverage.LeaderEffect

open CCF Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

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
public def changedPrimary (s t : Model.State) : Bool :=
  let peers := probes s t
  t.nodes.any fun (node, post) =>
    post.role == .primary && !(s.nodes.any fun (old, pre) => old == node && sameNode peers pre post)

/-- The changed primary was already primary in this term. -/
public def changedIncumbent (s t : Model.State) : Bool :=
  changedPrimary s t && !PairQuestions.answer s t .wonPrimary

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
      · rcases (@Summary.matchIndex _ _ _ _ _ c.sum primary prePrimary term.symm peer) with
          eq | ⟨msg, event, _⟩
        · exact eq.symm
        · exact (visible (receive_visible event)).elim
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
  · have eq := state_unique c.inv.distinct old prev
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

private theorem changedPrimary_ctx_iff [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (valid : Nonempty (Ctx f t)) :
    changedPrimary f.current t = true ↔ Classes.step_leader_led_now_after_inl f t := by
  obtain ⟨c⟩ := valid
  rw [changedPrimary_mem c]
  constructor
  · rintro ⟨n, post, now, primary, fresh⟩
    rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, old⟩
    · exact ⟨c, c.actor, c.post, ⟨c, _, _, now, primary, fun h => fresh h.1, rfl, rfl, rfl⟩,
        ⟨rfl, rfl⟩, rfl, rfl, now, primary⟩
    · exact (fresh old).elim
  · rintro ⟨_, _, _, ⟨_, n, post, now, primary, fresh, _⟩, _⟩
    exact ⟨n, post, now, primary, fun old => fresh ⟨old, primary⟩⟩

private theorem changedIncumbent_ctx_iff [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (valid : Nonempty (Ctx f t)) :
    changedIncumbent f.current t = true ↔ Classes.step_leader_led_leader_inl f t := by
  obtain ⟨c⟩ := valid
  change (changedPrimary f.current t && !PairQuestions.newPrimary f.current t) = true ↔ _
  rw [and_true, Bool.not_eq_true', Bool.eq_false_iff, changedPrimary_mem c]
  constructor
  · rintro ⟨⟨n, post, now, primary, fresh⟩, notWon⟩
    rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, old⟩
    · rcases Summary.leader c.sum primary with ⟨preRole, term⟩ | wins
      · exact ⟨c, c.actor, c.post, ⟨c, _, _, now, primary, fun h => fresh h.1, rfl, rfl, rfl⟩,
          ⟨rfl, rfl⟩, rfl, rfl, now, primary, now, ⟨preRole, term⟩, preRole, term, now, primary⟩
      · exact (notWon ((PairQuestions.won_iff rfl ⟨c⟩).mp
          ⟨c, c.actor, c.post, ⟨c, _, _, now, primary, fun h => fresh h.1, rfl, rfl, rfl⟩,
            ⟨rfl, rfl⟩, rfl, rfl, now, primary, now, wins, now, primary⟩)).elim
    · exact (fresh old).elim
  · rintro ⟨actual, n, post, reach, _, rfl, rfl, now, primary, _, ⟨preRole, term⟩, _⟩
    refine ⟨(changedPrimary_mem c).mp ((changedPrimary_ctx_iff ⟨c⟩).mpr
      ⟨actual, actual.actor, actual.post, reach, ⟨rfl, rfl⟩, rfl, rfl, now, primary⟩), ?_⟩
    intro won
    obtain ⟨node, state, mem, role, fresh⟩ := (PairQuestions.newPrimary_iff _ _).mp won
    rcases actual.now_after mem with ⟨rfl, rfl⟩ | ⟨_, old⟩
    · exact fresh ⟨actual.pre, actual.pre_now, preRole, term.symm⟩
    · exact fresh ⟨state, old, role, rfl⟩

private theorem folded_context {cfg ns f t action} (run : FullProfile.Folded cfg ns f)
    (step : (transitionSystem cfg ns).step (FullProfile.current f) action = some t) :
    letI : Config.InitialConfiguration := ⟨cfg⟩
    Nonempty (Ctx f t) := by
  letI : Config.InitialConfiguration := ⟨cfg⟩
  obtain ⟨tr⟩ := LocalTransition.ofStep step
  exact ⟨⟨tr, run.invariant⟩⟩

/-- Exact on every initialized run. The action and history certify the domain of
the theorem but are not inputs to the Boolean reader. -/
public theorem changedPrimary_iff {cfg ns f t action} (run : FullProfile.Folded cfg ns f)
    (step : (transitionSystem cfg ns).step (FullProfile.current f) action = some t) :
    changedPrimary (FullProfile.current f) t = true ↔
      FullProfile.questionHolds cfg f t (.step .leader_led_now_after_inl) := by
  letI : Config.InitialConfiguration := ⟨cfg⟩
  exact changedPrimary_ctx_iff (folded_context run step)

/-- Same-term primary changes are exactly the generated incumbent branch. -/
public theorem changedIncumbent_iff {cfg ns f t action} (run : FullProfile.Folded cfg ns f)
    (step : (transitionSystem cfg ns).step (FullProfile.current f) action = some t) :
    changedIncumbent (FullProfile.current f) t = true ↔
      FullProfile.questionHolds cfg f t (.step .leader_led_leader_inl) := by
  letI : Config.InitialConfiguration := ⟨cfg⟩
  exact changedIncumbent_ctx_iff (folded_context run step)

/-- Every newly primary node is a changed primary; only incumbent changes
can add a distinction to the election bit in `PairQuestions`. -/
public theorem wonPrimary_implies_changedPrimary {cfg ns f t action} (run : FullProfile.Folded cfg ns f)
    (step : (transitionSystem cfg ns).step (FullProfile.current f) action = some t)
    (won : PairQuestions.answer (FullProfile.current f) t .wonPrimary = true) :
    changedPrimary (FullProfile.current f) t = true := by
  letI : Config.InitialConfiguration := ⟨cfg⟩
  obtain ⟨c⟩ := folded_context run step
  obtain ⟨node, post, now, primary, fresh⟩ := (PairQuestions.newPrimary_iff _ _).mp won
  exact (changedPrimary_mem c).mpr ⟨node, post, now, primary, fun old => fresh ⟨post, old, primary, rfl⟩⟩

/-- The `leader_led` actor branch also supplies the fresh actor state needed by
the ordinary (non-send) `commit_backed` actor branch. This says nothing by itself
about whether an actual commit certificate exists. -/
public theorem changedPrimary_implies_commitBacked {cfg ns f t action} (run : FullProfile.Folded cfg ns f)
    (step : (transitionSystem cfg ns).step (FullProfile.current f) action = some t)
    (changed : changedPrimary (FullProfile.current f) t = true) :
    FullProfile.questionHolds cfg f t (.step .commit_backed_now_after_inl) := by
  letI : Config.InitialConfiguration := ⟨cfg⟩
  obtain ⟨c⟩ := folded_context run step
  obtain ⟨n, post, now, _, fresh⟩ := (changedPrimary_mem c).mp changed
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, prev⟩
  · exact .inl ⟨c, c.actor, c.post, ⟨c, _, _, now, fresh, rfl, rfl, rfl⟩,
      ⟨rfl, rfl⟩, rfl, rfl, now⟩
  · exact (fresh prev).elim

end ConsensusCoverage.LeaderEffect
