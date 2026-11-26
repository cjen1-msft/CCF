module

meta import Relevance.Answer
public import ConsensusCoverage.Classes
import all ConsensusCoverage.Classes
import all Consensus.Proofs.SafetyInvariant

/-! Two questions from the stepwise proof that can be answered from snapshots alone.
The election reduction requires a valid frame transition; the executable label
does not take an action, actor, or ghost state. -/

namespace ConsensusCoverage.PairQuestions

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

private def zero (s : Model.State) : Bool :=
  s.nodes.any fun p => p.2.commitIndex == 0

private theorem zero_iff [Config.InitialConfiguration] (s : Model.State) (f : Frame)
    (current : f.current = s) :
    Classes.state_committed_logs_comparable_left_backed_inl f ↔ zero s = true := by
  subst s
  constructor
  · rintro ⟨node, st, now, _, _, h⟩
    exact List.any_eq_true.2 ⟨(node, st), now, beq_iff_eq.2 h⟩
  · intro h
    obtain ⟨⟨node,st⟩, now, test⟩ := List.any_eq_true.1 h
    have eq : st.commitIndex = 0 := beq_iff_eq.1 test
    exact ⟨node, st, now, 0, Or.inl eq, eq⟩

private def newPrimary (before after : Model.State) : Bool :=
  after.nodes.any fun (node,post) =>
    post.role == .primary && !(before.nodes.any fun (old,pre) =>
      old == node && pre.role == .primary && pre.currentTerm == post.currentTerm)

private theorem newPrimary_iff (before after : Model.State) :
    newPrimary before after = true ↔ ∃ node post, (node,post) ∈ after.nodes ∧
      post.role = .primary ∧
      ¬∃ pre, (node,pre) ∈ before.nodes ∧ pre.role = .primary ∧ pre.currentTerm = post.currentTerm := by
  simp only [newPrimary, List.any_eq_true, Prod.exists, Bool.and_eq_true, beq_iff_eq,
    Bool.not_eq_true', Bool.eq_false_iff]
  grind

private theorem won_iff [Config.InitialConfiguration]
    {f : Frame} {before after : Model.State} (current : f.current = before)
    (valid : Nonempty (Ctx f after)) :
    Classes.step_leader_led_leader_inr f after ↔ newPrimary before after = true := by
  subst before
  rw [newPrimary_iff]
  constructor
  · rintro ⟨c, n, s, _, ⟨rfl,rfl⟩, _, _, _, primary, _, wins, _, _⟩
    refine ⟨c.actor, c.post, c.post_now, primary, ?_⟩
    rintro ⟨pre, old, role, term⟩
    obtain rfl := c.now_pre old
    obtain ⟨_, _, _, termCase, _, _⟩ := c.electStep (c.wins_elect wins)
    rcases termCase with lt | ⟨_, cand⟩
    · omega
    · simp [role] at cand
  · rintro ⟨n, post, now, primary, notOld⟩
    obtain ⟨c⟩ := valid
    have fresh : ¬ Now f n post :=
      fun old => notOld ⟨post, old, primary, rfl⟩
    rcases c.now_after now with ⟨rfl,rfl⟩ | ⟨_,old⟩
    · rcases Summary.leader c.sum primary with ⟨preRole,term⟩ | wins
      · exact (notOld ⟨c.pre, c.pre_now, preRole, term.symm⟩).elim
      · exact ⟨c, c.actor, c.post,
          ⟨c, c.actor, c.post, now, primary, fun h => fresh h.1, rfl, rfl, rfl⟩,
          ⟨rfl,rfl⟩, rfl, rfl, now, primary, now, wins, now, primary⟩
    · exact (fresh old).elim

public inductive Question
  | zeroBefore | wonPrimary | zeroAfter
  deriving Repr, DecidableEq

private def specification [Config.InitialConfiguration]
    (f : Frame) (after : Model.State) : Question → Prop
  | .zeroBefore => Classes.state_committed_logs_comparable_left_backed_inl f
  | .wonPrimary => Classes.step_leader_led_leader_inr f after
  | .zeroAfter => Classes.state_committed_logs_comparable_left_backed_inl (f.advance after)

/-- In particular, proof contexts (and the configured node list) are not runtime inputs. -/
public def answer (before after : Model.State) : Question → Bool :=
  question_table% (fun (q : Question) [Config.InitialConfiguration]
      (f : Frame) (_ : f.current = before) (_ : Nonempty (Ctx f after)) =>
      specification f after q) by
    first | exact zero_iff before _ ‹_› | exact zero_iff after _ rfl | exact won_iff ‹_› ‹_›

public def label (before after : Model.State) : Bool × Bool × Bool :=
  let f := answer before after
  (f .zeroBefore, f .wonPrimary, f .zeroAfter)

theorem answer_iff [Config.InitialConfiguration] {f : Frame} {after : Model.State}
    (c : Ctx f after) (q : Question) :
    answer f.current after q = true ↔ specification f after q := by
  cases q with
  | zeroBefore => simpa [answer, specification] using (zero_iff _ f rfl).symm
  | zeroAfter => simpa [answer, specification] using (zero_iff after (f.advance after) rfl).symm
  | wonPrimary => simpa [answer, specification] using (won_iff rfl ⟨c⟩).symm

/-- Rows are ordered `(a node at commit zero before, new primary, a node at zero after)`. -/
public def table : List (Bool × Bool × Bool) :=
  [(true,false,true), (true,true,true), (true,false,false), (false,false,false), (false,true,false)]

private theorem win_preserves_commit [Config.InitialConfiguration]
    {f : Frame} {after : Model.State} (c : Ctx f after)
    (wins : Wins c.actor c.pre c.event c.post) : c.post.commitIndex = c.pre.commitIndex := by
  obtain ⟨cand, campaign, _, advance⟩ := wins
  have ⟨_, logEq, commitEq, _⟩ := campaign
  rcases advance with same | ⟨_, _, _, _, _, _, lt, eq, _⟩
  · rw [same]; exact commitEq
  · have ⟨three, cases'⟩ := c.campaign_three campaign
    have low (entry : Entry) (mem : entry ∈ (primaryState cand).log) : entry.term < cand.currentTerm := by
      have h := List.IsPrefix.mem mem (primaryState_log_prefix cand)
      rw [logEq] at h
      rcases cases' with lt | ⟨same, role⟩
      · exact Nat.lt_of_le_of_lt (c.inv.terms _ _ c.pre_now _ h) lt
      · rw [← same]
        exact (c.inv.candidate _ _ c.pre_now role).2.2.2.2 _ h
    rw [eq] at lt
    have term := (highestCommittableIndex_spec _ _ lt).2.2.1
    change termAt _ _ = cand.currentTerm at term
    have bound := termAt_le_of_mem (bound := cand.currentTerm - 1)
      (fun e h => Nat.le_sub_one_of_lt (low e h)) (highestCommittableIndex (primaryState cand) c.actor)
    omega

private theorem zero_mem (s : Model.State) :
    zero s = true ↔ ∃ n st, (n,st) ∈ s.nodes ∧ st.commitIndex = 0 := by
  simp [zero, List.any_eq_true, Prod.exists]

private theorem zero_old [Config.InitialConfiguration] {nodes : List NodeID}
    {f : Frame} {after : Model.State} {act : Model.Action} (c : Ctx f after)
    (stepped : (transitionSystem Config.INITIAL_CONFIGURATION nodes).step f.current act = some after)
    (h : zero after = true) : zero f.current = true := by
  obtain ⟨n, st, now, z⟩ := (zero_mem _).1 h
  apply (zero_mem _).2
  rcases c.now_after now with ⟨rfl,rfl⟩ | ⟨_,old⟩
  · refine ⟨c.actor, c.pre, c.pre_now, ?_⟩
    have frontier := c.frontier_pre
    have le := (Direct.committed_log_step c.inv.distinct stepped c.pre_now c.post_now).length_le
    simpa [NodeState.committedLog, z, List.length_take, Nat.min_eq_left frontier] using le
  · exact ⟨n, st, old, z⟩

private theorem zero_on_win [Config.InitialConfiguration]
    {f : Frame} {after : Model.State} (ctx : Nonempty (Ctx f after))
    (win : newPrimary f.current after = true) (h : zero f.current = true) : zero after = true := by
  obtain ⟨c, _, _, _, _, _, _, _, _, _, wins, _, _⟩ := (won_iff rfl ctx).2 win
  obtain ⟨n,st,old,z⟩ := (zero_mem _).1 h
  apply (zero_mem _).2
  by_cases same : n = c.actor
  · subst n
    exact ⟨_, _, c.post_now, (win_preserves_commit c wins).trans ((c.now_pre old) ▸ z)⟩
  · refine ⟨n, st, ?_, z⟩
    rw [c.tr.nodesEq]
    exact List.mem_map.2 ⟨_,old, by simp [same]⟩

theorem complete [Config.InitialConfiguration] {nodes : List NodeID} {before after : Model.State}
    {act : Model.Action} (reachable : (transitionSystem Config.INITIAL_CONFIGURATION nodes).Reachable before)
    (stepped : (transitionSystem Config.INITIAL_CONFIGURATION nodes).step before act = some after) :
    label before after ∈ table := by
  obtain ⟨f, rfl, inv⟩ := inv_of_reachable reachable
  obtain ⟨tr⟩ := LocalTransition.ofStep stepped
  let c : Ctx f after := ⟨tr, inv⟩
  have mono := zero_old c stepped
  have frame := zero_on_win ⟨c⟩
  change (zero f.current, newPrimary f.current after, zero after) ∈ table
  cases h₁ : zero f.current <;> cases h₂ : newPrimary f.current after <;> cases h₃ : zero after <;>
    simp_all [table]

end ConsensusCoverage.PairQuestions
