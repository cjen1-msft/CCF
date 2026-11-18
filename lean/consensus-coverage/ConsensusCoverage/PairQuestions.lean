module

meta import Relevance.Answer
public import ConsensusCoverage.Classes
import all ConsensusCoverage.Classes
import all Consensus.Proofs.SafetyInvariant

/-! A snapshot-only slice of the generated history proof. The precondition on the
election reduction is that the snapshots really are consecutive in an execution;
the executable label does not take an action, actor, or history. -/

namespace ConsensusCoverage.PairQuestions

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

private def zero (s : Model.State) : Bool :=
  s.nodes.any fun p => p.2.commitIndex == 0

private theorem zero_iff [Config.InitialConfiguration] (s : Model.State) (rest : History) :
    Classes.state_committed_logs_comparable_left_backed_inl (s :: rest) ↔ zero s = true := by
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

private theorem won_iff [Config.InitialConfiguration] {nodes : List NodeID}
    {after before : Model.State} {rest : History} (valid : Nonempty (Ctx nodes after before rest)) :
    Classes.step_leader_led_leader_inr nodes after before rest ↔ newPrimary before after = true := by
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
    have fresh : ¬ Now (before :: rest) n post :=
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

private def specification [Config.InitialConfiguration] (nodes : List NodeID)
    (before after : Model.State) (rest : History) : Question → Prop
  | .zeroBefore => Classes.state_committed_logs_comparable_left_backed_inl (before :: rest)
  | .wonPrimary => Classes.step_leader_led_leader_inr nodes after before rest
  | .zeroAfter => Classes.state_committed_logs_comparable_left_backed_inl (after :: before :: rest)

/-- In particular, proof contexts (and the configured node list) are not runtime inputs. -/
public def answer (before after : Model.State) : Question → Bool :=
  question_table% (fun (q : Question) [Config.InitialConfiguration] (nodes : List NodeID)
      (rest : History) (_ : Nonempty (Ctx nodes after before rest)) =>
      specification nodes before after rest q) by
    first | exact zero_iff _ _ | exact won_iff ‹_›

public def label (before after : Model.State) : Bool × Bool × Bool :=
  let f := answer before after
  (f .zeroBefore, f .wonPrimary, f .zeroAfter)

private theorem validCtx [Config.InitialConfiguration] {nodes : List NodeID}
    {after before : Model.State} {rest : History} (exec : Exec nodes (after :: before :: rest)) :
    Nonempty (Ctx nodes after before rest) := by
  cases exec with
  | step prior stepped =>
    obtain ⟨tr⟩ := LocalTransition.ofStep stepped
    exact ⟨⟨.step prior stepped, tr, good_of_exec prior⟩⟩

theorem answer_iff [Config.InitialConfiguration] {nodes : List NodeID} {before after : Model.State}
    {rest : History} (exec : Exec nodes (after :: before :: rest)) (q : Question) :
    answer before after q = true ↔ specification nodes before after rest q := by
  cases q with
  | zeroBefore => simpa [answer, specification] using (zero_iff before rest).symm
  | zeroAfter => simpa [answer, specification] using (zero_iff after (before :: rest)).symm
  | wonPrimary => simpa [answer, specification] using (won_iff (validCtx exec)).symm

/-- Rows are ordered `(a node at commit zero before, new primary, a node at zero after)`. -/
public def table : List (Bool × Bool × Bool) :=
  [(true,false,true), (true,true,true), (true,false,false), (false,false,false), (false,true,false)]

private theorem win_preserves_commit [Config.InitialConfiguration] {nodes : List NodeID}
    {after before : Model.State} {rest : History} (c : Ctx nodes after before rest)
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
    {after before : Model.State} {rest : History} (c : Ctx nodes after before rest)
    (h : zero after = true) : zero before = true := by
  obtain ⟨n, st, now, z⟩ := (zero_mem _).1 h
  apply (zero_mem _).2
  rcases c.now_after now with ⟨rfl,rfl⟩ | ⟨_,old⟩
  · refine ⟨c.actor, c.pre, c.pre_now, ?_⟩
    have pre := c.pre_now
    have post := c.post_now
    have frontier := c.frontier_pre
    have keys := c.prior.keys List.mem_cons_self
    cases c.exec with
    | step _ stepped =>
      have pref := Direct.committed_log_step keys stepped pre post
      have le := pref.length_le
      simp [NodeState.committedLog, z, List.length_take, Nat.min_eq_left frontier] at le
      exact le
  · exact ⟨n, st, old, z⟩

private theorem zero_on_win [Config.InitialConfiguration] {nodes : List NodeID}
    {after before : Model.State} {rest : History} (ctx : Nonempty (Ctx nodes after before rest))
    (win : newPrimary before after = true) (h : zero before = true) : zero after = true := by
  obtain ⟨c, _, _, _, _, _, _, _, _, _, wins, _, _⟩ := (won_iff ctx).2 win
  obtain ⟨n,st,old,z⟩ := (zero_mem _).1 h
  apply (zero_mem _).2
  by_cases same : n = c.actor
  · subst n
    exact ⟨_, _, c.post_now, (win_preserves_commit c wins).trans ((c.now_pre old) ▸ z)⟩
  · refine ⟨n, st, ?_, z⟩
    rw [c.tr.nodesEq]
    exact List.mem_map.2 ⟨_,old, by simp [same]⟩

theorem complete [Config.InitialConfiguration] {nodes : List NodeID} {before after : Model.State}
    {rest : History} (exec : Exec nodes (after :: before :: rest)) : label before after ∈ table := by
  have ⟨c⟩ := validCtx exec
  have mono := zero_old c
  have frame := zero_on_win ⟨c⟩
  change (zero before, newPrimary before after, zero after) ∈ table
  cases h₁ : zero before <;> cases h₂ : newPrimary before after <;> cases h₃ : zero after <;>
    simp_all [table]

end ConsensusCoverage.PairQuestions
