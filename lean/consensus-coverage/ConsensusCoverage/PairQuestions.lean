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

end ConsensusCoverage.PairQuestions
