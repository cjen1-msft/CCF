module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.PairQuestions
public import ConsensusCoverage.StateCoverage
import all ConsensusCoverage.PairQuestions
import all ConsensusCoverage.StateCoverage
import all ConsensusCoverage.CommitMonitor
import all ConsensusCoverage.Classes
import all Consensus.Proofs.SafetyInvariant

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

namespace ConsensusCoverage.FrontierRows

@[expose] public section

structure Row where
  zeroBefore : Bool
  backedBefore : Bool
  wonPrimary : Bool
  zeroAfter : Bool
  backedAfter : Bool
  deriving Repr, DecidableEq

def Row.ofPair (pair : Bool × Bool × Bool) (backedBefore backedAfter : Bool) : Row :=
  ⟨pair.1, backedBefore, pair.2.1, pair.2.2, backedAfter⟩

def Row.pair (row : Row) : Bool × Bool × Bool :=
  (row.zeroBefore, row.wonPrimary, row.zeroAfter)

@[simp] theorem Row.pair_ofPair (p : Bool × Bool × Bool) (b a : Bool) :
    (Row.ofPair p b a).pair = p := rfl

/-- In bit order `(zero before, backed before, win, zero after, backed after)`,
the rows are `10010 10110 10011 10001 11011 11111 11001 01001 01101`. -/
def table : List Row :=
  [⟨true, false, false, true, false⟩, ⟨true, false, true, true, false⟩,
   ⟨true, false, false, true, true⟩, ⟨true, false, false, false, true⟩,
   ⟨true, true, false, true, true⟩, ⟨true, true, true, true, true⟩,
   ⟨true, true, false, false, true⟩,
   ⟨false, true, false, false, true⟩, ⟨false, true, true, false, true⟩]

theorem table_count : table.Nodup ∧ table.length = 9 := by decide

/-- The proof projection from an enabled step and its previous states, newest first.
The history excludes `s` and `t`, which are supplied separately. -/
def historyLabel (cfg : CCF.Finset NodeID) (s t : Model.State) (past : List Model.State) : Row :=
  Row.ofPair (PairQuestions.label s t) (StateCoverage.read cfg s past).2
    (StateCoverage.read cfg t (s :: past)).2

@[simp] theorem historyLabel_pair (cfg : CCF.Finset NodeID) (s t : Model.State)
    (past : List Model.State) : (historyLabel cfg s t past).pair = PairQuestions.label s t := rfl

def GhostOccurs (row : Row) : Prop :=
  ∃ (cfg : CCF.Finset NodeID) (nodes : List NodeID) (s t : Model.State)
    (past : List Model.State) (act : Model.Action), StateCoverage.Run cfg nodes s past ∧
      (transitionSystem cfg nodes).step s act = some t ∧ historyLabel cfg s t past = row

end

private theorem all_cases (z b w z' b' : Bool)
    (old : z = true ∨ b = true) (next : z' = true ∨ b' = true)
    (noNewZero : z' = true → z = true) (keepBacking : b = true → b' = true)
    (winZero : w = true → z = true → z' = true)
    (winBacking : w = true → b' = true → b = true) :
    (⟨z, b, w, z', b'⟩ : Row) ∈ table := by
  cases z <;> cases b <;> cases w <;> cases z' <;> cases b' <;> simp_all [table]

/-- The node list need not contain the configured primary, or indeed any nodes at all. -/
public theorem empty_initial {cfg : CCF.Finset NodeID} (hne : cfg.Nonempty) :
    (transitionSystem cfg []).init ({nodes := [], network := []} : Model.State) := by
  exact ⟨hne, rfl, by simp⟩

public theorem no_step_without_nodes {cfg : CCF.Finset NodeID} {nodes : List NodeID}
    {s t : Model.State} {act : Model.Action} (step : (transitionSystem cfg nodes).step s act = some t) :
    s.nodes ≠ [] := by
  letI : Config.InitialConfiguration := ⟨cfg⟩
  obtain ⟨tr⟩ := LocalTransition.ofStep step
  have mem := tr.pre_mem
  intro empty
  simp [empty] at mem

public theorem no_step_empty_node_list {cfg : CCF.Finset NodeID} {s t : Model.State}
    {act : Model.Action} (reach : (transitionSystem cfg []).Reachable s) :
    (transitionSystem cfg []).step s act ≠ some t := by
  have empty : s.nodes = [] := by
    induction reach using (@CCF.TransitionSystem.Reachable.rec (transitionSystem cfg [])) with
    | initial init => exact List.map_eq_nil_iff.1 init.2.1
    | step _ step ih => exact (no_step_without_nodes step ih).elim
  exact fun step => no_step_without_nodes step empty

def HasCommit (f : Frame) : Prop := ∃ k part, Committed f k part

noncomputable def ghostLabel [Config.InitialConfiguration] (f : Frame) (t : Model.State) : Row :=
  open Classical in
  ⟨PairQuestions.zero f.current, decide (HasCommit f), PairQuestions.newPrimary f.current t,
    PairQuestions.zero t, decide (HasCommit (f.advance t))⟩

theorem inl_iff [Config.InitialConfiguration] (f : Frame) :
    Classes.state_committed_logs_comparable_left_backed_inl f ↔
      PairQuestions.zero f.current = true :=
  PairQuestions.zero_iff _ _ rfl

private theorem zero_or_backed [Config.InitialConfiguration] {f : Frame} (inv : Inv f)
    {n : NodeID} {st : NodeState} (mem : Now f n st) :
    PairQuestions.zero f.current = true ∨ HasCommit f := by
  obtain ⟨_, z | ⟨k, part, committed, _⟩⟩ := (inv.commit_backed n st mem).1
  · exact .inl ((PairQuestions.zero_mem _).2 ⟨n, st, mem, z⟩)
  · exact .inr ⟨k, part, committed⟩

theorem inr_iff [Config.InitialConfiguration] {f : Frame} (inv : Inv f)
    (hasNode : f.current.nodes ≠ []) :
    Classes.state_committed_logs_comparable_left_backed_inr f ↔ HasCommit f := by
  constructor
  · rintro ⟨_, _, _, _, _, ⟨k, part, committed, _⟩, _⟩
    exact ⟨k, part, committed⟩
  · rintro ⟨k, part, committed⟩
    obtain ⟨⟨n, st⟩, mem⟩ := List.exists_mem_of_ne_nil _ hasNode
    suffices ∃ k part, Committed f k part ∧ st.log.take st.commitIndex <+: part by
      obtain ⟨k, part, committed, sub⟩ := this
      have h : Committed f k part ∧ k ≤ k ∧ st.log.take st.commitIndex <+: part :=
        ⟨committed, Nat.le_refl k, sub⟩
      exact ⟨n, st, mem, k, .inr ⟨k, part, h⟩, ⟨k, part, h⟩,
        k, ⟨part, h⟩, part, h, committed, h.2, h.2⟩
    obtain ⟨_, z | ⟨k', part', committed', _, sub⟩⟩ := (inv.commit_backed n st mem).1
    · exact ⟨k, part, committed, by simp [z]⟩
    · exact ⟨k', part', committed', sub⟩

private theorem generated_frame_iff [Config.InitialConfiguration] {nodes : List NodeID}
    {f : Frame} {t : Model.State} {act : Model.Action} (inv : Inv f)
    (step : (transitionSystem Config.INITIAL_CONFIGURATION nodes).step f.current act = some t) :
    let row := ghostLabel f t
    (row.zeroBefore = true ↔ Classes.state_committed_logs_comparable_left_backed_inl f) ∧
    (row.backedBefore = true ↔ Classes.state_committed_logs_comparable_left_backed_inr f) ∧
    (row.wonPrimary = true ↔ Classes.step_leader_led_leader_inr f t) ∧
    (row.zeroAfter = true ↔ Classes.state_committed_logs_comparable_left_backed_inl (f.advance t)) ∧
    (row.backedAfter = true ↔ Classes.state_committed_logs_comparable_left_backed_inr (f.advance t)) := by
  obtain ⟨tr⟩ := LocalTransition.ofStep step
  let c : Ctx f t := ⟨tr, inv⟩
  have afterNotEmpty : (f.advance t).current.nodes ≠ [] :=
    List.ne_nil_of_mem c.post_now
  exact ⟨(inl_iff _).symm, by simp [ghostLabel, inr_iff c.inv (no_step_without_nodes step)],
    (PairQuestions.won_iff rfl ⟨c⟩).symm, (inl_iff (f.advance t)).symm,
    by simp [ghostLabel, inr_iff c.inv_step afterNotEmpty]⟩

private theorem historyLabel_eq [Config.InitialConfiguration] {nodes : List NodeID}
    {s t : Model.State} {past : List Model.State} {act : Model.Action}
    (step : (transitionSystem Config.INITIAL_CONFIGURATION nodes).step s act = some t) :
    historyLabel Config.INITIAL_CONFIGURATION s t past = ghostLabel (StateCoverage.frame s past) t := by
  classical
  obtain ⟨tr⟩ := LocalTransition.ofStep step
  have commit (x : Model.State) (xs : List Model.State) (nonempty : x.nodes ≠ []) :
      (StateCoverage.read Config.INITIAL_CONFIGURATION x xs).2 =
        decide (HasCommit (StateCoverage.frame x xs)) := by
    apply Bool.eq_iff_iff.2
    have nonempty' : x.nodes.isEmpty = false :=
      Bool.eq_false_iff.2 (fun h => nonempty (List.isEmpty_iff.1 h))
    simp only [StateCoverage.read, nonempty', Bool.not_false, Bool.true_and, decide_eq_true_eq]
    have h := CommitMonitor.anyCommit_iff (x :: xs)
    rw [← StateCoverage.frame_logs] at h
    exact h
  unfold historyLabel ghostLabel
  rw [StateCoverage.frame_current, commit s past (List.ne_nil_of_mem tr.pre_mem),
    commit t (s :: past) (List.ne_nil_of_mem tr.post_mem)]
  rfl

/-- Every column is exactly its named generated class on the frame folded from the
actual initialized execution, including the negative answer by negating the iff. -/
theorem generated_iff [Config.InitialConfiguration] {nodes : List NodeID}
    {s t : Model.State} {past : List Model.State} {act : Model.Action}
    (run : StateCoverage.Run Config.INITIAL_CONFIGURATION nodes s past)
    (step : (transitionSystem Config.INITIAL_CONFIGURATION nodes).step s act = some t) :
    let f := StateCoverage.frame s past
    let row := historyLabel Config.INITIAL_CONFIGURATION s t past
    (row.zeroBefore = true ↔ Classes.state_committed_logs_comparable_left_backed_inl f) ∧
    (row.backedBefore = true ↔ Classes.state_committed_logs_comparable_left_backed_inr f) ∧
    (row.wonPrimary = true ↔ Classes.step_leader_led_leader_inr f t) ∧
    (row.zeroAfter = true ↔ Classes.state_committed_logs_comparable_left_backed_inl (f.advance t)) ∧
    (row.backedAfter = true ↔ Classes.state_committed_logs_comparable_left_backed_inr (f.advance t)) := by
  rw [historyLabel_eq step]
  exact generated_frame_iff (StateCoverage.run_inv run) (by rwa [StateCoverage.frame_current])

private theorem win_older_log [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) (wins : Wins c.actor c.pre c.event c.post) :
    c.post.log <+: c.pre.log ∧ ∀ e ∈ c.post.log, e.term < c.post.currentTerm := by
  obtain ⟨cand, campaign, _, logEq, termEq, _⟩ := Wins.facts wins
  have ⟨_, preLog, _, _⟩ := campaign
  have sub : c.post.log <+: c.pre.log := by
    rw [logEq, ← preLog]
    exact primaryState_log_prefix _
  refine ⟨sub, fun e mem => ?_⟩
  have old := sub.mem mem
  rw [termEq]
  rcases (c.campaign_three campaign).2 with lt | ⟨eq, role⟩
  · exact Nat.lt_of_le_of_lt (c.inv.terms _ _ c.pre_now _ old) lt
  · rw [← eq]
    exact (c.inv.candidate _ _ c.pre_now role).2.2.2.2 _ old

private theorem fresh_commit [Config.InitialConfiguration] {s : Model.State} {past : List Model.State}
    {n : NodeID} {st : NodeState} {k i : Nat}
    (h : CommitStep (StateCoverage.frame s past) n st k 0 i) :
    Committed (StateCoverage.frame s past) k (st.log.take i) := by
  cases past <;> exact Or.inr ⟨n, st, 0, i, h, rfl, Or.inl rfl⟩

private theorem hasCommit_on_win [Config.InitialConfiguration] {s t : Model.State}
    {past : List Model.State} :
    let f := StateCoverage.frame s past
    Nonempty (Ctx f t) → PairQuestions.newPrimary f.current t = true →
      HasCommit (f.advance t) → HasCommit f := by
  intro f ctx win h
  obtain ⟨c, _, _, _, _, _, _, _, _, _, wins, _, _⟩ := (PairQuestions.won_iff rfl ctx).2 win
  obtain ⟨k, part, past | ⟨n, st, base, i, fresh, rfl, backed⟩⟩ := h
  · exact ⟨k, part, past⟩
  obtain ⟨⟨now, termEq, notCandidate, led⟩, baseLe, within, sig, term, voters, quorum, seen⟩ := fresh
  have elect := c.wins_elect wins
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨other, old⟩
  · have bound := termAt_le_of_mem (bound := c.post.currentTerm - 1)
      (fun e mem => Nat.le_sub_one_of_lt ((win_older_log c wins).2 e mem)) i
    have above := (c.electStep elect).2.2.2.2.2.2.2
    omega
  · have oldLed := c.led_other other led
    have diff : c.post.currentTerm ≠ k := fun heq =>
      other (c.new_old_unique elect (heq.symm ▸ oldLed)).symm
    rcases backed with rfl | ⟨earlier, p, commit, _, _⟩
    · -- Reuse the unchanged leader and its old observations in the previous frame.
      refine ⟨k, st.log.take i, fresh_commit (s := s) (past := past)
        ⟨⟨old, termEq, notCandidate, oldLed⟩, baseLe, within, sig, term, voters, quorum, ?_⟩⟩
      intro v hv
      obtain ⟨log, seenLog, sub⟩ := seen v hv
      have observed : Seen (f.advance t) v ⟨k, log⟩ := seenLog
      rcases c.seen_after observed with past | ⟨_, eq⟩
      · exact ⟨log, past, sub⟩
      · exact (diff (congrArg Observation.currentTerm eq).symm).elim
    · exact ⟨earlier, p, commit⟩

public theorem complete {cfg : CCF.Finset NodeID} {nodes : List NodeID}
    {s t : Model.State} {past : List Model.State} {act : Model.Action}
    (run : StateCoverage.Run cfg nodes s past)
    (step : (transitionSystem cfg nodes).step s act = some t) :
    historyLabel cfg s t past ∈ table := by
  classical
  letI : Config.InitialConfiguration := ⟨cfg⟩
  let f := StateCoverage.frame s past
  have eq : historyLabel cfg s t past = ghostLabel f t := historyLabel_eq step
  rw [eq]
  have stepped : (transitionSystem cfg nodes).step f.current act = some t := by
    rwa [StateCoverage.frame_current]
  obtain ⟨tr⟩ := LocalTransition.ofStep stepped
  let c : Ctx f t := ⟨tr, StateCoverage.run_inv run⟩
  have next : PairQuestions.zero t = true ∨ HasCommit (f.advance t) :=
    zero_or_backed c.inv_step c.post_now
  exact all_cases _ _ _ _ _ (by simpa using zero_or_backed c.inv c.pre_now) (by simpa using next)
    (PairQuestions.zero_old c stepped)
    (by simpa using (show HasCommit f → HasCommit (f.advance t) from
      fun ⟨k, p, h⟩ => ⟨k, p, .inl h⟩))
    (PairQuestions.zero_on_win ⟨c⟩) (by simpa using hasCommit_on_win (s := s) (past := past) ⟨c⟩)

end ConsensusCoverage.FrontierRows
