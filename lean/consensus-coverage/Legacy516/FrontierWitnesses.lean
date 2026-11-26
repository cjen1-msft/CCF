module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.FrontierRows
import all ConsensusCoverage.FrontierRows
import all ConsensusCoverage.StateCoverage
import all ConsensusCoverage.CommitMonitor
import all ConsensusCoverage.PairWitnesses

namespace ConsensusCoverage.FrontierRows

open Consensus Consensus.Model Consensus.Model.Node

private abbrev Command := PairQuestions.Command

private def election (candidate peer : NodeID) : List Command :=
  [.input candidate (.timeout .election),
   .deliver candidate peer, .deliver peer candidate, .deliver candidate peer, .deliver peer candidate]

private def signature : Command := .input 0 (.append [{content := .signature}])

private def stepDown : Command := .input 0 (.timeout .checkQuorum)

private structure Run where
  cfg : CCF.Finset NodeID
  nodes : List NodeID
  schedule : List Command

private def runs : List Run :=
  [⟨{0}, [0], [signature, signature]⟩,
   ⟨{0,1}, [0,1], [signature, stepDown] ++ election 0 1⟩,
   ⟨{0,1}, [0,1], PairQuestions.schedule⟩,
   ⟨{0,1}, [0,1,2], PairQuestions.schedule⟩]

private def initial (r : Run) : Model.State :=
  {nodes := r.nodes.map fun n => (n, initialNodeState r.cfg n)}

private def Run.valid (r : Run) : Prop := r.cfg.Nonempty ∧ r.nodes.Nodup

private theorem initialized (r : Run) (valid : r.valid) :
    (transitionSystem r.cfg r.nodes).init (initial r) := by
  refine ⟨valid.1, ?_, ?_⟩ <;> simp [initial, protocol, Function.comp_def, valid.2]

private abbrev Observe (α : Type) :=
  CCF.Finset NodeID → Model.State → Model.State → List Model.State → α

private def replay {α : Type} (observe : Observe α) (r : Run) (s : Model.State)
    (past : List Model.State) : List Command → Option (List α)
  | [] => some []
  | cmd :: cmds => do
    let act ← cmd.resolve s
    let t ← (transitionSystem r.cfg r.nodes).step s act
    return observe r.cfg s t past :: (← replay observe r t (s :: past) cmds)

private theorem replay_sound {α : Type} {observe : Observe α} {r : Run} {s : Model.State}
    {past cmds es} {P : α → Prop} (path : StateCoverage.Run r.cfg r.nodes s past)
    (ok : ∀ {s t past act}, StateCoverage.Run r.cfg r.nodes s past →
      (transitionSystem r.cfg r.nodes).step s act = some t →
      P (observe r.cfg s t past))
    (h : replay observe r s past cmds = some es) : ∀ e ∈ es, P e := by
  induction cmds generalizing s past es with
  | nil => cases h; simp
  | cons cmd rest ih =>
    simp only [replay, Option.bind_eq_bind, Option.bind_eq_some_iff] at h
    obtain ⟨act, _, t, step, tail, followed, eq⟩ := h
    cases eq
    intro e mem
    rcases List.mem_cons.1 mem with rfl | old
    · exact ok path step
    · exact ih (.step path step) followed e old

private def rows (observe : Observe Row) : List Run → Option (List Row)
  | [] => some []
  | r :: rs => do
    let front ← replay observe r (initial r) [] r.schedule
    return front ++ (← rows observe rs)

/-- Projected rows of the four executable witness schedules, in run order. -/
public def witnessRows : Option (List Row) := rows historyLabel runs

private def covers (rs : Option (List Row)) : Bool :=
  match rs with
  | none => false
  | some seen => table.all fun row => row ∈ seen

private theorem valid_runs : ∀ r ∈ runs, r.valid := by
  intro r hr
  simp only [runs, List.mem_cons, List.not_mem_nil, or_false] at hr
  rcases hr with rfl | rfl | rfl | rfl <;> unfold Run.valid <;> decide

private theorem witness {observe : Observe Row} {P : Row → Prop}
    (ok : ∀ {r : Run} {s t past act}, StateCoverage.Run r.cfg r.nodes s past →
      (transitionSystem r.cfg r.nodes).step s act = some t →
      P (observe r.cfg s t past))
    {rs : List Run} (valid : ∀ r ∈ rs, r.valid) {found : List Row}
    (replayed : rows observe rs = some found) :
    ∀ row ∈ found, P row := by
  induction rs generalizing found with
  | nil => cases replayed; simp
  | cons r rs ih =>
    simp only [rows, Option.bind_eq_bind, Option.bind_eq_some_iff] at replayed
    obtain ⟨first, h, later, h', eq⟩ := replayed
    have := Option.some.inj (show some (first ++ later) = some found from eq)
    subst found
    intro row hr
    rcases List.mem_append.1 hr with start | tail
    · exact replay_sound (.initial (initialized r (valid r (by simp)))) ok h _ start
    · exact ih (fun r hr => valid r (List.mem_cons_of_mem _ hr)) h' _ tail

private theorem mem_of_covers {found : Option (List Row)} (check : covers found = true)
    {row : Row} (mem : row ∈ table) : ∃ rs, found = some rs ∧ row ∈ rs := by
  cases found with
  | none => contradiction
  | some rs => exact ⟨rs, rfl, of_decide_eq_true (List.all_eq_true.1 check _ mem)⟩

private theorem exact_of_check (check : covers witnessRows = true)
    (row : Row) : row ∈ table ↔ GhostOccurs row := by
  constructor
  · intro mem
    obtain ⟨found, replayed, mem⟩ := mem_of_covers check mem
    refine witness (observe := historyLabel) ?_ valid_runs replayed row mem
    intro r s t past act h step
    exact ⟨r.cfg, r.nodes, s, t, past, act, h, step, rfl⟩
  · rintro ⟨_, _, _, _, _, _, reach, step, rfl⟩
    exact complete reach step

set_option maxRecDepth 8192 in
private theorem all_rows_covered : covers witnessRows = true := by decide +kernel

/-- The exact numerical table for the five generated branch answers. -/
public theorem ghost_exact (row : Row) : row ∈ table ↔ GhostOccurs row :=
  exact_of_check all_rows_covered row

private def withoutAck : Run :=
  ⟨{0, 1}, [0, 1], [signature, .input 0 (.sendEntries 1 2), .deliver 0 1, stepDown]⟩

private def zeros (s : Model.State) : Bool := s.nodes.all fun n => n.2.commitIndex == 0

private def observeZeros : Observe (Bool × Bool) :=
  fun cfg s t past => (zeros s && zeros t,
    let row := historyLabel cfg s t past
    row.backedBefore && row.backedAfter)

private def counterCovered (xs : Option (List (Bool × Bool))) : Bool :=
  match xs with
  | none => false
  | some es => decide ((true, true) ∈ es)

set_option maxRecDepth 8192 in
private theorem counter_check :
    counterCovered (replay observeZeros withoutAck (initial withoutAck) [] withoutAck.schedule) =
      true := by decide +kernel

private theorem counter_mem {xs : Option (List (Bool × Bool))}
    (h : counterCovered xs = true) : ∃ es, xs = some es ∧ (true, true) ∈ es := by
  cases xs with
  | none => contradiction
  | some es => exact ⟨es, rfl, of_decide_eq_true h⟩

private theorem zeros_spec {s : Model.State} (h : zeros s = true) :
    ∀ p ∈ s.nodes, p.2.commitIndex = 0 :=
  fun p mem => beq_iff_eq.1 (List.all_eq_true.1 h p mem)

/-- The follower received the signature, but the ack was not delivered. The proof
answers `inr` in both frames even though every node stays at commit index zero. -/
public theorem backing_not_positive :
    ∃ (cfg : CCF.Finset NodeID) (nodes : List NodeID) (s t : Model.State)
      (past : List Model.State) (act : Model.Action), StateCoverage.Run cfg nodes s past ∧
      (transitionSystem cfg nodes).step s act = some t ∧
      (historyLabel cfg s t past).backedBefore = true ∧
      (historyLabel cfg s t past).backedAfter = true ∧
      (∀ p ∈ s.nodes, p.2.commitIndex = 0) ∧ (∀ p ∈ t.nodes, p.2.commitIndex = 0) := by
  obtain ⟨es, ran, mem⟩ := counter_mem counter_check
  let P (v : Bool × Bool) :=
    v = (true, true) → ∃ s t past act, StateCoverage.Run withoutAck.cfg withoutAck.nodes s past ∧
      (transitionSystem withoutAck.cfg withoutAck.nodes).step s act = some t ∧
      observeZeros withoutAck.cfg s t past = (true, true)
  have ok {s t past act} (run : StateCoverage.Run withoutAck.cfg withoutAck.nodes s past)
      (step : (transitionSystem withoutAck.cfg withoutAck.nodes).step s act = some t) :
      P (observeZeros withoutAck.cfg s t past) :=
    fun eq => ⟨s, t, past, act, run, step, eq⟩
  have valid : withoutAck.valid := by unfold Run.valid; decide
  obtain ⟨s, t, past, act, run, step, eq⟩ :=
    replay_sound (r := withoutAck) (observe := observeZeros) (P := P)
      (.initial (initialized withoutAck valid)) ok ran _ mem rfl
  have z : zeros s = true ∧ zeros t = true :=
    Bool.and_eq_true_iff.1 (congrArg Prod.fst eq)
  have b : (historyLabel withoutAck.cfg s t past).backedBefore = true ∧
      (historyLabel withoutAck.cfg s t past).backedAfter = true :=
    Bool.and_eq_true_iff.1 (congrArg Prod.snd eq)
  exact ⟨withoutAck.cfg, withoutAck.nodes, s, t, past, act, run, step, b.1, b.2,
    zeros_spec z.1, zeros_spec z.2⟩

end ConsensusCoverage.FrontierRows
