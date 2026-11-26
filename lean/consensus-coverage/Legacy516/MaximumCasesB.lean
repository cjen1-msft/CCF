module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ActionProfile
import all ConsensusCoverage.CaseWitnesses
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ReachPath
import all Consensus.Proofs.SafetyInvariant
meta import Lean

namespace ConsensusCoverage.MaximumCasesB

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open ActionProfile SolvedWitnesses Lean Meta Elab Tactic

set_option maxRecDepth 8192
set_option maxHeartbeats 0

private abbrev Pool (entry : (P : Nat → Prop) → DecidablePred P → Prop) :=
  ∃ P d, entry P d ∧ (∃ i, P i) ∧ ¬ P 0

-- The new call carries the old hypotheses in the same order with two
-- premises appended at the end. Keep the original proof projections.
local elab "extend_conjunction " h:ident " with " last:tacticSeq : tactic => withMainContext do
  let mut h ← getFVarFromUserName h.getId
  let mut t ← inferType h
  let mut goal ← getMainGoal
  repeat
    let g ← whnf (← goal.getType)
    unless g.isAppOf ``And do throwError "expected a conjunction"
    if ← isDefEq t (g.getArg! 0) then
      let gs ← goal.applyConst ``And.intro
      gs[0]!.assign h
      replaceMainGoal [gs[1]!]
      evalTactic last
      break
    unless t.isAppOf ``And do throwError "incoming assumptions diverged"
    let gs ← goal.applyConst ``And.intro
    gs[0]!.assign (mkProj ``And 0 h)
    h := mkProj ``And 1 h
    t := t.getArg! 1
    goal := gs[1]!

local macro "commit_pool " c:term:arg h:ident : tactic => `(tactic|
  (obtain ⟨middle, path⟩ := $h
   obtain ⟨_, _, _, _, _, _, grew, eq, _⟩ := path.2.1
   have ahead : middle.commitIndex < highestCommittableIndex middle ($c).actor := eq ▸ grew
   have spec := highestCommittableIndex_spec middle ($c).actor ahead
   refine ⟨_, _, ⟨_, _, ⟨middle, ($c).actor, ?_, ahead, rfl, HEq.rfl, rfl⟩,
     Nat.zero_lt_of_lt ahead, HEq.rfl⟩,
     ⟨_, ahead, spec.2.1, spec.2.2.1, spec.2.2.2⟩, fun zero => Nat.not_lt_zero _ zero.1⟩
   extend_conjunction path with exact ⟨ahead, rfl⟩))

private theorem pools [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    {c : Ctx f t} (h : step_advance_backed_advance_inr f t c) :
    Pool ((reach% step_foldl_select_max_values_cons[0]) f t c) ∨
    Pool ((reach% step_foldl_select_max_values_cons[1]) f t c) ∨
    Pool ((reach% step_foldl_select_max_values_cons[2]) f t c) ∨
    Pool ((reach% step_foldl_select_max_values_cons[3]) f t c) := by
  rcases h with h | h | h | h
  · left; commit_pool c h
  · right; left; commit_pool c h
  · right; right; left; commit_pool c h
  · right; right; right; commit_pool c h

public def questions : List Classes.StepBranch :=
  [.foldl_select_max_values_cons, .foldl_select_max_ih_inl, .foldl_select_max_chosen_pos,
   .foldl_select_max_le_total_inl, .foldl_select_max_le_total_inr, .foldl_select_max_chosen_neg,
   .foldl_select_max_ih_inr]

-- The induction head, tail and initial accumulator are universally
-- generalized in the proof, not tied to positions of the input range.
local macro "use_pool " p:ident : tactic => `(tactic|
  (obtain ⟨P, d, entry, ⟨i, good⟩, bad⟩ := $p
   letI : DecidablePred P := d
   refine ⟨P, d, entry, ?_⟩
   first
   | exact ⟨[], fun _ => Or.inl rfl⟩
   | exact ⟨i, [], fun _ => Or.inl rfl, i, rfl, good, Nat.le_refl _⟩
   | exact ⟨i, [], fun _ => Or.inl rfl, i, rfl, good⟩
   | exact ⟨0, [], fun _ => Or.inl rfl, i, rfl, bad⟩
   | exact ⟨i, [], fun _ => Or.inl rfl, i, rfl⟩
   | exact ⟨i, [], fun _ => Or.inl rfl, i, by simpa only [List.foldl_nil, ite_eq_left good, Nat.max_self]⟩))

public theorem occurs {b : Classes.StepBranch} (member : b ∈ questions) :
    ∃ s : Step, label s (.step b) = true := by
  obtain ⟨s, yes⟩ := CaseWitnesses.occurs (b := .advance_backed_advance_inr) (by decide +kernel)
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have ready := pools ((sig_iff s.context _).mp ((label_true s _).mp yes))
  refine ⟨s, (label_true s _).mpr ((sig_iff s.context _).mpr ?_)⟩
  simp only [questions, List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with rfl | rfl | rfl | rfl | rfl | rfl | rfl
  all_goals
    rcases ready with p | p | p | p
    · left; use_pool p
    · right; left; use_pool p
    · right; right; left; use_pool p
    · right; right; right; left; use_pool p

end ConsensusCoverage.MaximumCasesB
