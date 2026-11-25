module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.DeepLeaderCases
import all ConsensusCoverage.QueueSamplesA
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ReachPath
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.DeepWinningCases

open Consensus Consensus.Proofs Consensus.Model Consensus.Model.Node Safety SolvedWitnesses
open ActionProfile QueueSamplesA

set_option maxRecDepth 8192

inductive Case where | positive | zero | identity

def column : Case → Classes.StepBranch
  | .positive => .primaryState_log_prefix_commit_pos
  | .zero => .primaryState_log_prefix_commit_neg
  | .identity => .facts_advance_inl_2

private def check (s : Step) (k : Case) : Bool :=
  (GuardedDomain.ofAction s.cfg s.before s.after s.past s.act).any fun x =>
    (decide (x.pre.role ≠ .primary ∧ x.post.role = .primary)) &&
      match k with
      | .positive => decide (0 < x.pre.commitIndex)
      | .zero => decide (¬0 < x.pre.commitIndex)
      | .identity => decide (x.pre.commitIndex = x.post.commitIndex)

private theorem sound (s : Step) (k : Case) (passed : check s k = true) :
    label s (.step (column k)) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  obtain ⟨x,found,ok⟩ := GuardedDomain.ofAction_matches s
  simp only [check,found,Option.any_some,Bool.and_eq_true,decide_eq_true_eq] at passed
  rw [← GuardedDomain.View.pre_eq ok,← GuardedDomain.View.post_eq ok] at passed
  obtain ⟨⟨old,primary⟩,h⟩ := passed
  have won := (Summary.leader c.sum primary).resolve_left (fun prior => old prior.1)
  have now := c.post_now
  have root : (reach% step_primaryState_log_prefix_commit_pos[2,0]) _ _ c c :=
    ⟨⟨_,_,now,fun prev => old ((c.now_pre prev) ▸ primary),rfl⟩,now,now,now,
      c.inv.terms _ _ c.pre_now,rfl⟩
  apply (label_true s _).mpr
  apply (sig_iff c _).mpr
  cases k with
  | positive | zero =>
    obtain ⟨candidate,camp,quorum,log,term,vote,matchEq,role,le⟩ := Wins.facts won
    have from_ : (reach% step_primaryState_log_prefix_commit_pos[2]) _ _ c candidate :=
      ⟨root,won,rfl,⟨camp,quorum,log,term,vote,matchEq,role,le⟩,camp,
        ⟨quorum,log,term,vote,matchEq,role,le⟩,camp.1,camp.2,camp.2.1,camp.2.2,
        quorum,log,term,vote,matchEq,role,le⟩
    right; right; left
    refine ⟨_,from_,?_⟩
    rw [camp.2.2.1]
    exact of_decide_eq_true h
  | identity =>
    have from_ : (reach% step_facts_advance_inl_2[4]) _ _ c c.actor c.pre c.event c.post :=
      ⟨root,won,rfl,rfl,rfl,rfl,rfl⟩
    obtain ⟨cand,camp,quorum,advance⟩ := won
    have same := of_decide_eq_true h
    have id_ : c.post = primaryState cand := advance.resolve_right fun bigger => by
      have strict : cand.commitIndex < c.post.commitIndex := bigger.2.2.2.2.2.2.1
      rw [camp.2.2.1] at strict
      exact (Nat.ne_of_lt strict) same
    iterate 4 right
    exact Or.inl ⟨_,_,_,_,from_,cand,⟨camp,quorum,advance⟩,camp,⟨quorum,advance⟩,
      quorum,advance,camp.1,camp.2.1,camp.2.2.1,camp.2.2.2,id_,⟨cand,camp,quorum,advance⟩⟩

open FrontierRows DeepSchedules in
local macro "win_at " k:term:arg sc:term:arg i:num : term =>
  `(checked (column $k) (selected $sc (by unfold Run.valid; decide) $i)
    (check · $k) (by decide +kernel) (sound · $k))

open DeepSchedules in
def certificates : List Certificate :=
  [win_at .positive (threeTerms true) 20,win_at .zero divergent 8,win_at .identity divergent 8]

end ConsensusCoverage.DeepWinningCases
