module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.DeepBoundCases
import all ConsensusCoverage.QueueSamplesA
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ReachPath
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.DeepLookupCases

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open Consensus.Proofs.Ledger
open ReadersAtoms GuardedDomain SolvedWitnesses ActionProfile QueueSamplesA

set_option maxRecDepth 8192

private def check (s : Step) : Bool :=
  (ofXAction s.cfg s.before s.after s.past s.act).any fun x =>
    decide (x.base.pre.role = .candidate ∧ x.base.post.role = .primary ∧
      x.base.pre.currentTerm = x.base.post.currentTerm ∧ 0 < x.base.pre.commitIndex)

theorem sound (s : Step) (pass : check s = true) : label s (.step .termAt_le_of_mem_found_some) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  obtain ⟨x,made,ok⟩ := ofXAction_matches s
  simp only [check,made,Option.any_some,decide_eq_true_eq] at pass
  rw [← View.pre_eq ok.1,← View.post_eq ok.1] at pass
  obtain ⟨cand,primary,same,pos⟩ := pass
  have won := (Summary.leader c.sum primary).resolve_left (fun old => by rw [cand] at old; cases old.1)
  have elect := c.wins_elect won
  have call := DeepBoundCases.entered c elect
  obtain ⟨st,w,mem,mem',log,idx,le,terms,turn,role,pfx,floor,xs,q,grants⟩ := id elect
  have stEq : st = c.pre := c.now_pre mem
  have stTerm : st.currentTerm = c.post.currentTerm := stEq ▸ same
  have stRole : st.role = .candidate := stEq ▸ cand
  have low := (c.inv.candidate _ _ mem stRole).2.2.2.2
  let j := max c.pre.commitIndex (maxCommittableIndex c.pre.log)
  have jp : 0 < j := Nat.lt_of_lt_of_le pos (Nat.le_max_left _ _)
  have jb : j ≤ c.pre.log.length := Nat.max_le.mpr ⟨le,maxCommittableIndexBounded _⟩
  have bs : j ≤ st.log.length := log ▸ jb
  obtain ⟨a,canon,length,take⟩ := c.inv.anchor _ _ j mem jp bs
  have termpos := Nat.lt_of_lt_of_le (by decide : 0 < 3) floor
  have root : (reach% step_termAt_le_of_mem_found_some[0]) _ _ c st.log (c.post.currentTerm-1) j := by
    right; right; left
    refine ⟨_,_,_,_,call,st,⟨w,mem,mem',log,idx,le,terms,turn,role,pfx,floor,xs,q,grants⟩,
      w,?_,mem,?_,mem',?_,log,?_,idx,?_,le,?_,terms,?_,turn,?_,role,?_,pfx,?_,floor,
      ⟨xs,q,grants⟩,xs,⟨q,grants⟩,q,grants,jp,a,canon,length,take,⟨stTerm,stRole⟩,stTerm,stRole,
      elect,jb,low,termpos,rfl,rfl,rfl⟩
    all_goals repeat' first | assumption | exact ⟨xs,q,grants⟩ | apply And.intro
  have index : j-1 < st.log.length := Nat.lt_of_lt_of_le (Nat.sub_lt jp (by decide)) bs
  have found : entryAt? st.log j = some st.log[j-1] := by simp [entryAt?,Nat.ne_of_gt jp,index]
  apply (label_true s _).mpr
  apply (sig_iff c _).mpr
  exact Or.inl ⟨_,_,_,root,_,found,found,fun e h => Nat.le_sub_one_of_lt (stTerm ▸ low e h)⟩

open DeepSchedules FrontierRows in
def certificates : List Certificate :=
  [checked .termAt_le_of_mem_found_some (selected (threeTerms true) (by unfold Run.valid; decide) 20)
    check (by decide +kernel) sound]

end ConsensusCoverage.DeepLookupCases
