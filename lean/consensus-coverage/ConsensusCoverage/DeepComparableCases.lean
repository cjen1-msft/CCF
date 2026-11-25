module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.QueueSamplesA
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ReachPath
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.DeepComparableCases

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open SolvedWitnesses ReadersAtoms GuardedDomain ActionProfile QueueSamplesA

private def column (forward : Bool) : Classes.StepBranch :=
  if forward then .take_eq_take_of_comparable_comparable_inl else .take_eq_take_of_comparable_comparable_inr

private def check (s : Step) : Bool :=
  (ofXAction s.cfg s.before s.after s.past s.act).any fun x =>
    decide (x.base.changed = true ∧ x.base.pre.log = x.base.post.log ∧ 1 ≤ x.base.pre.log.length)

private theorem sound (s : Step) (fwd : Bool) (yes : check s = true) : label s (.step (column fwd)) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  obtain ⟨x,made,ok⟩ := ofXAction_matches s
  simp only [check,made,Option.any_some,decide_eq_true_eq] at yes
  obtain ⟨changed,eq,bnd⟩ := yes
  rw [← View.pre_eq ok.1,← View.post_eq ok.1] at eq
  rw [← View.pre_eq ok.1] at bnd
  have fresh : ¬ Now s.frame c.actor c.post := fun h =>
    Bool.noConfusion (changed.symm.trans ((View.old_post ok.1).mp h))
  have post : 1 ≤ c.post.log.length := eq ▸ bnd
  have pos := Nat.zero_lt_succ 0
  have call : (reach% step_take_eq_take_of_comparable_comparable_inl[0,0]) _ _ c c :=
    ⟨c.actor,c.post,1,c.post_now,pos,post,fun h => fresh h.1,rfl⟩
  obtain ⟨l,canon,bl,agree⟩ := c.inv.anchor _ _ 1 c.pre_now pos bnd
  have left : c.pre.log <+: c.post.log := eq ▸ List.prefix_refl _
  have right : c.post.log <+: c.pre.log := eq ▸ List.prefix_refl _
  have root : (reach% step_take_eq_take_of_comparable_comparable_inl[0]) _ _ c c.pre.log c.post.log 1 :=
    Or.inl ⟨call,c.post_now,pos,post,c.post_now,post,c.post_now,right,l,⟨canon,bl,agree⟩,canon,
      ⟨bl,agree⟩,bl,agree,rfl,rfl⟩
  apply (label_true s _).mpr
  apply (sig_iff c _).mpr
  cases fwd with
  | true => exact Or.inl ⟨_,_,1,root,left,Or.inl left,bnd,post⟩
  | false => exact Or.inl ⟨_,_,1,root,right,Or.inr right,bnd,post⟩

open DeepSchedules FrontierRows in
def certificates : List Certificate :=
  [true,false].map fun fwd => checked (column fwd) (selected divergent (by unfold Run.valid; decide) 8)
    check (by decide +kernel) (sound · fwd)

end ConsensusCoverage.DeepComparableCases
