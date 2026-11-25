module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.DeepCarriedCases
import all ConsensusCoverage.DeepHistoryCases
import all ConsensusCoverage.QueueSamplesA
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ReachPath
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.DeepTipCases

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open ReadersAtoms GuardedDomain SolvedWitnesses ActionProfile QueueSamplesA

private def column (fresh : Bool) : Classes.StepBranch := if fresh then .tip_chain_fresh else .tip_chain_backed

private theorem sound (s : Step) (e i : Nat) (fresh : Bool)
    (pass : DeepCarriedCases.check s .fresh e i = true) : label s (.step (column fresh)) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  obtain ⟨x,made,ok⟩ := ofXAction_matches s
  simp only [DeepCarriedCases.check,made,Option.any_some,Bool.and_eq_true,decide_eq_true_eq,List.any_eq_true] at pass
  obtain ⟨⟨pre,post,lt,_⟩,l,_,⟨mem,_⟩,facts⟩ := pass
  rw [← View.pre_eq ok.1] at pre
  rw [← View.post_eq ok.1] at post lt
  have elect := c.wins_elect ((Summary.leader c.sum post).resolve_left fun old => pre old.1)
  have m := (X.committed_before ok e (l.take i)).mpr mem
  have f := DeepHistoryCases.oldFacts_sound ok facts
  have chain := c.inv.commitChains _ _ m
  have r := (DeepCarriedCases.source c m lt elect).1
  have caller : (reach% step_tip_chain_fresh[0,0,2]) _ _ c :=
    ⟨_,_,_,_,_,_,r.1,elect,r.2.2.2.1,lt,m⟩
  have root : (reach% step_tip_chain_fresh[0]) _ _ c e (l.take i) :=
    Or.inl ⟨Or.inr (Or.inr caller),m⟩
  apply (label_true s _).mpr
  apply (sig_iff c _).mpr
  cases fresh with
  | true => exact Or.inl ⟨_,_,root,l,i,f,f,rfl,chain,proof_irrel_heq _ _,chain⟩
  | false => exact Or.inl ⟨_,_,root,l,0,i,e,l.take i,f,m,chain,Nat.le_refl _,by simp,f,Nat.le_refl _,
      rfl,chain,proof_irrel_heq _ _,chain⟩

open DeepSchedules FrontierRows in
def certificates : List Certificate :=
  [true,false].map fun fresh => checked (column fresh) (selected divergent (by unfold Run.valid; decide) 8)
    (DeepCarriedCases.check · .fresh 2 2) (by decide +kernel) (sound · 2 2 fresh)

end ConsensusCoverage.DeepTipCases
