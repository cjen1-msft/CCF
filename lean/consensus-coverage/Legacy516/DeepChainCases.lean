module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.BackingRead
import all ConsensusCoverage.DeepHistoryCases
import all ConsensusCoverage.QueueSamplesA
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ReachPath
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.DeepChainCases

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open ReadersAtoms GuardedDomain SolvedWitnesses ActionProfile QueueSamplesA

set_option maxRecDepth 8192

private def column (fresh : Bool) : Classes.StepBranch :=
  if fresh then .advance_chain_fresh else .advance_chain_backed

private def check (s : Step) (e i : Nat) : Bool :=
  (BackingRead.read (s.cfg.min?.getD 0) s.after (s.before :: s.past)).2 &&
    (ofXAction s.cfg s.before s.after s.past s.act).any fun x =>
      ((x.base.before :: x.base.past).flatMap fun a => a.nodes.map (fun p => p.2.log)).any fun l =>
        decide ((e,l.take i) ∈ x.committedBefore) && DeepHistoryCases.oldFacts x l e 0 i

theorem sound (s : Step) (e i : Nat) (p : check s e i = true) (fresh : Bool) : label s (.step (column fresh)) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  obtain ⟨x,made,ok⟩ := ofXAction_matches s
  simp only [check,BackingRead.prior_answer,made,Option.any_some,Bool.and_eq_true,List.any_eq_true,decide_eq_true_eq] at p
  obtain ⟨prior,l,_,mem,old⟩ := p
  have facts := DeepHistoryCases.oldFacts_sound ok old
  have m := (X.committed_before ok e (l.take i)).mpr mem
  have chain := c.inv.commitChains _ _ m
  have root : (reach% step_advance_chain_fresh[0]) _ _ c :=
    (sig_iff c .commitChains_step_backing_inr).mp ((label_true s _).mp prior)
  apply (label_true s _).mpr
  apply (sig_iff c _).mpr
  cases fresh with
  | true => exact ⟨root,l,e,i,facts⟩
  | false => exact ⟨root,l,e,0,i,e,l.take i,facts,m,chain,Nat.le_refl _,by simp,chain.advance⟩

open DeepSchedules FrontierRows in
def certificates : List Certificate :=
  [true,false].map fun fresh =>
    checked (column fresh) (selected installLater (by unfold Run.valid; decide) 9)
      (check · 2 2) (by decide +kernel) (fun s h => sound s 2 2 h fresh)

end ConsensusCoverage.DeepChainCases
