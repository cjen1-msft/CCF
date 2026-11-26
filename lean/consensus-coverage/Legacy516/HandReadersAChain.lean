module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersABase
import all ConsensusCoverage.BackingArms
import all ConsensusCoverage.BackingRead
import all ConsensusCoverage.DelayedNominationArms
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersA.Chain

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety ActionProfile SolvedWitnesses
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

def reader : Reader := fun cfg before _ after past => (BackingRead.read (cfg.min?.getD 0) after (before :: past)).2

def column (fresh : Bool) : Classes.StepBranch := if fresh then .advance_chain_fresh else .advance_chain_backed

private theorem branches [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t) (fresh : Bool) :
    sig c (column fresh) ↔ sig c .commitChains_step_backing_inr := by
  constructor
  · intro h
    cases fresh <;> exact h.1
  · intro h
    have root : (reach% step_advance_chain_fresh[0]) f t c := h
    obtain ⟨_,_,_,_,_,_,_,e,p,old,_⟩ := (BackingArms.prior_iff c).mp ((sig_iff c _).mpr h)
    obtain ⟨l,k,i,facts,base⟩ := DelayedNomination.oldChainBase (c.inv.commitChains e p old) old
    have baseChain : CommitChain f.logs k (l.take i) := .fresh facts
    cases fresh
    · exact ⟨root,l,k,0,i,k,l.take i,facts,base,baseChain,Nat.le_refl _,List.nil_prefix,baseChain.advance⟩
    · exact ⟨root,l,k,i,facts⟩

def exactReader (fresh : Bool) : Exact (column fresh) where
  eval := reader
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    rw [reader,BackingRead.prior_answer]
    apply Bool.eq_iff_iff.mpr
    rw [label_true,label_true,holds,holds,sig_iff,sig_iff]
    exact branches s.context fresh

end ConsensusCoverage.HandReadersA.Chain
