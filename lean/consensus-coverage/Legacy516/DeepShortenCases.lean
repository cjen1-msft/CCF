module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.DeepAcceptedCases
import all ConsensusCoverage.DeepHandlerCases
import all ConsensusCoverage.QueueSamplesA
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ReachPath
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.DeepShortenCases

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety Ledger
open ReadersAtoms GuardedDomain SolvedWitnesses ActionProfile QueueSamplesA

private def column (zero : Bool) : Classes.StepBranch := if zero then .shorten_backed_inl else .shorten_backed_inr

private def check (s : Step) (zero : Bool) : Bool :=
  (ofXAction s.cfg s.before s.after s.past s.act).any fun x =>
    let r := DeepHandlerCases.request x.event
    let i := maxCommittableIndexUpTo x.base.post.log (min r.primaryCommit (r.prevLogIndex+r.entries.length))
    decide (x.base.changed = true ∧ x.event = .receive (DeepHandlerCases.sender x.event) (.appendEntriesRequest r) ∧
      Accepted x.base.pre r x.base.post ∧ max x.base.pre.commitIndex i = i ∧ decide (r.primaryCommit = 0) = zero)

private theorem sound (s : Step) (zero : Bool) (pass : check s zero = true) : label s (.step (column zero)) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  obtain ⟨x,made,ok⟩ := ofXAction_matches s
  simp only [check,made,Option.any_some,decide_eq_true_eq] at pass
  obtain ⟨changed,ev,acc,pick,cond⟩ := pass
  rw [← View.pre_eq ok.1,← View.post_eq ok.1] at acc pick
  let r := DeepHandlerCases.request x.event
  let j := maxCommittableIndexUpTo c.post.log (min r.primaryCommit (r.prevLogIndex+r.entries.length))
  let v := DeepHandlerCases.sender x.event
  have event := (X.event_eq ok).trans ev
  have fresh : ¬ Now s.frame c.actor c.post := fun h =>
    Bool.noConfusion (changed.symm.trans ((View.old_post ok.1).mp h))
  have inner : (reach% step_shorten_backed_inl[0,0]) _ _ c c v r :=
    ⟨⟨c.post_now,fresh,rfl⟩,c.post_now,c.post_now,event,acc,Subsingleton.elim _ _,
      c.post_now,(fun h => ⟨⟨_,h⟩,fun _ _ => h⟩),rfl⟩
  obtain ⟨l,shape⟩ := c.accept_shape event acc
  have le := Consensus.Proofs.Safety.maxCommittableIndexUpTo_le c.post.log
    (min r.primaryCommit (r.prevLogIndex+r.entries.length))
  have bnd : j ≤ r.primaryCommit := Nat.le_trans le (Nat.min_le_left _ _)
  have root : (reach% step_shorten_backed_inl[0]) _ _ c s.frame l j r.primaryCommit r.term :=
    ⟨v,r,inner,shape,shape.1,shape.2,shape.2.1,shape.2.2,shape.2.2.1,shape.2.2.2,shape.2.2.2.1,
      shape.2.2.2.2,acc.1,acc.2,acc.2.1,acc.2.2,acc.2.2.1,acc.2.2.2,acc.2.2.2.1,
      acc.2.2.2.2,acc.2.2.2.2.1,acc.2.2.2.2.2,acc.2.2.2.2.2.1,acc.2.2.2.2.2.2,
      pick,event,acc,le,rfl,rfl,rfl,rfl⟩
  have back : Backed s.frame l r.primaryCommit r.term := shape.1.backed
  apply (label_true s _).mpr
  apply (sig_iff c _).mpr
  cases zero with
  | true =>
    have z : r.primaryCommit = 0 := of_decide_eq_true cond
    rw [z] at root bnd back
    exact Or.inl ⟨_,_,_,_,root,back,bnd⟩
  | false =>
    obtain ⟨e,p,m,lo,sub⟩ := back.resolve_left (of_decide_eq_false cond)
    have h := And.intro m (And.intro lo sub)
    exact Or.inl ⟨_,_,_,_,_,root,⟨e,p,h⟩,e,⟨p,h⟩,p,h,m,h.2,lo,sub,back,bnd⟩

open DeepSchedules FrontierRows in
def certificates : List Certificate :=
  [checked (column true) (selected installLater (by unfold Run.valid; decide) 1)
     (check · true) (by decide +kernel) (sound · true),
   checked (column false) (selected laggingBacked (by unfold Run.valid; decide) 9)
     (check · false) (by decide +kernel) (sound · false)]

end ConsensusCoverage.DeepShortenCases
