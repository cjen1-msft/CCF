module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.AssistOverlapA
import all ConsensusCoverage.DeepBoundCases
import all ConsensusCoverage.DeepCarriedCases
import all ConsensusCoverage.DeepHistoryCases
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.ConfiguredOverlapB

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses

set_option maxRecDepth 8192

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} {c : Ctx f t}
  {l : List Entry} {e i k : Nat}

structure History (c : Ctx f t) (l r : List Entry) (a b k : Nat) : Prop where
  ordinary : AssistOverlapA.Origin c l r a b k
  configured : (reach% step_activeConfigurations_overlap_chosen_bound_inr[5,0]) f t c l r a b k
    ordinary.right ordinary.rightNE

theorem origin (elect : ElectStep f t c.actor c.post.currentTerm c.pre.log c.pre.commitIndex)
    (lt : e < c.post.currentTerm) (m : Committed f e (l.take i)) (facts : CommitFacts f.logs l e 0 i)
    (gap : c.pre.commitIndex < i) (agree : l.take k = c.pre.log.take k) (covers : c.pre.commitIndex ≤ k) :
    History c l c.pre.log 0 c.pre.commitIndex k := by
  have root := DeepCarriedCases.source c m lt elect
  have camp := root.2.2.2.2
  have back : c.pre.commitIndex = 0 ∨ ∃ a p, f.logs.committed a p ∧ c.pre.log.take c.pre.commitIndex <+: p :=
    (c.elect_backed elect).imp_right fun ⟨a,p,m,_,sub⟩ => ⟨a,p,m,sub⟩
  have sub := c.old_in_new elect m lt
  have high (_ : 0 < c.pre.commitIndex) : ∃ q, c.pre.log.take c.pre.commitIndex <+: q ∧
      (l.take i <+: q ∨ q <+: l.take i) := ⟨_,List.take_prefix _ _,.inl sub⟩
  have wit := And.intro agree (And.intro (Nat.zero_le k) covers)
  have chain := c.inv.commitChains _ _ m
  have delta := DeepBoundCases.entered c elect
  have after_ := delta.2.2
  have entry : (reach% step_activeConfigurations_overlap_chosen_bound_inr[5,0,0,3,0,0,0])
      f t c c e c.post.currentTerm c.pre.commitIndex c.actor (l.take i) c.pre.log :=
    ⟨⟨.inl m,after_,lt,fun old => delta.1.2 old.2.1,rfl⟩,m,.inl m,after_,lt,rfl⟩
  have campRoot : (reach% step_activeConfigurations_overlap_chosen_bound_inr[5,0,0,3,0])
      f t c c.actor c.post.currentTerm c.pre.log c.pre.commitIndex e (l.take i) camp :=
    ⟨elect,⟨entry,elect,m,after_,lt,rfl,HEq.rfl⟩,lt,m,camp,HEq.rfl⟩
  have ready : (reach% step_core_covered_pos[8]) f t c f.logs c.actor e 0 i
      c.post.currentTerm c.pre.commitIndex c.post.currentTerm k l c.pre.log :=
    Or.inl ⟨e,l.take i,root,facts,m,lt,⟨k,wit⟩,wit,agree,wit.2,wit.2.1,covers,camp,back,lt,
      high,chain,m,rfl,rfl,rfl⟩
  have sensitive : (reach% step_activeConfigurations_overlap_chosen_bound_inr[5,0,0,3]) f t c f.logs
      c.actor e 0 i c.post.currentTerm c.pre.commitIndex c.post.currentTerm k l c.pre.log camp :=
    Or.inl ⟨e,l.take i,camp,campRoot,facts,m,lt,⟨k,wit⟩,wit,agree,wit.2,wit.2.1,covers,
      back,lt,high,chain,m,rfl,rfl,rfl,HEq.rfl⟩
  obtain ⟨xs,q,acks⟩ := facts.acks
  obtain ⟨ys,q',votes⟩ := camp.voters
  have clean := fun t a above (_ : t ≤ c.post.currentTerm) canon => c.inv.later e t _ a m canon above
  have before : (reach% step_rooted_overlap_eq_zero_or_pos_inl[5,0]) f t c l c.pre.log
      0 c.pre.commitIndex k i xs ys := by
    right; right; right
    exact ⟨_,_,_,_,_,ready,⟨q,acks⟩,q,acks,⟨q',votes⟩,q',votes,Nat.not_le_of_lt gap,
      facts,camp,agree,wit.2.1,covers,clean,c.inv.chains,lt,Nat.sub_le _ _⟩
  have retained : (reach% step_activeConfigurations_overlap_chosen_bound_inr[5,0,0]) f t c l c.pre.log
      0 c.pre.commitIndex k i camp.rooted xs ys q' := by
    right; right; right
    exact ⟨_,_,_,_,_,camp,sensitive,⟨q,acks⟩,q,acks,⟨q',votes⟩,q',votes,Nat.not_le_of_lt gap,
      c.inv.chains,facts,lt,Nat.sub_le _ _,agree,wit.2.1,covers,clean,HEq.rfl,HEq.rfl⟩
  have nonempty : l ≠ [] := by
    intro nil
    have h := facts.indexLe
    rw [nil] at h
    simp at h
    omega
  have rightNE := hasQuorum_nonempty q'
  have ipos := signature_pos facts.signature
  exact ⟨⟨.inl ⟨i,xs,ys,before,facts.rooted,camp.rooted,agree,wit.2.1,covers,facts.baseLe,
    Nat.le_of_lt gap,q,q',nonempty,ipos⟩,facts.rooted,camp.rooted,nonempty,rightNE,agree,wit.2.1,covers⟩,
    .inl ⟨i,camp.rooted,xs,ys,q',retained,facts.rooted,agree,wit.2.1,covers,facts.baseLe,Nat.le_of_lt gap,
      q,nonempty,ipos,HEq.rfl,HEq.rfl⟩⟩

end
end ConsensusCoverage.ConfiguredOverlapB
