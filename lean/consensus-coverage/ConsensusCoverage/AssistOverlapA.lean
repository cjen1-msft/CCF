module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.DeepCarriedCases
import all ConsensusCoverage.DeepHistoryCases
import all ConsensusCoverage.QueueSamplesA
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.AssistOverlapA

open CCF Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open ActionProfile ReadersAtoms GuardedDomain SolvedWitnesses QueueSamplesA
set_option maxRecDepth 8192

structure Origin [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)
    (l r : List Entry) (b d k : Nat) : Prop where
  entered : (reach% step_rooted_overlap_eq_zero_or_pos_inl[5]) f t c l r b d k
  left : Rooted Config.GENESIS l
  right : Rooted Config.GENESIS r
  leftNE : l ≠ []
  rightNE : r ≠ []
  agree : l.take k = r.take k
  leftLe : b ≤ k
  rightLe : d ≤ k

private def check (s : Step) (d e i : Nat) : Bool :=
  (ofXAction s.cfg s.before s.after s.past s.act).any fun x =>
    let pre := x.base.pre
    decide (pre.role ≠ .primary ∧ x.base.post.role = .primary ∧ e < x.base.post.currentTerm ∧
      pre.commitIndex = d ∧ d < i) &&
    ((x.base.before :: x.base.past).flatMap fun a => a.nodes.map (fun p => p.2.log)).any fun l =>
      decide ((e,l.take i) ∈ x.committedBefore ∧ l.take d = pre.log.take d) &&
        DeepHistoryCases.oldFacts x l e 0 i

theorem origin (s : Step) {d e i} (passed : check s d e i = true) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩;
    ∃ l, Origin s.context l s.context.pre.log 0 d d := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  obtain ⟨x,made,ok⟩ := ofXAction_matches s
  simp only [check,made,Option.any_some,Bool.and_eq_true,decide_eq_true_eq,List.any_eq_true] at passed
  obtain ⟨⟨pre,post,lt,dEq,gap⟩,l,_,⟨mem,agree⟩,facts⟩ := passed
  rw [← View.pre_eq ok.1] at pre dEq agree
  rw [← View.post_eq ok.1] at post lt
  subst d
  have elect := c.wins_elect ((Summary.leader c.sum post).resolve_left fun old => pre old.1)
  have m := (X.committed_before ok e (l.take i)).mpr mem
  have f := DeepHistoryCases.oldFacts_sound ok facts
  have root := DeepCarriedCases.source c m lt elect
  have camp := root.2.2.2.2
  have back : c.pre.commitIndex = 0 ∨ ∃ a p, s.frame.logs.committed a p ∧ c.pre.log.take c.pre.commitIndex <+: p :=
    (c.elect_backed elect).imp_right fun ⟨a,p,m,_,sub⟩ => ⟨a,p,m,sub⟩
  have sub := c.old_in_new elect m lt
  have high (_ : 0 < c.pre.commitIndex) : ∃ q, c.pre.log.take c.pre.commitIndex <+: q ∧
      (l.take i <+: q ∨ q <+: l.take i) := ⟨_,List.take_prefix _ _,.inl sub⟩
  have wit := And.intro agree (And.intro (Nat.zero_le c.pre.commitIndex) (Nat.le_refl c.pre.commitIndex))
  have ready : (reach% step_core_covered_pos[8]) _ _ c s.frame.logs c.actor e 0 i
      c.post.currentTerm c.pre.commitIndex c.post.currentTerm c.pre.commitIndex l c.pre.log :=
    Or.inl ⟨e,l.take i,root,f,m,lt,⟨_,wit⟩,wit,agree,wit.2,wit.2.1,wit.2.2,camp,back,lt,
      high,c.inv.commitChains _ _ m,m,rfl,rfl,rfl⟩
  obtain ⟨xs,q,acks⟩ := f.acks
  obtain ⟨ys,q',votes⟩ := camp.voters
  have clean := fun t a above (_ : t ≤ c.post.currentTerm) canon => c.inv.later e t _ a m canon above
  have before : (reach% step_rooted_overlap_eq_zero_or_pos_inl[5,0]) _ _ c l c.pre.log
      0 c.pre.commitIndex c.pre.commitIndex i xs ys := by
    right; right; right
    exact ⟨_,_,_,_,_,ready,⟨q,acks⟩,q,acks,⟨q',votes⟩,q',votes,Nat.not_le_of_lt gap,
      f,camp,agree,wit.2.1,wit.2.2,clean,c.inv.chains,lt,Nat.sub_le _ _⟩
  have nonempty : l ≠ [] := by
    intro nil
    have h := f.indexLe
    rw [nil] at h
    simp at h
    omega
  have rightNE := hasQuorum_nonempty q'
  refine ⟨l, ⟨.inl ⟨i,xs,ys,before,f.rooted,camp.rooted,agree,wit.2.1,wit.2.2,f.baseLe,
    Nat.le_of_lt gap,q,q',nonempty,signature_pos f.signature⟩,f.rooted,camp.rooted,nonempty,
    rightNE,agree,wit.2.1,wit.2.2⟩⟩

def zeroStep : Step := (selected DeepSchedules.divergent (by unfold FrontierRows.Run.valid; decide) 8).get
  (by decide +kernel)

def positiveStep : Step := (selected (DeepSchedules.threeTerms false) (by unfold FrontierRows.Run.valid; decide) 18).get
  (by decide +kernel)

theorem zeroOrigin :
    letI : Config.InitialConfiguration := ⟨zeroStep.cfg⟩
    ∃ l, Origin zeroStep.context l zeroStep.context.pre.log 0 0 0 :=
  origin zeroStep (e := 2) (i := 2) (by decide +kernel)

theorem positiveOrigin :
    letI : Config.InitialConfiguration := ⟨positiveStep.cfg⟩
    ∃ l, Origin positiveStep.context l positiveStep.context.pre.log 0 2 2 :=
  origin positiveStep (e := 3) (i := 3) (by decide +kernel)

private theorem heads [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}
    {l r b d k} (o : Origin c l r b d k) :
    l.take (max k 1) = r.take (max k 1) ∧ (r.take (max k 1)).take 1 = [Config.GENESIS] := by
  have lh := o.left.head o.leftNE
  have rh := o.right.head o.rightNE
  constructor
  · rcases Nat.eq_zero_or_pos k with h | h
    · simp [h,lh,rh]
    · simpa only [Nat.max_eq_left h] using o.agree
  · rw [List.take_take,Nat.min_eq_left (Nat.le_max_right _ _),rh]

private theorem zeroCases [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}
    {l r} (o : Origin c l r 0 0 0) :
    sig c .rooted_overlap_eq_zero_or_pos_inl ∧ sig c .rooted_overlap_bound_inr := by
  have ⟨same,root⟩ := heads o
  have lh := o.left.head o.leftNE
  have rh := o.right.head o.rightNE
  obtain ⟨u,a,b,h⟩ := activeConfigurations_overlap same (Nat.le_trans o.leftLe (Nat.le_max_left _ _))
    (Nat.le_trans o.rightLe (Nat.le_max_left _ _)) (configurationHistory_ne_nil root Config.GENESIS_configured)
  have first : ∀ v, v ∈ configurationHistory (r.take (max 0 1)) → u.index ≤ v.index :=
    h.elim (fun le _ _ => Nat.le_trans le (Nat.zero_le _)) id
  constructor <;> (iterate 5 right) <;> left
  · exact ⟨_,_,_,_,o.entered,o.agree,o.leftLe,o.rightLe,root,o.left,o.right,o.leftNE,o.rightNE,lh,rh⟩
  · exact ⟨_,_,_,_,_,o.entered,u,⟨a,b,h⟩,a,⟨b,h⟩,b,h,first,o.right,o.rightNE,o.agree,
      o.leftLe,o.rightLe,rh,same,root,o.left,o.leftNE,lh⟩

private theorem positiveCases [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}
    {l r} (o : Origin c l r 0 2 2) :
    sig c .rooted_overlap_eq_zero_or_pos_inr ∧ sig c .rooted_overlap_bound_inl := by
  have ⟨same,root⟩ := heads o
  have lh := o.left.head o.leftNE
  have rh := o.right.head o.rightNE
  obtain ⟨u,a,b,within⟩ := rooted_overlap Config.GENESIS_configured o.left o.right o.leftNE o.rightNE
    o.agree o.leftLe o.rightLe
  have h : u.index ≤ max 0 2 ∨ ∀ v, v ∈ configurationHistory (r.take (max 2 1)) →
      u.index ≤ v.index := .inl within
  constructor <;> (iterate 5 right) <;> left
  · exact ⟨_,_,_,_,_,o.entered,by decide,o.agree,o.leftLe,o.rightLe,root,o.left,o.right,o.leftNE,o.rightNE,lh,rh⟩
  · exact ⟨_,_,_,_,_,o.entered,u,⟨a,b,h⟩,a,⟨b,h⟩,b,h,within,o.leftLe,o.rightLe,
      o.left,o.right,o.leftNE,o.rightNE,o.agree,lh,rh,same,root⟩

private theorem zeroLabels :
    label zeroStep (.step .rooted_overlap_eq_zero_or_pos_inl) = true ∧
    label zeroStep (.step .rooted_overlap_bound_inr) = true := by
  letI : Config.InitialConfiguration := ⟨zeroStep.cfg⟩
  obtain ⟨l,o⟩ := zeroOrigin
  have ⟨a,b⟩ := zeroCases o
  exact ⟨(label_true _ _).mpr ((sig_iff _ _).mpr a),(label_true _ _).mpr ((sig_iff _ _).mpr b)⟩

private theorem positiveLabels :
    label positiveStep (.step .rooted_overlap_eq_zero_or_pos_inr) = true ∧
    label positiveStep (.step .rooted_overlap_bound_inl) = true := by
  letI : Config.InitialConfiguration := ⟨positiveStep.cfg⟩
  obtain ⟨l,o⟩ := positiveOrigin
  have ⟨a,b⟩ := positiveCases o
  exact ⟨(label_true _ _).mpr ((sig_iff _ _).mpr a),(label_true _ _).mpr ((sig_iff _ _).mpr b)⟩

def certificates : List Certificate :=
  [⟨_,zeroStep,zeroLabels.1⟩,⟨_,positiveStep,positiveLabels.1⟩,
   ⟨_,positiveStep,positiveLabels.2⟩,⟨_,zeroStep,zeroLabels.2⟩]

end ConsensusCoverage.AssistOverlapA
