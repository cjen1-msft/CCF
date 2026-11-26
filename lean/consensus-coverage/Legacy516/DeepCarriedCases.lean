module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.DeepBoundCases
import all ConsensusCoverage.DeepHistoryCases
import all ConsensusCoverage.QueueSamplesA
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.ReadersAtoms
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.DeepCarriedCases

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses
open ReadersAtoms GuardedDomain ActionProfile QueueSamplesA

set_option maxRecDepth 8192

inductive Case where | fresh | backed | contained | agreed | small | large | covered | uncovered

def column : Case → Classes.StepBranch
  | .fresh => .carried_of_chain_certificate_fresh
  | .backed => .carried_of_chain_certificate_backed
  | .contained => .carried_of_chain_agreement_inl
  | .agreed => .carried_of_chain_agreement_inr
  | .small => .agree_or_contained_lt_or_ge_inl
  | .large => .agree_or_contained_lt_or_ge_inr
  | .covered => .core_covered_pos
  | .uncovered => .core_covered_neg

private def guard (k : Case) (commit i : Nat) : Prop :=
  match k with
  | .small => commit ≤ 0
  | .large => 0 < commit
  | .covered => i ≤ commit
  | .uncovered => ¬ i ≤ commit
  | _ => True

private instance (k : Case) (commit i : Nat) : Decidable (guard k commit i) :=
  by cases k <;> unfold guard <;> infer_instance

private def check (s : Step) (k : Case) (e i : Nat) : Bool :=
  (ofXAction s.cfg s.before s.after s.past s.act).any fun x =>
    decide (x.base.pre.role ≠ .primary ∧ x.base.post.role = .primary ∧ e < x.base.post.currentTerm ∧
      guard k x.base.pre.commitIndex i) &&
    ((x.base.before :: x.base.past).flatMap fun a => a.nodes.map (fun p => p.2.log)).any fun l =>
      decide ((e,l.take i) ∈ x.committedBefore ∧ l.take x.base.pre.commitIndex = x.base.pre.log.take x.base.pre.commitIndex) &&
        DeepHistoryCases.oldFacts x l e 0 i

theorem source [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)
    {e : Nat} {p : List Entry} (m : Committed f e p) (lt : e < c.post.currentTerm)
    (elect : ElectStep f t c.actor c.post.currentTerm c.pre.log c.pre.commitIndex) :
    (reach% step_carried_of_chain_certificate_fresh[8]) f t c c.actor c.post.currentTerm c.pre.log c.pre.commitIndex e p := by
  have delta := DeepBoundCases.entered c elect
  have now := delta.2.2
  have active : (reach% step_carried_of_chain_certificate_fresh[8,0,0,0])
      f t c e p c.actor c.post.currentTerm c.pre.log c.pre.commitIndex :=
    ⟨.inl m,now,lt,fun old => delta.1.2 old.2.1⟩
  have before_ : (reach% step_carried_of_chain_certificate_fresh[8,0,0]) f t c e
      c.post.currentTerm c.pre.commitIndex c.actor p c.pre.log :=
    ⟨active,m,.inl m,now,lt⟩
  exact ⟨⟨before_,elect,m,now,lt⟩,lt,elect,m,
    (c.freshCampaign elect).transport (g' := f.logs) (fun _ m => m) (fun _ _ h => h)
      (fun _ _ _ le => le) (fun _ _ _ _ obs _ => .inl obs)⟩

theorem sound (s : Step) (k : Case) (e i : Nat) (passed : check s k e i = true) :
    label s (.step (column k)) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  obtain ⟨x,made,ok⟩ := ofXAction_matches s
  simp only [check,made,Option.any_some,Bool.and_eq_true,decide_eq_true_eq,List.any_eq_true] at passed
  obtain ⟨⟨pre,post,lt,cond⟩,l,_,⟨mem,agree⟩,facts⟩ := passed
  rw [← View.pre_eq ok.1] at pre cond agree
  rw [← View.post_eq ok.1] at post lt
  have won := (Summary.leader c.sum post).resolve_left (fun old => pre old.1)
  have elect := c.wins_elect won
  have m := (X.committed_before ok e (l.take i)).mpr mem
  have f := DeepHistoryCases.oldFacts_sound ok facts
  have chain := c.inv.commitChains e (l.take i) m
  have root := source c m lt elect
  have camp := root.2.2.2.2
  have back : c.pre.commitIndex = 0 ∨ ∃ a p, s.frame.logs.committed a p ∧
      c.pre.log.take c.pre.commitIndex <+: p :=
    (c.elect_backed elect).imp_right fun ⟨a,p,m,_,sub⟩ => ⟨a,p,m,sub⟩
  have sub := c.old_in_new elect m lt
  have high (_ : 0 < c.pre.commitIndex) : ∃ q, c.pre.log.take c.pre.commitIndex <+: q ∧
      (l.take i <+: q ∨ q <+: l.take i) := ⟨_,List.take_prefix _ _,.inl sub⟩
  have low (_ : c.pre.commitIndex ≤ 0) : l.take 0 <+: c.pre.log := by simp
  have carry {l' : List Entry} {t b i' : Nat} (_ : CommitFacts s.frame.logs l' t b i')
      (old : s.frame.logs.committed t (l'.take i')) (earlier : t < c.post.currentTerm)
      (_ : c.pre.commitIndex ≤ b → l'.take b <+: c.pre.log) :=
    c.old_in_new elect old earlier
  have wit := And.intro agree (And.intro (Nat.zero_le c.pre.commitIndex) (Nat.le_refl c.pre.commitIndex))
  have ready : (reach% step_core_covered_pos[8]) _ _ c s.frame.logs c.actor e 0 i
      c.post.currentTerm c.pre.commitIndex c.post.currentTerm c.pre.commitIndex l c.pre.log :=
    Or.inl ⟨e,l.take i,root,f,m,lt,⟨_,wit⟩,wit,agree,wit.2,wit.2.1,wit.2.2,camp,back,lt,
      high,chain,m,rfl,rfl,rfl⟩
  apply (label_true s _).mpr
  apply (sig_iff c _).mpr
  cases k with
  | fresh | backed | contained | agreed =>
    iterate 8 right
    first
    | exact ⟨_,_,_,_,_,_,root,l,e,i,f,m,lt,camp,lt,@carry,back,chain,m⟩
    | exact ⟨_,_,_,_,_,_,root,l,e,0,i,e,l.take i,f,m,chain,Nat.le_refl _,by simp,
        fun m' lt' => c.old_in_new elect m' lt',m,lt,camp,back,lt,@carry,chain,m⟩
    | exact Or.inl ⟨_,_,_,_,_,_,root,l,e,i,f,m,lt,sub,camp,back,lt,high,chain,m⟩
    | exact Or.inl ⟨_,_,_,_,_,_,root,l,e,i,f,m,lt,⟨_,wit⟩,_,wit,agree,wit.2,wit.2.1,
        wit.2.2,camp,back,lt,high,chain,m⟩
  | small | large =>
    have caller : (reach% step_agree_or_contained_lt_or_ge_inl[8]) _ _ c l c.pre.log 0 i c.pre.commitIndex :=
      Or.inl ⟨_,_,_,_,root,e,f,m,lt,camp,back,lt,high,chain,m,rfl⟩
    iterate 8 right
    exact Or.inl ⟨_,_,_,_,_,caller,cond,f.baseLe,camp.frontier,low,high,f.indexLe⟩
  | covered | uncovered =>
    obtain ⟨xs,q,acks⟩ := f.acks
    obtain ⟨ys,q',votes⟩ := camp.voters
    iterate 8 right
    exact ⟨_,_,_,_,_,_,_,_,_,_,_,ready,xs,⟨q,acks⟩,q,acks,ys,⟨q',votes⟩,q',votes,cond,
      f,camp,wit.2.2,fun t a above _ canon => c.inv.later e t _ a m canon above,c.inv.chains,
      lt,Nat.sub_le _ _,agree,wit.2.1⟩

open FrontierRows DeepSchedules in
local macro "carried_at " k:term:arg sc:term:arg offset:num e:num i:num : term =>
  `(checked (column $k) (selected $sc (by unfold Run.valid; decide) $offset)
    (check · $k $e $i) (by decide +kernel) (sound · $k $e $i))

open DeepSchedules in
def certificates : List Certificate :=
  [carried_at .fresh divergent 8 2 2,carried_at .backed divergent 8 2 2,
   carried_at .contained divergent 8 2 2,carried_at .agreed divergent 8 2 2,
   carried_at .small divergent 8 2 2,carried_at .large (threeTerms true) 20 3 3,
   carried_at .covered (threeTerms true) 20 3 3,carried_at .uncovered divergent 8 2 2]

end ConsensusCoverage.DeepCarriedCases
