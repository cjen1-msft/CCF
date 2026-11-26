module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersElectionRank
import all ConsensusCoverage.HandReadersElectionRankSites
import all ConsensusCoverage.HandReadersElectionMonoSites
import all ConsensusCoverage.HandReadersACampaign
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersElection.Mono

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety Ledger
open ActionProfile SolvedWitnesses HandReadersA ReadersAtoms
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192

inductive Kind where | positive | equal | short
def column : Kind → Classes.StepBranch
  | .positive => .termAt_mono_eq_zero_or_pos_inr
  | .equal => .termAt_mono_eq_or_lt_of_le_inl
  | .short => .termAt_mono_eq_or_lt_of_le_inr

def pick (kind : Kind) (st : NodeState) (i : Nat) : Bool :=
  match kind with
  | .positive => true
  | .equal => i == maxCommittableIndex st.log
  | .short => decide (i < maxCommittableIndex st.log)

def useCampaign : Kind → Bool | .short => false | _ => true

def reader (kind : Kind) : Reader := fun cfg before act after past =>
  (ofXAction cfg before after past act).any (fun x =>
    Rank.view .ahead x (pick kind) || Rank.view .tied x (pick kind)) ||
  (useCampaign kind && CampaignRows.reader true true cfg before act after past &&
    actorRead (fun _ pre _ _ => decide (0 < maxCommittableIndex pre.log)) cfg before act after past)

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

abbrev Result (kind : Kind) :=
  (Rank.Selected c .ahead (pick kind) ∨ Rank.Selected c .tied (pick kind)) ∨
  (useCampaign kind = true ∧ MonoSites.Campaign c) ∧ 0 < maxCommittableIndex c.pre.log

private theorem evidence {l i j} (kind : Kind) (site : MonoSites.Sites c l i j) (pos : 0 < i)
    (selected : ∀ st, j = maxCommittableIndex st.log → pick kind st i = true)
    (camp : j = i → useCampaign kind = true) : Result c kind := by
  obtain ⟨v,n,term,r,k,l',st,w,input,m,m',le,termEq,vote,up,sub,_,maxIdx⟩ | ⟨src,_,idx,eq⟩ :=
    MonoSites.necessary c site
  · have pass := selected st maxIdx
    rcases up with ahead | tied
    · exact .inl (.inl ⟨v,n,term,r,k,l',i,st,w,input,m,m',le,termEq,vote,sub,decide_eq_true ahead,pass⟩)
    · exact .inl (.inr ⟨v,n,term,r,k,l',i,st,w,input,m,m',le,termEq,vote,sub,
        by simpa only [Rank.cut,Bool.and_eq_true,beq_iff_eq,decide_eq_true_eq] using tied,pass⟩)
  · exact .inr ⟨⟨camp eq,src⟩,idx ▸ pos⟩

private theorem necessary (kind : Kind) (h : sig c (column kind)) : Result c kind := by
  cases kind
  all_goals repeat' (change _ ∨ _ at h; rcases h with h | h)
  all_goals
    first
    | obtain ⟨l,i,j,src,pos,rest⟩ := h
      refine evidence c _ (l := l) (j := j) ?_ pos ?_ ?_
    | obtain ⟨l,i,src,pos,rest⟩ := h
      refine evidence c _ (l := l) (j := i) ?_ pos ?_ ?_
    · repeat' first | exact src | exact Or.inl src | apply Or.inr
    · intro st eq
      first | rfl | exact beq_iff_eq.mpr eq | exact decide_eq_true (eq ▸ rest.1)
    · intro eq
      first | rfl | exact (Nat.lt_irrefl _ (eq ▸ rest.1)).elim

private theorem rank_case {rk : Rank.Kind} (kind : Kind) (h : Rank.Selected c rk (pick kind)) :
    sig c (column kind) := by
  obtain ⟨v,n,term,r,k,l,i,st,post,input,pre,now,le,termEq,vote,sub,guard,pass⟩ := h
  have which := RankSites.sufficient c input
  obtain ⟨_,hit,_,seen,_,signed,atI⟩ := input
  have up := Rank.cut_up rk guard
  have edge := And.intro pre (And.intro now (And.intro le (And.intro termEq (And.intro vote up))))
  have kept := isSignatureAt_of_prefix sub (isSignatureAt_take_of_le Nat.le.refl signed)
  have within := Nat.le_of_eq (List.length_take_of_le (signature_bound signed)).symm
  have bound := signatureIndex_le_maxCommittableIndex kept
  have pos := signature_pos signed
  have mb := maxCommittableIndexBounded st.log
  have so := c.inv.sorted v st pre
  have src : (reach% step_termAt_mono_eq_zero_or_pos_inr[0]) f t c st.log i (maxCommittableIndex st.log) ∨
      (reach% step_termAt_mono_eq_zero_or_pos_inr[1]) f t c st.log i (maxCommittableIndex st.log) := by
    rcases which with root | root
    case' inl => left
    case' inr => right; left
    all_goals exact ⟨v,n,term,r,k,l,root,st,⟨post,edge⟩,post,edge,pre,edge.2,now,edge.2.2,le,edge.2.2.2,
      termEq,⟨vote,up⟩,vote,up,sub,seen,signed,atI,within,kept,bound,hit,rfl,rfl⟩
  cases kind <;> rcases src with site | site
  all_goals
    first
    | left; first | refine ⟨_,_,_,site,?_⟩ | refine ⟨_,_,(beq_iff_eq.mp pass).symm ▸ site,?_⟩
    | right; left; first | refine ⟨_,_,_,site,?_⟩ | refine ⟨_,_,(beq_iff_eq.mp pass).symm ▸ site,?_⟩
    first | exact ⟨pos,bound,mb,so⟩ | exact ⟨pos,of_decide_eq_true pass,bound,mb,so⟩
          | exact ⟨pos,Nat.le_refl _,(beq_iff_eq.mp pass).symm ▸ mb,so⟩

private theorem sufficient (kind : Kind) (h : Result c kind) : sig c (column kind) := by
  rcases h with (rank | rank) | ⟨⟨byCampaign,campaign⟩,pos⟩
  · exact rank_case c kind rank
  · exact rank_case c kind rank
  · have sites := MonoSites.campaign_site c campaign
    cases kind <;> try cases byCampaign
    all_goals rcases sites with site | site
    all_goals
      first
      | iterate 11 right
        left; first | refine ⟨_,_,_,site,?_⟩ | refine ⟨_,_,site,?_⟩
      | iterate 12 right
        left; first | refine ⟨_,_,_,site,?_⟩ | refine ⟨_,_,site,?_⟩
      exact ⟨pos,Nat.le_refl _,maxCommittableIndexBounded _,c.pre_sorted⟩
end

def exactReader (kind : Kind) : Exact (column kind) where
  eval := reader kind
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    obtain ⟨x,made,ok⟩ := ofXAction_matches s
    have camp := Bool.eq_iff_iff.mp ((CampaignRows.exactReader true true).eq_label s)
    rw [label_true,holds,sig_iff] at camp
    change MonoSites.Campaign s.context ↔ CampaignRows.reader true true s.cfg s.before s.act s.after s.past = true at camp
    apply Bool.eq_iff_iff.mpr
    simp only [reader,made,Option.any_some,Bool.and_eq_true,Bool.or_eq_true,Rank.selected_iff s.context ok,
      ← camp,actorRead_at,decide_eq_true_eq,label_true,holds,sig_iff]
    exact ⟨necessary s.context kind,sufficient s.context kind⟩

end ConsensusCoverage.HandReadersElection.Mono
