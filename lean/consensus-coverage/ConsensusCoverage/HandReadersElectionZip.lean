module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersElectionOverlap
import all ConsensusCoverage.OverlapInductionB
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersElection.Zip

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety Ledger
open ActionProfile SolvedWitnesses HandReadersA Overlap
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192

def column (cons : Bool) : Classes.StepBranch := if cons then .zipIdx_sorted_log_cons else .zipIdx_sorted_log_nil

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

structure Cut (l r : List Entry) (b d : Nat) where
  k : Nat
  source : (reach% step_activeConfigurations_overlap_le_total_inl[0]) f t c l r b d k ∨
    (reach% step_activeConfigurations_overlap_le_total_inl[3]) f t c l r b d k ∨
    (reach% step_activeConfigurations_overlap_le_total_inl[5]) f t c l r b d k
  eq : l.take k = r.take k
  left : b ≤ k
  right : d ≤ k
  head : (r.take k).take 1 = [Config.GENESIS]

theorem cut {l r b d} (enabled : Enabled c l r b d) : Nonempty (Cut c l r b d) := by
  obtain ⟨s⟩ := Overlap.sufficient c enabled
  have lh := s.left.head s.leftNE
  have rh := s.right.head s.rightNE
  have eq : l.take (max s.pivot 1) = r.take (max s.pivot 1) := by
    rcases Nat.eq_zero_or_pos s.pivot with zero | pos
    · simp only [zero,Nat.zero_max,lh,rh]
    · simpa only [Nat.max_eq_left pos] using s.same
  have head : (r.take (max s.pivot 1)).take 1 = [Config.GENESIS] := by
    rw [List.take_take,Nat.min_eq_left (Nat.le_max_right _ _),rh]
  refine ⟨⟨_,?_,eq,Nat.le_trans s.leftLe (Nat.le_max_left _ _),Nat.le_trans s.rightLe (Nat.le_max_left _ _),head⟩⟩
  rcases s.site with site | site | site
  case' inl => left
  case' inr.inl => right; left
  case' inr.inr => right; right
  all_goals exact ⟨s.pivot,site,s.left,s.right,s.leftNE,s.rightNE,s.same,s.leftLe,s.rightLe,lh,rh,eq,head,rfl⟩

private theorem necessary (cons : Bool) (yes : sig c (column cons)) : Evidence c (fun _ _ _ _ => true) := by
  cases cons
  all_goals repeat' (change _ ∨ _ at yes; rcases yes with yes | yes)
  all_goals
    try (change _ ∧ _ at yes; replace yes := yes.1)
    repeat' (change _ ∨ _ at yes; rcases yes with yes | yes)
  all_goals
    obtain ⟨l,r,b,d,k,⟨j,site,_⟩,_⟩ := yes
    refine ⟨l,r,b,d,Overlap.necessary c (j := j) ?_,rfl⟩
    repeat' first | exact site | exact Or.inl site | apply Or.inr

private theorem sufficient (cons : Bool) (h : Evidence c (fun _ _ _ _ => true)) : sig c (column cons) := by
  obtain ⟨l,r,b,d,enabled,_⟩ := h
  obtain ⟨⟨k,src,eq,bl,dl,head⟩⟩ := cut c enabled
  obtain ⟨ls,hl⟩ := configurationHistory_split l k
  obtain ⟨rs,hr⟩ := configurationHistory_split r k
  let cs := configurationHistory (r.take k)
  have ne := configurationHistory_ne_nil head Config.GENESIS_configured
  have pos := List.length_pos_iff.mpr ne
  have last := Nat.sub_one_lt (Nat.ne_of_gt pos)
  have ready :
      (reach% step_zipIdx_sorted_log_nil[0]) f t c ∨
      (reach% step_zipIdx_sorted_log_nil[3]) f t c ∨
      (reach% step_zipIdx_sorted_log_nil[5]) f t c := by
    rcases src with src | src | src
    case' inl => left
    case' inr.inl => right; left
    case' inr.inr => right; right
    all_goals
      obtain ord | ord := Nat.le_total b d
      case' inl => left
      case' inr => right
      all_goals exact ⟨l,r,b,d,k,src,ls,hl,hl.1,hl.2,rs,hr,hr.1,hr.2,ord,bl,dl,length_filter_le _ _,
        length_filter_le _ _,length_filter_index_mono cs ord,
        Nat.lt_of_le_of_lt (Nat.sub_le_sub_right (length_filter_le _ _) 1) last,
        eq,ne,pos,OverlapInductionB.countFilter,OverlapInductionB.inDrop,last⟩
  cases cons <;> rcases ready with h | h | h
  all_goals
    first
    | left; first | exact h | exact ⟨h,[],by simp⟩
    | iterate 3 right
      left; first | exact h | exact ⟨h,[],by simp⟩
    | iterate 5 right
      left; first | exact h | exact ⟨h,[],by simp⟩
end

def exactReader (cons : Bool) : Exact (column cons) where
  eval := Overlap.reader (fun _ _ _ _ => true)
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    apply Bool.eq_iff_iff.mpr
    rw [Overlap.reader_iff,label_true,holds,sig_iff]
    exact ⟨necessary s.context cons,sufficient s.context cons⟩

end ConsensusCoverage.HandReadersElection.Zip
