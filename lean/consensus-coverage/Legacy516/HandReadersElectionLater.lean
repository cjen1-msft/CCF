module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersElectionCounted
import all ConsensusCoverage.HandReadersElectionZip
import all ConsensusCoverage.HandReadersElectionOverlap
import all ConsensusCoverage.HandReadersElectionPairs
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersElection.Later

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety Ledger
open ActionProfile SolvedWitnesses HandReadersA Overlap Counted
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192

def test : Pairs.Test := fun l _ b i r d =>
  decide (b = 0 ∧ d = 0 ∧ d < i) && (List.range (r.length+1)).any fun j =>
    l.take j == r.take j && (configurationHistory (r.take j)).any fun u => decide (1 < u.index)

private theorem test_iff (l : List Entry) (k b i : Nat) (r : List Entry) (d : Nat) :
    test l k b i r d = true ↔ b = 0 ∧ d = 0 ∧ d < i ∧
      ∃ j, l.take j = r.take j ∧ ∃ u ∈ configurationHistory (r.take j), 1 < u.index := by
  simp only [test,Bool.and_eq_true,decide_eq_true_eq,List.any_eq_true,List.mem_range,Nat.lt_succ_iff,beq_iff_eq]
  constructor
  · rintro ⟨⟨b,d,lt⟩,j,_,eq,next⟩
    exact ⟨b,d,lt,j,eq,next⟩
  · rintro ⟨b,d,lt,j,eq,next⟩
    let m := min r.length j
    have same := congrArg (List.take m) eq
    rw [List.take_take,List.take_take,Nat.min_eq_left (Nat.min_le_right ..)] at same
    have right : r.take m = r.take j := by
      change r.take (min r.length j) = _
      rw [← List.take_take]
      apply List.take_of_length_le
      exact (List.take_sublist j r).length_le
    exact ⟨⟨b,d,lt⟩,m,Nat.min_le_left ..,same,right ▸ next⟩

private theorem short [Config.InitialConfiguration] {l : List Entry} {u : Configuration} (head : l.take 1 = [Config.GENESIS])
    (mem : u ∈ configurationHistory (l.take 1)) : u.index = 1 := by
  rw [head] at mem
  obtain ⟨nodes,is⟩ := Option.isSome_iff_exists.mp Config.GENESIS_configured
  simpa [configurationHistory,is] using congrArg Configuration.index (show u = ⟨1,nodes⟩ by
    simpa [configurationHistory,is] using mem)

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private theorem necessary (h : sig c .chosen_bound_mem_cons_inr) : Pairs.Evidence c test := by
  repeat' (change _ ∨ _ at h; rcases h with h | h)
  all_goals
    obtain ⟨cs,z,site,no,u,mem,head,tail,sorted,_,empty,_,inTail,_⟩ := h
    have rooted : Counted.Sites c cs z := by
      repeat' first | exact site | exact Or.inl site | apply Or.inr
    obtain ⟨l,r,b,d,j,pivot,rfl,rfl,root⟩ := Counted.sourceAt c rooted
    have z : max b d = 0 := Nat.eq_zero_of_not_pos (fun pos => no ((Counted.count_iff root _).mpr pos))
    have hb : b = 0 := by omega
    have hd : d = 0 := by omega
    have above := (List.pairwise_cons.mp sorted).1 u inTail
    have hn : ¬head.index ≤ max b d := fun le => empty (List.length_pos_iff.mpr
      (List.ne_nil_of_mem (List.mem_filter.mpr ⟨List.mem_cons_self,decide_eq_true le⟩)))
    have gap : 1 < u.index := by omega
    have jp : 0 < j := by
      apply Nat.pos_of_ne_zero
      intro zero
      rw [zero,Nat.zero_max] at root mem
      rw [List.take_take,Nat.min_self] at root
      exact (Nat.ne_of_gt gap) (short root mem)
    rw [Nat.max_eq_left jp] at mem
    obtain ⟨⟨k,i,pair,lt,_⟩,eq,_,_⟩ | ⟨_,fixed⟩ := pivot
    · exact ⟨l,k,b,i,r,d,pair,(test_iff ..).mpr ⟨hb,hd,lt,j,eq,u,mem,gap⟩⟩
    · omega

private theorem sufficient (h : Pairs.Evidence c test) : sig c .chosen_bound_mem_cons_inr := by
  obtain ⟨l,k,b,i,r,d,pair,yes⟩ := h
  obtain ⟨rfl,rfl,lt,j,eq,u,mem,gap⟩ := (test_iff ..).mp yes
  have jp : 0 < j := by
    apply Nat.pos_of_ne_zero
    rintro rfl
    simp [configurationHistory] at mem
  obtain ⟨s⟩ := Overlap.seedAt c (l := l) (r := r) (b := 0) (d := 0) (j := j)
    (.inl ⟨⟨k,i,pair,lt,by simp⟩,eq,Nat.zero_le _,Nat.zero_le _⟩)
  obtain ⟨cut,eqk⟩ := Zip.cutAt c s
  rw [Nat.max_eq_left jp] at eqk
  have orig := Counted.originAt c cut
  rw [eqk] at orig
  have head := cut.head
  rw [eqk] at head
  have no : ¬0 < (filt (configurationHistory (r.take j)) 0).length :=
    fun h => (Nat.lt_irrefl 0) ((Counted.count_iff head _).mp h)
  have pos := List.length_pos_iff.mpr (configurationHistory_ne_nil head Config.GENESIS_configured)
  have sorted := configurationHistory_sorted (r.take j)
  let a : Configuration := ⟨1,∅⟩
  have above : u.index ≠ 0 := by omega
  rcases orig with orig | orig | orig
  all_goals
    first
    | left; refine ⟨_,0,orig,no,u,mem,a,[u],?_⟩
    | iterate 3 right
      left; refine ⟨_,0,orig,no,u,mem,a,[u],?_⟩
    | iterate 5 right
      left; refine ⟨_,0,orig,no,u,mem,a,[u],?_⟩
    exact ⟨by simpa [a] using gap,by simp,by simp [a,above],.tail _ (.head _),.head _,sorted,pos⟩
end

def exactReader : Exact .chosen_bound_mem_cons_inr where
  eval := Pairs.reader test
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    apply Bool.eq_iff_iff.mpr
    rw [Pairs.reader_iff,label_true,holds,sig_iff]
    exact ⟨necessary s.context,sufficient s.context⟩

end ConsensusCoverage.HandReadersElection.Later
