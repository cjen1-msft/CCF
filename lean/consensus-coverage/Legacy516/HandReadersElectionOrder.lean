module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersElectionOverlap
import all ConsensusCoverage.HandReadersElectionZip
import all ConsensusCoverage.OverlapInductionB
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersElection.Order

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety Ledger
open ActionProfile SolvedWitnesses HandReadersA Overlap
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192

def column (forward : Bool) : Classes.StepBranch := if forward then .activeConfigurations_overlap_le_total_inl
  else .activeConfigurations_overlap_le_total_inr

def test (forward : Bool) : Test := fun _ _ b d => if forward then decide (b ≤ d) else decide (d ≤ b)

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private theorem necessary (forward : Bool) (h : sig c (column forward)) : Evidence c (test forward) := by
  cases forward
  all_goals repeat' (change _ ∨ _ at h; rcases h with h | h)
  all_goals
    obtain ⟨l,r,b,d,k,⟨j,site,_⟩,_,_,_,_,_,_,_,_,order,_⟩ := h
    refine ⟨l,r,b,d,Overlap.necessary c (j := j) ?_,decide_eq_true order⟩
    repeat' first | exact site | exact Or.inl site | apply Or.inr

private theorem sufficient (forward : Bool) (h : Evidence c (test forward)) : sig c (column forward) := by
  obtain ⟨l,r,b,d,enabled,guard⟩ := h
  obtain ⟨⟨k,src,eq,bl,dl,head⟩⟩ := Zip.cut c enabled
  obtain ⟨ls,hl⟩ := configurationHistory_split l k
  obtain ⟨rs,hr⟩ := configurationHistory_split r k
  have ne := configurationHistory_ne_nil head Config.GENESIS_configured
  have pos := List.length_pos_iff.mpr ne
  cases forward <;> rcases src with src | src | src
  all_goals
    first
    | left; refine ⟨l,r,b,d,k,src,?_⟩
    | iterate 3 right
      left; refine ⟨l,r,b,d,k,src,?_⟩
    | iterate 5 right
      left; refine ⟨l,r,b,d,k,src,?_⟩
    exact ⟨ls,hl,hl.1,hl.2,rs,hr,hr.1,hr.2,of_decide_eq_true guard,bl,dl,length_filter_le _ _,
      length_filter_le _ _,eq,ne,configurationHistory_sorted _,pos,OverlapInductionB.countFilter,
      OverlapInductionB.inDrop,Nat.sub_one_lt (Nat.ne_of_gt pos)⟩
end

def exactReader (forward : Bool) : Exact (column forward) where
  eval := Overlap.reader (test forward)
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    apply Bool.eq_iff_iff.mpr
    rw [Overlap.reader_iff,label_true,holds,sig_iff]
    exact ⟨necessary s.context forward,sufficient s.context forward⟩

end ConsensusCoverage.HandReadersElection.Order
