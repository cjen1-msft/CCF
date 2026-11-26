module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersElectionCounted
import all ConsensusCoverage.HandReadersElectionOverlap
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersElection.Filter

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety Ledger
open ActionProfile SolvedWitnesses HandReadersA Overlap Counted
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192

def column (zero : Bool) : Classes.StepBranch := if zero then .getElem_le_of_lt_length_filter_i_inl
  else .getElem_le_of_lt_length_filter_i_inr

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private theorem iff_pos (zero : Bool) : sig c (column zero) ↔ Evidence c (test true) := by
  constructor
  · intro h
    cases zero
    all_goals repeat' (change _ ∨ _ at h; rcases h with h | h)
    all_goals
      obtain ⟨cs,z,_,⟨site,pos,_⟩,_⟩ := h
      refine Counted.necessary c (cs := cs) (z := z) ?_ true (decide_eq_true pos)
      repeat' first | exact site | exact Or.inl site | apply Or.inr
  · intro h
    obtain ⟨cs,z,site,sorted,pos,yes,gap⟩ := Counted.sufficient c h
    let i := (filt cs z).length - 1
    have counted := of_decide_eq_true yes
    have sub : i < (filt cs z).length := Nat.sub_one_lt (Nat.ne_of_gt counted)
    let a : Configuration := ⟨0,∅⟩
    let b : Configuration := ⟨1,∅⟩
    have one : 1 ≤ z := gap rfl
    have shape : filt [a,b] z = [a,b] := by simp [filt,a,b,one]
    have tail : filt [b] z = [b] := by simp [filt,b,one]
    have pair : [a,b].Pairwise (fun x y => x.index < y.index) := by decide
    cases zero <;> rcases site with site | site | site
    all_goals
      first
      | left; refine ⟨cs,z,i,⟨site,counted,sorted,pos,rfl⟩,?_⟩
      | iterate 3 right
        left; refine ⟨cs,z,i,⟨site,counted,sorted,pos,rfl⟩,?_⟩
      | iterate 5 right
        left; refine ⟨cs,z,i,⟨site,counted,sorted,pos,rfl⟩,?_⟩
      first
      | refine ⟨a,[b],fun so _ lt => getElem_le_of_lt_length_filter so lt,pair,0,?_,Nat.zero_le _,?_,?_,sub,sorted⟩
      | refine ⟨a,[b],fun so _ lt => getElem_le_of_lt_length_filter so lt,pair,1,?_,Nat.zero_le _,0,?_,?_,sub,sorted⟩
      all_goals first
        | change _ < (filt [a,b] z).length; simp [shape]
        | change _ < (a :: filt [b] z).length; simp [tail]
end

def exactReader (zero : Bool) : Exact (column zero) where
  eval := Overlap.reader (test true)
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    apply Bool.eq_iff_iff.mpr
    rw [Overlap.reader_iff,label_true,holds,sig_iff]
    exact iff_pos s.context zero

end ConsensusCoverage.HandReadersElection.Filter
