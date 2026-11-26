module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersElectionCounted
import all ConsensusCoverage.HandReadersElectionOverlap
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersElection.Chosen

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety Ledger
open ActionProfile SolvedWitnesses HandReadersA Overlap Counted
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192

inductive Kind where | counted | none | head

def column : Kind → Classes.StepBranch
  | .counted => .chosen_bound_counted_pos
  | .none => .chosen_bound_counted_neg
  | .head => .chosen_bound_mem_cons_inl

def pos : Kind → Bool | .counted => true | _ => false

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private theorem iff_count (kind : Kind) : sig c (column kind) ↔ Evidence c (test (pos kind)) := by
  constructor
  · intro h
    cases kind
    all_goals repeat' (change _ ∨ _ at h; rcases h with h | h)
    all_goals
      obtain ⟨cs,z,site,guard,_⟩ := h
      apply Counted.necessary c (cs := cs) (z := z)
      · repeat' first | exact site | exact Or.inl site | apply Or.inr
      · first | exact decide_eq_true guard | exact decide_eq_false guard
  · intro h
    obtain ⟨cs,z,site,sorted,posLen,guard,_⟩ := Counted.sufficient c h
    cases kind <;> rcases site with site | site | site
    all_goals
      first | left; refine ⟨cs,z,site,?_⟩
            | iterate 3 right
              left; refine ⟨cs,z,site,?_⟩
            | iterate 5 right
              left; refine ⟨cs,z,site,?_⟩
      first
      | exact ⟨of_decide_eq_true guard,sorted,posLen⟩
      | exact ⟨of_decide_eq_false guard,sorted,posLen⟩
      | have no := of_decide_eq_false guard
        obtain ⟨u,mem⟩ := List.exists_mem_of_ne_nil _ (List.length_pos_iff.mp posLen)
        have out : ¬u.index ≤ z := fun le => no (List.length_pos_iff.mpr
          (List.ne_nil_of_mem (List.mem_filter.mpr ⟨mem,decide_eq_true le⟩)))
        exact ⟨no,u,mem,[],by simp,by simp,by simp [out],.head _,sorted,posLen⟩
end

def exactReader (kind : Kind) : Exact (column kind) where
  eval := Overlap.reader (test (pos kind))
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    apply Bool.eq_iff_iff.mpr
    rw [Overlap.reader_iff,label_true,holds,sig_iff]
    exact iff_count s.context kind

end ConsensusCoverage.HandReadersElection.Chosen
