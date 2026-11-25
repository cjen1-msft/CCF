module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ActionProfile
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersElection.Tables

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open ActionProfile SolvedWitnesses

private abbrev EntryPair := NodeID × NodeState

private theorem findHead (xs : List EntryPair) (v : NodeID) (st : NodeState) :
    (∃ hd tl, ((tl.map Prod.fst).Nodup → (v,st) ∈ tl → tl.find? (fun p => p.1 == v) = some (v,st)) ∧
      ((hd :: tl).map Prod.fst).Nodup ∧ (v,st) ∈ hd :: tl ∧
      ∃ value, (((v,value) :: tl).map Prod.fst).Nodup ∧ (v,st) ∈ (v,value) :: tl ∧
      (v,st) ∈ xs ∧ (xs.map Prod.fst).Nodup) ↔ (v,st) ∈ xs ∧ (xs.map Prod.fst).Nodup := by
  constructor
  · rintro ⟨_,_,_,_,_,_,_,_,h⟩; exact h
  · rintro h
    exact ⟨(v,st),[],by simp,by simp,by simp,st,by simp,by simp,h⟩

private theorem findTail (xs : List EntryPair) (v : NodeID) (st : NodeState) :
    (∃ hd tl, ((tl.map Prod.fst).Nodup → (v,st) ∈ tl → tl.find? (fun p => p.1 == v) = some (v,st)) ∧
      ((hd :: tl).map Prod.fst).Nodup ∧ (v,st) ∈ hd :: tl ∧
      ∃ key value, (((key,value) :: tl).map Prod.fst).Nodup ∧ (v,st) ∈ (key,value) :: tl ∧
      ¬key = v ∧ (v,st) ∈ xs ∧ (xs.map Prod.fst).Nodup) ↔ (v,st) ∈ xs ∧ (xs.map Prod.fst).Nodup := by
  constructor
  · rintro ⟨_,_,_,_,_,_,_,_,_,_,h⟩; exact h
  · rintro h
    exact ⟨(v+1,st),[(v,st)],by simp,by simp,by simp,v+1,st,by simp,by simp,Nat.succ_ne_self _,h⟩

private theorem equalHead (v : NodeID) (st : NodeState) : ∃ p : EntryPair, p.1 = v := ⟨(v,st),rfl⟩
private theorem otherHead (v : NodeID) (st : NodeState) : ∃ p : EntryPair, ¬p.1 = v := ⟨(v+1,st),Nat.succ_ne_self _⟩

public theorem find_arms_eq (s : Step) :
    label s (.step .find_of_mem_here_pos) = label s (.step .find_of_mem_here_neg) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  apply Bool.eq_iff_iff.mpr
  simp only [label_true,holds,sig_iff]
  change step_find_of_mem_here_pos _ _ _ ↔ step_find_of_mem_here_neg _ _ _
  simp only [step_find_of_mem_here_pos,step_find_of_mem_here_neg,findHead,findTail]

public theorem replace_arms_eq (s : Step) :
    label s (.step .replaceNode_keys_here_pos) = label s (.step .replaceNode_keys_here_neg) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  apply Bool.eq_iff_iff.mpr
  simp only [label_true,holds,sig_iff]
  change step_replaceNode_keys_here_pos _ _ _ ↔ step_replaceNode_keys_here_neg _ _ _
  have yes (v : NodeID) := equalHead v s.context.pre
  have no (v : NodeID) := otherHead v s.context.pre
  simp only [step_replaceNode_keys_here_pos,step_replaceNode_keys_here_neg,yes,no,and_true]

end ConsensusCoverage.HandReadersElection.Tables
