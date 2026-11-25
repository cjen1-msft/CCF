module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkCExtension
import all ConsensusCoverage.HandReadersTrunkDRecordSample
import all ConsensusCoverage.DelayedNominationSuccessor
import all ConsensusCoverage.Timely
import all Consensus.Proofs.SafetyInvariant
import CCF.Proofs.Finset

namespace ConsensusCoverage.HandReadersTrunkD.Nominate

open CCF Consensus Model Model.Node Proofs Safety Ledger
set_option maxRecDepth 8192
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

def suffix (n k : Nat) (somePeer : Bool) : List Entry :=
  [⟨k,.transaction 0 {retirementConfirmations := {n}}⟩,⟨k,.signature⟩,
    ⟨k,.transaction 0 {configuration := some {n}}⟩,
    ⟨k,.transaction 0 {configuration := some (if somePeer then {n+1} else ∅)}⟩]
abbrev extend (s : NodeState) (l : List Entry) := {s with log := s.log ++ l}
abbrev canon (n : NodeID) (s : NodeState) (p : Bool) := extend s (suffix n s.currentTerm p)

private theorem history (s : NodeState) (n : NodeID) (p : Bool) :
    configurationHistory (canon n s p).log = configurationHistory s.log ++
      [⟨s.log.length+3,{n}⟩,⟨s.log.length+4,if p then {n+1} else ∅⟩] := by
  simp [suffix,configurationHistory,List.zipIdx_append,EntryContent.metadata,Nat.add_comm] <;> omega

private theorem active_append {s : NodeState} {xs : List Entry} (front : s.commitIndex ≤ s.log.length) :
    s.activeConfigurations <+: (extend s xs).activeConfigurations := by
  obtain ⟨rest,eq,later⟩ := configurationHistory_split (s.log++xs) s.log.length
  rw [List.take_append_of_le_length (Nat.le_refl _),List.take_length] at eq
  let h := configurationHistory s.log
  have le : (h.filter (·.index ≤ s.commitIndex)).length - 1 ≤ h.length := by
    have := List.length_filter_le (fun c : Node.Configuration=>decide (c.index ≤ s.commitIndex)) h; omega
  change h.drop _ <+: (configurationHistory (s.log++xs)).drop (((configurationHistory (s.log++xs)).filter (·.index ≤ s.commitIndex)).length - 1)
  rw [eq,filter_index_append front later,List.drop_append_of_le_length le]
  exact List.prefix_append _ _

private theorem active_canon {s : NodeState} (n : NodeID) (p : Bool) (fr : s.commitIndex ≤ s.log.length) :
    (canon n s p).activeConfigurations = s.activeConfigurations ++
      [⟨s.log.length+3,{n}⟩,⟨s.log.length+4,if p then {n+1} else ∅⟩] := by
  unfold NodeState.activeConfigurations activeConfigurations
  rw [history]
  have a : ¬s.log.length+3 ≤ s.commitIndex := by omega
  have b : ¬s.log.length+4 ≤ s.commitIndex := by omega
  dsimp only
  simp only [List.filter_append,List.filter_cons,decide_eq_false a,decide_eq_false b,
    Bool.false_eq_true,ite_false,List.filter_nil,List.append_nil]
  apply List.drop_append_of_le_length
  have := List.length_filter_le (fun c : Node.Configuration=>decide (c.index ≤ s.commitIndex)) (configurationHistory s.log)
  omega

private theorem member_iff {n : Nat} {cs : List Node.Configuration} :
    n ∈ configurationMembers cs ↔ ∃ cfg ∈ cs, n ∈ cfg.nodes := by
  have loop (acc : Finset Nat) (cs : List Node.Configuration) :
      n ∈ cs.foldl (fun a c=>a ∪ c.nodes) acc ↔ n ∈ acc ∨ ∃ cfg ∈ cs, n ∈ cfg.nodes := by
    induction cs generalizing acc with
    | nil => simp
    | cons x xs ih => simp only [List.foldl_cons,ih,Finset.mem_union,List.mem_cons]; grind
  simpa [configurationMembers] using loop ∅ cs

private theorem completed_eq {s : NodeState} (xs : List Entry) (fr : s.commitIndex ≤ s.log.length) :
    (extend s xs).retirementCompletedNodes = s.retirementCompletedNodes := by
  simp [NodeState.retirementCompletedNodes,NodeState.committedLog,List.take_append_of_le_length fr]

private theorem peerMono {s : NodeState} {n v : Nat} (xs : List Entry) (fr : s.commitIndex ≤ s.log.length)
    (mem : v ∈ eligiblePeers s n) : v ∈ eligiblePeers (extend s xs) n := by
  obtain ⟨ne,old⟩ := Finset.mem_erase.mp mem
  apply Finset.mem_erase.mpr; refine ⟨ne,Finset.mem_union.mpr ?_⟩
  rcases Finset.mem_union.mp old with active | done_
  · obtain ⟨cfg,inCfg,member⟩ := member_iff.mp active
    exact .inl (member_iff.mpr ⟨cfg,(active_append fr).subset inCfg,member⟩)
  · exact .inr (completed_eq xs fr ▸ done_)

private theorem successor {s : NodeState} {n : Nat} : (findSuccessor s n).isSome = true ↔
    (eligiblePeers s n).Nonempty := by
  unfold findSuccessor
  let rank (v : Nat) := (s.matchIndex v,latestMembershipIndex s.activeConfigurations v,v)
  let pick (o : Option Nat) (v : Nat) := match o with
    | none => some v | some w => if rankBelow (rank w) (rank v) then some v else o
  have some_ (xs : List Nat) (v : Nat) : (xs.foldl pick (some v)).isSome = true := by
    induction xs generalizing v with
    | nil => rfl
    | cons x xs ih => simp only [List.foldl_cons,pick]; split <;> apply ih
  change ((eligiblePeers s n).sort.foldl pick none).isSome = true ↔ _
  cases ls : (eligiblePeers s n).sort with
  | nil =>
    apply iff_of_false (by change ¬false = true; decide); rintro ⟨v,member⟩
    have h := Finset.mem_sort.mpr member; rw [ls] at h; contradiction
  | cons v xs =>
    exact iff_of_true (some_ xs v) ⟨v,Finset.mem_sort.mp (ls ▸ List.mem_cons_self)⟩

theorem target {s : NodeState} (n : NodeID) (want : Bool) (fr : s.commitIndex ≤ s.log.length)
    (possible : want = false → ¬(eligiblePeers s n).Nonempty) : (findSuccessor (canon n s want) n).isSome = want := by
  cases want
  case true =>
    apply successor.mpr
    refine ⟨n+1,Finset.mem_erase.mpr ⟨Nat.succ_ne_self _,Finset.mem_union.mpr (.inl ?_)⟩⟩
    apply member_iff.mpr
    rw [active_canon _ _ fr]
    exact ⟨_,List.mem_append_right _ (.tail _ (.head _)),Finset.mem_singleton.mpr rfl⟩
  case false =>
    apply Bool.eq_false_iff.mpr; intro yes
    obtain ⟨v,vm⟩ := successor.mp yes
    obtain ⟨diff,either⟩ := Finset.mem_erase.mp vm
    apply possible rfl ⟨v,Finset.mem_erase.mpr ⟨diff,Finset.mem_union.mpr ?_⟩⟩
    rcases Finset.mem_union.mp either with mem | mem
    · obtain ⟨cfg,inList,h⟩ := member_iff.mp mem
      rw [active_canon _ _ fr] at inList
      rcases List.mem_append.mp inList with old | added
      · exact .inl (member_iff.mpr ⟨cfg,old,h⟩)
      · simp only [List.mem_cons,List.not_mem_nil,or_false] at added
        rcases added with rfl | rfl
        · exact (diff (Finset.mem_singleton.mp h)).elim
        · exact (Finset.notMem_empty _ h).elim
    · exact .inr (completed_eq _ fr ▸ mem)

private theorem adjacent {α : Type} (cs : List α) (a b : α) :
    (a,b) ∈ (cs++[a,b]).zip (cs++[a,b]).tail := by
  induction cs with
  | nil => exact .head _
  | cons x xs ih => cases xs <;> exact .tail _ ih

theorem retirement_present (n : NodeID) (s : NodeState) (p : Bool) :
    (retirementIndexInLog n (canon n s p).log).isSome = true := by
  rw [retirementIndexInLog,Option.isSome_map, List.find?_isSome, history]
  refine ⟨_,adjacent _ _ _,decide_eq_true ⟨Finset.mem_singleton.mpr rfl,?_⟩⟩
  cases p <;> simp

abbrev Confirm (n : NodeID) (l : List Entry) := ∃ e ∈ l, n ∈ e.content.metadata.retirementConfirmations

private theorem confirmFirst (n : NodeID) (l : List Entry) :
    (firstLogIndexAfter l 0 (fun c=>decide (n ∈ c.metadata.retirementConfirmations))).isSome = true ↔ Confirm n l := by
  rw [firstLogIndexAfter,Option.isSome_map,List.find?_isSome]
  constructor
  · rintro ⟨⟨e,j⟩,mem,ok⟩
    obtain ⟨_,_,eq⟩ := List.mem_zipIdx mem
    exact ⟨e,eq ▸ List.getElem_mem _,of_decide_eq_true (Bool.and_eq_true_iff.mp ok).2⟩
  · rintro ⟨e,mem,ok⟩
    obtain ⟨i,le,h⟩ := List.mem_iff_getElem.mp mem
    refine ⟨(e,1+i),List.mem_iff_getElem.mpr ⟨i,by simpa,?_⟩,?_⟩
    · simp [List.getElem_zipIdx,h]
    · exact Bool.and_eq_true_iff.mpr ⟨decide_eq_true (by omega),decide_eq_true ok⟩

theorem retire_iff (s : NodeState) (n i : Nat) : (s.recordCommit n i).isRetiredCommitted n ↔
    (retirementIndexInLog n s.log).isSome ∧ (s.retiredCommittedIndex.isSome ∨ Confirm n (s.log.take i)) := by
  unfold NodeState.recordCommit
  dsimp only
  split
  all_goals
    cases found : retirementIndexInLog n s.log <;> cases old : s.retiredCommittedIndex <;>
      simp [NodeState.isRetiredCommitted,NodeState.retirement,found,←confirmFirst]
    all_goals cases conf : firstLogIndexAfter (s.log.take i) 0 (fun content=>decide (n ∈ content.metadata.retirementConfirmations)) <;>
      simp only [Option.isSome_none,Option.isSome_some] <;> grind

end ConsensusCoverage.HandReadersTrunkD.Nominate
