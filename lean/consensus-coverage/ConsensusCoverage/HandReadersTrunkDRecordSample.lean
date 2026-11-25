module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkDLeader
import all ConsensusCoverage.HandReadersOtherFoldDirect
import all ConsensusCoverage.HandReadersTrunkCExtension
import all ConsensusCoverage.FollowerFoldCasesB
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
import CCF.Proofs.Finset

namespace ConsensusCoverage.HandReadersTrunkD.Record

open CCF Consensus Model Model.Node Proofs Safety Ledger SolvedWitnesses
set_option maxRecDepth 8192
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private abbrev latched (n : NodeID) (st : NodeState) (i : Nat) :=
  {st with commitIndex := i,retiredCommittedIndex := st.retiredCommittedIndex.orElse fun _ =>
    firstLogIndexAfter (st.log.take i) 0 (fun c => decide (n ∈ c.metadata.retirementConfirmations))}

def Retire (n : NodeID) (st : NodeState) (i : Nat) : Prop :=
  (!st.retiredCommittedIndex.isSome) = true ∧ (latched n st i).isRetiredCommitted n
instance (n st i) : Decidable (Retire n st i) := by unfold Retire; infer_instance

def cut (b : Bool) (n : NodeID) (st : NodeState) (i : Nat) := decide (Retire n st i) == b
abbrev Pick (b : Bool) (n : NodeID) (st : NodeState) :=
  Leader.Growth n st ∧ cut b n st (highestCommittableIndex st n)

private def sigE : Entry := ⟨0,.signature⟩
private def start (n : Nat) : Entry := ⟨0,.transaction 0 {configuration := some {n},retirementConfirmations := {n}}⟩
private def removed : Entry := ⟨0,.transaction 0 {configuration := some ∅}⟩
private def state (l : List Entry) (i : Nat) : NodeState :=
  ⟨.primary,0,l,i,fun _ => 0,fun _ => 0,false,none,false,∅,∅,none⟩

private def middle (n : Nat) (pos : Bool) :=
  state (if pos then [start n,sigE,removed] else [start n,sigE]) 0

private theorem newHigh (n : Nat) (pos : Bool) : 2 ≤ highestCommittableIndex (middle n pos) n := by
  let s := middle n pos
  let p := fun (i : Nat) => s.commitIndex < i ∧ isSignatureAt s.log i = true ∧ termAt s.log i = s.currentTerm ∧
    hasQuorum (s.activeConfigurations.filter (fun cfg => cfg.index ≤ i))
      (s.activeMembers.filter (fun v=> v = n ∨ s.matchIndex v ≥ i))
  letI : DecidablePred p := fun _=>inferInstanceAs (Decidable (_ ∧ _ ∧ _ ∧ _))
  have mem : n ∈ (middle n pos).activeMembers := by
    cases pos <;> simp [middle,state,start,sigE,removed,NodeState.activeMembers,NodeState.activeConfigurations,
      activeConfigurations,configurationHistory,configurationMembers,EntryContent.metadata]
  have singleton : ((middle n pos).activeMembers.filter (fun v => v = n ∨ 2 ≤ (middle n pos).matchIndex v)) ∩ ({n} : Finset Nat) = {n} := by
    apply Finset.ext
    intro v
    simp only [Finset.mem_inter,Finset.mem_filter,Finset.mem_singleton]
    constructor
    · exact And.right
    · rintro rfl; exact ⟨⟨mem,.inl rfl⟩,rfl⟩
  unfold highestCommittableIndex
  apply HandReadersTrunkC.Extension.foldMember p (i := 2)
  · change _ ∧ _ ∧ _ ∧ _
    cases pos
    all_goals
      refine ⟨by change 0 < 2; decide,rfl,rfl,?_⟩
      change hasQuorum ([⟨1,{n}⟩] : List Node.Configuration)
        ((middle n _).activeMembers.filter fun v => v = n ∨ 2 ≤ (middle n _).matchIndex v)
      refine ⟨by simp,List.all_eq_true.mpr ?_⟩
      intro cfg listed; have eq := List.mem_singleton.mp listed; subst cfg
      apply decide_eq_true; unfold hasConfigurationMajority; rw [singleton]; change 1 * 2 > 1; decide
  · cases pos <;> first | change 2 ∈ List.range 3; decide | change 2 ∈ List.range 4; decide

private theorem retiredAt (n : Nat) (l : List Entry) (i : Nat)
    (config : retirementIndexInLog n l = some 3) (first : ∃ rest, l = start n :: rest) (positive : 0 < i) :
    Retire n (state l 0) i := by
  obtain ⟨rest,rfl⟩ := first
  refine ⟨rfl,?_⟩
  obtain ⟨k,rfl⟩ := Nat.exists_eq_succ_of_ne_zero (Nat.ne_of_gt positive)
  unfold NodeState.isRetiredCommitted NodeState.retirement
  dsimp only
  change (match retirementIndexInLog n (start n :: rest) with
    | none => MembershipState.noRetirementObserved | some _ => _) = _
  rw [config]
  simp [state,firstLogIndexAfter,start,EntryContent.metadata]

private theorem removedIndex (n : Nat) :
    retirementIndexInLog n [start n,sigE,removed] = some 3 ∧
    retirementIndexInLog n [start n,sigE,removed,sigE] = some 3 := by
  simp [retirementIndexInLog,configurationHistory,start,sigE,removed,EntryContent.metadata]

theorem sample (n : Nat) (pos : Bool) :
    ∃ m, Pick pos n m ∧ Direct.CommitFrontier m := by
  let m := middle n pos
  have high := newHigh n pos
  have gt : Leader.Growth n m := Nat.lt_of_lt_of_le (by decide : 0 < 2) high
  refine ⟨m,⟨gt,?_⟩,Nat.zero_le _,fun p => (Nat.lt_irrefl _ p).elim⟩
  cases pos
  · have none : retirementIndexInLog n [start n,sigE] = none := rfl
    simp [m,middle,cut,Retire,state,NodeState.isRetiredCommitted,NodeState.retirement,none]
  · exact beq_iff_eq.mpr (decide_eq_true (retiredAt n _ _ (removedIndex n).1 ⟨_,rfl⟩ gt))

private abbrev FoldSite (n : Nat) (k : Nat) (s : NodeState) (i : Nat) :=
  ∃ (head : Entry) (tail : List Entry), (∀ (st : NodeState), ∃ j a b h,
    tail.foldl (fun z e => if e.content.isSignature then
      let w := {z with log := z.log ++ [e]}
      w.recordCommit n (max w.commitIndex (maxCommittableIndexUpTo w.log k)) else {z with log := z.log ++ [e]}) st =
        {st with log := st.log ++ tail,commitIndex := j,retiredCommittedIndex := a,role := b,primaryKnown := h} ∧
    (b = st.role ∨ b = .none) ∧ st.commitIndex ≤ j ∧ j ≤ max st.commitIndex (maxCommittableIndexUpTo (st.log ++ tail) k)) ∧
    ∃ st : NodeState, head.content.isSignature = true ∧ maxCommittableIndexUpTo (st.log ++ [head]) k ≤
      maxCommittableIndexUpTo (st.log ++ [head] ++ tail) k ∧ s = {st with log := st.log ++ [head]} ∧
      i = max st.commitIndex (maxCommittableIndexUpTo (st.log ++ [head]) k)

theorem follower (n k : Nat) (pos : Bool) : ∃ s i, FoldSite n k s i ∧ cut pos n s i := by
  cases pos
  · let st := state [] 0
    refine ⟨{st with log := [sigE]},max st.commitIndex (maxCommittableIndexUpTo [sigE] k),
      ⟨sigE,[],fromLeader_loop n k [],st,rfl,Nat.le_refl _,rfl,rfl⟩,?_⟩
    rfl
  · let st := state [start n,sigE,removed] 1
    refine ⟨{st with log := st.log ++ [sigE]},max st.commitIndex (maxCommittableIndexUpTo (st.log++[sigE]) k),
      ⟨sigE,[],fromLeader_loop n k [],st,rfl,Nat.le_refl _,rfl,rfl⟩,?_⟩
    apply beq_iff_eq.mpr; apply decide_eq_true
    exact retiredAt n _ _ (removedIndex n).2 ⟨_,rfl⟩ (Nat.lt_of_lt_of_le (by decide : 0 < 1) (Nat.le_max_left ..))

end ConsensusCoverage.HandReadersTrunkD.Record
