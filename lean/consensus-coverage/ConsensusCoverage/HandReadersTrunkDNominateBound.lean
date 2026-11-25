module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkDNominateLog
import all ConsensusCoverage.HandReadersTrunkDLeader
import all ConsensusCoverage.HandReadersTrunkCExtension
import all ConsensusCoverage.DelayedNominationSuccessor
import all ConsensusCoverage.Timely
import all Consensus.Proofs.SafetyInvariant
import CCF.Proofs.Finset

namespace ConsensusCoverage.HandReadersTrunkD.Nominate

open CCF Consensus Model Model.Node Proofs Safety Ledger HandReadersTrunkC
set_option maxRecDepth 8192
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private abbrev high (n : Nat) (m : NodeState) := highestCommittableIndex m n
abbrev Pick (p : Bool) (n : Nat) (m : NodeState) :=
  Leader.Growth n m ∧ (m.recordCommit n (high n m)).isRetiredCommitted n ∧ m.role = .primary ∧
    (findSuccessor m n).isSome = p

private theorem ge_of_index {m : NodeState} {n i : Nat} (grow : m.commitIndex < i)
    (len : i ≤ m.log.length) (signed : isSignatureAt m.log i = true) (term : termAt m.log i = m.currentTerm)
    (q : hasQuorum (Timely.bounded m.log m.commitIndex i) (Extension.voters m n i)) : i ≤ high n m := by
  let good := fun (j : Nat) => m.commitIndex < j ∧ isSignatureAt m.log j = true ∧
    termAt m.log j = m.currentTerm ∧ hasQuorum (Timely.bounded m.log m.commitIndex j) (Extension.voters m n j)
  letI : DecidablePred good := fun _=>inferInstanceAs (Decidable (_ ∧ _ ∧ _ ∧ _))
  exact Extension.foldMember good ⟨grow,signed,term,q⟩ (List.mem_range.mpr (Nat.lt_succ_of_le len)) 0

private theorem confirm_mono {n i j : Nat} {l l' : List Entry} (sub : l <+: l') (le : i ≤ j)
    (h : Confirm n (l.take i)) : Confirm n (l'.take j) := by
  obtain ⟨e,mem,yes⟩ := h
  have cut := (List.prefix_take_iff.mpr ⟨(List.take_prefix i l).trans sub,List.length_take_le _ _⟩ :
    l.take i <+: l'.take i)
  exact ⟨e,(cut.trans (take_prefix_take l' le)).subset mem,yes⟩

private theorem confirm_new {n s p j} (hj : s.log.length + 1 ≤ j) :
    Confirm n ((canon n s p).log.take j) := by
  let x : Entry := ⟨s.currentTerm,.transaction 0 {retirementConfirmations := {n}}⟩
  have eq : (canon n s p).log.take (s.log.length+1) = s.log ++ [x] := by
    simp [suffix,x,List.take_append,List.take_of_length_le (Nat.le_succ s.log.length)]
  apply confirm_mono (l := (canon n s p).log) (List.prefix_refl _) hj
  rw [eq]; exact ⟨x,List.mem_append_right _ (.head _),Finset.mem_singleton.mpr rfl⟩

private theorem bound_new {s : NodeState} (n : NodeID) (p : Bool) (front : s.commitIndex ≤ s.log.length) :
    Timely.bounded (canon n s p).log s.commitIndex (s.log.length+2) = s.activeConfigurations := by
  change (canon n s p).activeConfigurations.filter _ = _
  rw [active_canon _ _ front,List.filter_append,List.filter_eq_self.mpr]
  · simp
  · intro cfg mem
    have bound := mem_history_filterMap ((activeConfigurations_sublist _ _).subset mem)
    simp only [decide_eq_true_eq]; omega

theorem normalize [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)
    (primary : c.pre.role = .primary) (want : Bool) {xs si}
    (h : Pick want c.actor {c.pre with log := c.pre.log ++ xs,sentIndex := si}) :
    Pick want c.actor (canon c.actor c.pre want) := by
  let st := c.pre
  let n := c.actor
  let m := {st with log := st.log ++ xs,sentIndex := si}
  let sm := canon n st want
  let i := high n m
  let j := high n sm
  obtain ⟨grow,ret,_,suc⟩ := h
  have a : st.commitIndex < i := grow
  obtain ⟨len,signed,term,q⟩ := highestCommittableIndex_spec m n a
  change hasQuorum (Timely.bounded m.log st.commitIndex i) (Extension.voters m n i) at q
  have fr : st.commitIndex ≤ st.log.length := c.frontier_pre
  have dest : (findSuccessor sm n).isSome = want := by
    apply target _ _ fr
    rintro rfl ⟨v,mem⟩
    have later := peerMono xs fr mem
    have pr := (successor (s := m)).mpr ⟨v,later⟩
    exact Bool.noConfusion (pr.symm.trans suc)
  refine ⟨?_,?_,primary,dest⟩ <;>
    suffices consequence : st.commitIndex < j ∧ (sm.retiredCommittedIndex.isSome ∨ Confirm n (sm.log.take j)) by
      first | exact consequence.1 | exact (retire_iff ..).mpr ⟨retirement_present ..,consequence.2⟩
  all_goals
    by_cases old : i ≤ st.log.length
    · have eq : Timely.bounded sm.log st.commitIndex i = Timely.bounded m.log st.commitIndex i := by
        change Timely.bounded (st.log++_) st.commitIndex i = Timely.bounded (st.log++_) st.commitIndex i
        rw [Timely.bounded_append st.log _ (Nat.le_of_lt a) old,Timely.bounded_append st.log _ (Nat.le_of_lt a) old]
      have q' := Extension.transfer (big := m) (small := sm) (self := n) (i := i) (j := i) rfl (Nat.le_refl _)
        (eq ▸ List.Subset.refl _) (eq ▸ q.1) q
      have sg := Extension.oldSignature old signed
      have tEq : termAt sm.log i = sm.currentTerm := by
        rw [termAt_of_prefix (List.prefix_append ..) old] at term ⊢
        exact term
      have grows := ge_of_index (m := sm) (n := n) a (Nat.le_trans old (List.prefix_append ..).length_le)
        (isSignatureAt_of_prefix (List.prefix_append ..) sg) tEq q'
      refine ⟨Nat.lt_of_lt_of_le a grows,?_⟩
      rcases ((retire_iff ..).mp ret).2 with latch | conf
      · exact .inl latch
      · have h : Confirm n (st.log.take i) := by
          change Confirm n ((st.log ++ xs).take i) at conf; rwa [List.take_append_of_le_length old] at conf
        exact .inr (confirm_mono (List.prefix_append ..) grows h)
    · let k := st.log.length+2
      have newBound := bound_new n want fr
      have oldBound := Timely.bounded_append st.log xs (i := st.log.length) fr (Nat.le_refl _)
      have has (cfg) (mem : cfg ∈ st.activeConfigurations) : cfg ∈ Timely.bounded m.log st.commitIndex i := by
        have pre' : cfg ∈ Timely.bounded st.log st.commitIndex st.log.length := by rwa [Extension.fullBound _ _ _ (Nat.le_refl _)]
        rw [←oldBound] at pre'
        obtain ⟨ac,cut⟩ := List.mem_filter.mp pre'
        exact List.mem_filter.mpr ⟨ac,decide_eq_true (Nat.le_trans (of_decide_eq_true cut) (Nat.le_of_lt (Nat.lt_of_not_ge old)))⟩
      have nonempty : st.activeConfigurations ≠ [] := by
        have ha := configurationHistory_ne_nil ((c.inv.rooted _ _ c.pre_now).head (c.inv.leader_logs _ _ c.pre_now primary))
          Config.GENESIS_configured
        intro no
        have drop := List.drop_eq_nil_iff.mp no
        have l := List.length_filter_le (fun cfg : Node.Configuration=>decide (cfg.index ≤ st.commitIndex)) (configurationHistory st.log)
        have pos := List.length_pos_iff.mpr ha
        change (configurationHistory st.log).length ≤ _ at drop
        change 0 < (configurationHistory st.log).length at pos; omega
      have q' : hasQuorum (Timely.bounded sm.log st.commitIndex k) (Extension.voters sm n k) := by
        rw [newBound]
        refine ⟨nonempty,List.all_eq_true.mpr fun cfg mem=>decide_eq_true ?_⟩
        apply Timely.majority_mono _ (hasQuorum_majority q (has cfg mem))
        intro v vm
        obtain ⟨active,ok⟩ := Finset.mem_filter.mp vm
        by_cases self : v = n
        · subst v
          refine Finset.mem_filter.mpr ⟨?_,.inl rfl⟩
          apply member_iff.mpr
          rw [active_canon n want fr]
          exact ⟨_,List.mem_append_right _ (.head _),Finset.mem_singleton.mpr rfl⟩
        · have le := ok.resolve_left self
          have diff : v ≠ c.actor := self
          have idx : i ≤ c.pre.matchIndex v := le
          obtain ⟨_,_,_,valid,_⟩ := c.match_pre primary diff (Nat.lt_of_lt_of_le (Nat.zero_lt_of_lt a) idx)
          exact (old (Nat.le_trans idx valid)).elim
      have e : entryAt? sm.log k = some ⟨st.currentTerm,.signature⟩ := by
        change entryAt? (st.log ++ suffix n st.currentTerm want) (st.log.length+2) = _
        simp [entryAt?,suffix]
      have prelt : st.commitIndex < k := Nat.lt_of_le_of_lt fr (by dsimp [k];omega)
      have grown : k ≤ j := ge_of_index (m:=sm) (n:=n) prelt (by simp [k,sm,suffix])
        (by simp [isSignatureAt,e,EntryContent.isSignature]) (by unfold termAt;rw [e];rfl) q'
      exact ⟨Nat.lt_of_lt_of_le prelt grown,.inr (confirm_new (Nat.le_trans (Nat.le_succ _) grown))⟩

end ConsensusCoverage.HandReadersTrunkD.Nominate
