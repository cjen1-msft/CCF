module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.AdvanceArmsB
import all ConsensusCoverage.DelayedNominationSuccessor
import all ConsensusCoverage.Timely
import all Consensus.Proofs.SafetyInvariant
import CCF.Proofs.Finset

namespace ConsensusCoverage.HandReadersTrunkC.Extension

open CCF Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety

private theorem foldAbove (p : Nat → Prop) [DecidablePred p] (xs : List Nat) (i : Nat) :
    i ≤ xs.foldl (fun b k => if p k then max b k else b) i := by
  induction xs generalizing i with
  | nil => exact Nat.le_refl _
  | cons a xs ih =>
    simp only [List.foldl_cons]
    apply Nat.le_trans _ (ih _)
    split <;> first | exact Nat.le_max_left _ _ | exact Nat.le_refl _

private theorem foldMember (p : Nat → Prop) [DecidablePred p] {i : Nat} (yes : p i)
    {xs : List Nat} (mem : i ∈ xs) (b : Nat) :
    i ≤ xs.foldl (fun b k => if p k then max b k else b) b := by
  induction xs generalizing b with
  | nil => contradiction
  | cons a xs ih =>
    simp only [List.foldl_cons]
    rcases List.mem_cons.mp mem with rfl | h
    · rw [ite_eq_left yes]
      exact Nat.le_trans (Nat.le_max_right _ _) (foldAbove p _ _)
    · exact ih h _

private abbrev voters (st : NodeState) (self i : Nat) :=
  st.activeMembers.filter (fun v => v = self ∨ i ≤ st.matchIndex v)

private theorem qualifies {st : NodeState} {self i : Nat} (hi : i ≤ st.log.length) (lo : st.commitIndex < i)
    (sg : isSignatureAt st.log i = true) (term : termAt st.log i = st.currentTerm)
    (q : hasQuorum (Timely.bounded st.log st.commitIndex i) (voters st self i)) :
    st.commitIndex < highestCommittableIndex st self := by
  apply Nat.lt_of_lt_of_le lo
  unfold highestCommittableIndex
  apply foldMember _ _ (List.mem_range.mpr (Nat.lt_succ_of_le hi))
  exact ⟨lo,sg,term,q⟩

-- Compare voter sets only inside this configuration. New configuration
-- transactions can add eligible peers, but cannot add an old member's vote.
private theorem transfer {big small : NodeState} {self i j : Nat}
    (same : big.matchIndex = small.matchIndex) (le : j ≤ i)
    (sub : Timely.bounded small.log small.commitIndex j ⊆ Timely.bounded big.log big.commitIndex i)
    (ne : Timely.bounded small.log small.commitIndex j ≠ [])
    (q : hasQuorum (Timely.bounded big.log big.commitIndex i) (voters big self i)) :
    hasQuorum (Timely.bounded small.log small.commitIndex j) (voters small self j) := by
  refine ⟨ne,List.all_eq_true.mpr fun cfg mem => decide_eq_true ?_⟩
  have major := hasQuorum_majority q (sub mem)
  have inc : voters big self i ∩ cfg.nodes ⊆ voters small self j ∩ cfg.nodes := by
    intro v hv
    obtain ⟨voted,member⟩ := Finset.mem_inter.mp hv
    have active := DelayedNomination.configuration_member (List.mem_filter.mp mem).1 member
    refine Finset.mem_inter.mpr ⟨Finset.mem_filter.mpr ⟨active,?_⟩,member⟩
    rcases (Finset.mem_filter.mp voted).2 with h | h
    · exact .inl h
    · rw [same] at h; exact .inr (Nat.le_trans le h)
  have incl := Finset.card_le_card inc
  unfold hasConfigurationMajority at *
  omega

private theorem fullBound (l : List Entry) (b j : Nat) (le : l.length ≤ j) :
    Timely.bounded l b j = activeConfigurations l b := by
  apply List.filter_eq_self.mpr
  intro cfg mem
  have h := mem_history_filterMap ((activeConfigurations_sublist l b).subset mem)
  simp only [decide_eq_true_eq]
  omega

private def sg (st : NodeState) : Entry := ⟨st.currentTerm,.signature⟩
private abbrev short (st : NodeState) := AdvanceArmsB.appended st

private theorem shortConfigs (st : NodeState) :
    activeConfigurations (short st).log st.commitIndex = activeConfigurations st.log st.commitIndex := by
  have h : configurationHistory (st.log ++ [sg st]) = configurationHistory st.log := by
    simp [configurationHistory,List.zipIdx_append,sg,EntryContent.metadata]
  unfold activeConfigurations
  change ((configurationHistory (st.log ++ [sg st])).drop
    (((configurationHistory (st.log ++ [sg st])).filter (·.index ≤ st.commitIndex)).length - 1)) = _
  rw [h]

private theorem shortBound (st : NodeState) (i : Nat) :
    Timely.bounded (short st).log (short st).commitIndex i = Timely.bounded st.log st.commitIndex i :=
  congrArg (fun cs : List Node.Configuration => cs.filter (·.index ≤ i)) (shortConfigs st)

private theorem oldSignature {l ext : List Entry} {i : Nat} (hi : i ≤ l.length)
    (yes : isSignatureAt (l ++ ext) i = true) : isSignatureAt l i = true := by
  unfold isSignatureAt entryAt? at *
  by_cases zero : i = 0
  · simp [zero] at yes
  · simpa only [zero,ite_false,List.getElem?_append_left (show i - 1 < l.length by omega)] using yes

-- Every feasible log extension is dominated by appending one current-term
-- signature: retain old signed indices, and move any later index to the
-- first suffix position (where fewer configurations and votes are needed).
theorem normalize [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)
    (primary : c.pre.role = .primary) (entries : List Entry) (sent : NodeID → Nat)
    (mid : NodeState) (hm : mid = {c.pre with log := c.pre.log ++ entries,sentIndex := sent})
    (ahead : mid.commitIndex < highestCommittableIndex mid c.actor) :
    c.pre.commitIndex < highestCommittableIndex (short c.pre) c.actor := by
  let st := c.pre
  let i := highestCommittableIndex mid c.actor
  obtain ⟨hi,signed,term,q⟩ := highestCommittableIndex_spec mid c.actor ahead
  have len := c.frontier_pre
  have base : mid.commitIndex = st.commitIndex := hm ▸ rfl
  have log : mid.log = st.log ++ entries := hm ▸ rfl
  have matchEq : mid.matchIndex = (short st).matchIndex := hm ▸ rfl
  change hasQuorum (Timely.bounded mid.log mid.commitIndex i) (voters mid c.actor i) at q
  change isSignatureAt mid.log i = true at signed
  change termAt mid.log i = mid.currentTerm at term
  have behind : st.commitIndex < i := base ▸ ahead
  by_cases old : i ≤ st.log.length
  · have beq : Timely.bounded (short st).log (short st).commitIndex i = Timely.bounded mid.log mid.commitIndex i := by
      rw [shortBound,log,base,Timely.bounded_append _ _ (Nat.le_of_lt behind) old]
    have stamped : termAt (short st).log i = (short st).currentTerm := by
      change termAt (st.log ++ [sg st]) i = st.currentTerm
      rw [termAt_of_prefix (List.prefix_append _ _) old]
      rw [log,termAt_of_prefix (List.prefix_append _ _) old,hm] at term
      exact term
    apply qualifies (st := short st) (Nat.le_trans old (List.prefix_append st.log [sg st]).length_le) behind
      (Ledger.isSignatureAt_of_prefix (List.prefix_append st.log [sg st]) (oldSignature old (log ▸ signed))) stamped
    exact transfer matchEq (Nat.le_refl _) (beq ▸ List.Subset.refl _) (beq ▸ q.1) q
  · let j := st.log.length + 1
    have le : j ≤ i := Nat.lt_of_not_ge old
    have ne := configurationHistory_ne_nil ((c.inv.rooted _ _ c.pre_now).head
      (c.inv.leader_logs _ _ c.pre_now primary)) Config.GENESIS_configured
    have hasConfig : activeConfigurations st.log st.commitIndex ≠ [] := by
      intro empty
      have drop := List.drop_eq_nil_iff.mp empty
      have sz := List.length_filter_le (fun x : Node.Configuration => decide (x.index ≤ st.commitIndex)) (configurationHistory st.log)
      have pos := List.length_pos_iff.mpr ne
      change 0 < (configurationHistory st.log).length at pos
      omega
    have oldBound := Timely.bounded_append st.log entries (i := st.log.length) len (Nat.le_refl _)
    have eq : Timely.bounded (short st).log (short st).commitIndex j = activeConfigurations st.log st.commitIndex := by
      rw [shortBound,fullBound _ _ _ (Nat.le_succ _)]
    have sub : Timely.bounded (short st).log (short st).commitIndex j ⊆ Timely.bounded mid.log mid.commitIndex i := by
      rw [eq,log,base,←fullBound st.log st.commitIndex st.log.length (Nat.le_refl _),←oldBound]
      intro cfg mem
      obtain ⟨a,b⟩ := List.mem_filter.mp mem
      exact List.mem_filter.mpr ⟨a,decide_eq_true (Nat.le_trans (of_decide_eq_true b) (Nat.le_of_lt le))⟩
    have found : entryAt? (short st).log j = some (sg st) := by
      change entryAt? (st.log ++ [sg st]) (st.log.length + 1) = _
      simp [entryAt?]
    apply qualifies (st := short st) (i := j) (by simp [short,AdvanceArmsB.appended,j]) (Nat.lt_succ_of_le len)
      (by simp [isSignatureAt,found,sg,EntryContent.isSignature])
      (by unfold termAt; rw [found]; rfl)
    exact transfer matchEq le sub (eq ▸ hasConfig) q

end ConsensusCoverage.HandReadersTrunkC.Extension
