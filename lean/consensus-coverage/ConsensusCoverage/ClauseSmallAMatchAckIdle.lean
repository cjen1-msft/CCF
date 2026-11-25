module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.AckAdvance
import all ConsensusCoverage.FullProfile
import all ConsensusCoverage.Timely
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.ClauseSmallA.MatchAckIdle

open CCF CCF.MultiNodeTransitionSystem
open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open Consensus.Proofs.Ledger

set_option maxRecDepth 8192
set_option maxHeartbeats 1000000

def Idle (self : NodeID) (st : NodeState) : Prop :=
  st.commitIndex = 0 → highestCommittableIndex st self ≤ st.commitIndex

theorem advance (self : NodeID) (mid : NodeState) :
    Sends (fun post _ => Idle self post) (advanceCommit (Capabilities.record self) mid self) := by
  unfold advanceCommit
  dsimp only
  refine Sends.ite' (fun below => Sends.pure' (fun _ => below)) fun ahead => ?_
  let next := mid.recordCommit self (highestCommittableIndex mid self)
  have eq : next.commitIndex = highestCommittableIndex mid self := by
    unfold next NodeState.recordCommit
    dsimp only
    split <;> rfl
  have positive : 0 < next.commitIndex := by rw [eq]; omega
  have done : Idle self next := fun zero => (Nat.ne_of_gt positive zero).elim
  refine Sends.ite'
    (fun _ => Sends.ite' (fun _ => ?_) (fun _ => Sends.pure' done)) (fun _ => Sends.pure' done)
  exact Sends.bind' (nominate_sends self mid) fun _ _ _ => Sends.pure' done

theorem congr_fields (self : NodeID) {a b : NodeState} (log : a.log = b.log)
    (commit : a.commitIndex = b.commitIndex) (stamp : a.currentTerm = b.currentTerm)
    (matched : a.matchIndex = b.matchIndex) :
    highestCommittableIndex a self = highestCommittableIndex b self := by
  simp only [highestCommittableIndex, NodeState.activeMembers, NodeState.activeConfigurations,
    log, commit, stamp, matched] <;> rfl

theorem score_witness (self : NodeID) (st : NodeState) {i : Nat}
    (bound : i ≤ st.log.length) (ahead : st.commitIndex < i)
    (signature : isSignatureAt st.log i = true) (stamp : termAt st.log i = st.currentTerm)
    (quorum : hasQuorum (Timely.bounded st.log st.commitIndex i)
      (st.activeMembers.filter fun v => v = self ∨ i ≤ st.matchIndex v)) :
    i ≤ highestCommittableIndex st self := by
  let step := fun (big j : Nat) => if j > st.commitIndex ∧ isSignatureAt st.log j = true ∧
    termAt st.log j = st.currentTerm ∧ hasQuorum (Timely.bounded st.log st.commitIndex j)
      (st.activeMembers.filter fun v => v = self ∨ j ≤ st.matchIndex v)
    then max big j else big
  have mono (j big : Nat) : big ≤ step big j := by
    unfold step
    split
    · exact Nat.le_max_left _ _
    · exact Nat.le_refl _
  have grows (l : List Nat) (a : Nat) : a ≤ l.foldl step a := by
    induction l generalizing a with
    | nil => exact Nat.le_refl _
    | cons j rest ih => exact Nat.le_trans (mono j a) (ih _)
  have found (xs : List Nat) (big : Nat) (mem : i ∈ xs) : i ≤ xs.foldl step big := by
    induction xs generalizing big with
    | nil => contradiction
    | cons x xs ih =>
      rcases List.mem_cons.mp mem with rfl | more
      · have now : i ≤ step big i := by
          unfold step
          rw [ite_eq_left ⟨ahead,signature,stamp,quorum⟩]
          exact Nat.le_max_right _ _
        exact Nat.le_trans now (grows _ _)
      · exact ih _ more
  exact found (List.range (st.log.length+1)) 0 (List.mem_range.mpr (by omega))

private theorem member_union {l : List Node.Configuration} {c : Node.Configuration} {v : NodeID}
    (mem : c ∈ l) (yes : v ∈ c.nodes) : v ∈ configurationMembers l := by
  have any (acc : Finset NodeID) (l : List Node.Configuration) :
      (v ∈ acc ∨ ∃ cfg ∈ l, v ∈ cfg.nodes) → v ∈ l.foldl (fun a cfg => a ∪ cfg.nodes) acc := by
    induction l generalizing acc with
    | nil => rintro (old | ⟨_, h, _⟩); exact old; contradiction
    | cons cfg rest ih =>
      intro seen
      apply ih
      rcases seen with old | ⟨c, hc, hv⟩
      · exact .inl (Finset.mem_union.mpr (.inl old))
      · rcases List.mem_cons.mp hc with rfl | tail
        · exact .inl (Finset.mem_union.mpr (.inr hv))
        · exact .inr ⟨c,tail,hv⟩
  exact any ∅ l (.inr ⟨c,mem,yes⟩)

theorem replace_voters (st : NodeState) (self i : Nat) {vs : Finset NodeID}
    (quorum : hasQuorum (Timely.bounded st.log st.commitIndex i) vs)
    (each : ∀ v ∈ vs, v = self ∨ i ≤ st.matchIndex v) :
    hasQuorum (Timely.bounded st.log st.commitIndex i)
      (st.activeMembers.filter fun v => v = self ∨ i ≤ st.matchIndex v) := by
  refine ⟨quorum.1,List.all_eq_true.mpr ?_⟩
  intro cfg mem
  have sub : vs ∩ cfg.nodes ⊆ (st.activeMembers.filter fun v => v = self ∨ i ≤ st.matchIndex v) ∩ cfg.nodes := by
    intro v hv
    obtain ⟨old, inCfg⟩ := Finset.mem_inter.mp hv
    refine Finset.mem_inter.mpr ⟨Finset.mem_filter.mpr ⟨?_,each v old⟩,inCfg⟩
    exact member_union (List.mem_filter.mp mem).1 inCfg
  have bound := Finset.card_le_card sub
  have before := of_decide_eq_true (List.all_eq_true.mp quorum.2 cfg mem)
  unfold hasConfigurationMajority at before
  apply decide_eq_true
  unfold hasConfigurationMajority
  omega

end ConsensusCoverage.ClauseSmallA.MatchAckIdle
