module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkDLeaderQuery
import all ConsensusCoverage.HandReadersTrunkCMatch
import all ConsensusCoverage.HandReadersTrunkABatch
import all ConsensusCoverage.HandReadersTrunkBFactor
import all ConsensusCoverage.HandReadersBGate
import all ConsensusCoverage.PromotionImpossibleB
import all ConsensusCoverage.SelfQuorumCasesB
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersTrunkD.Leader

open Consensus Model Model.Node Proofs Safety SolvedWitnesses HandReadersTrunkC
set_option maxRecDepth 8192
set_option maxHeartbeats 1500000
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

abbrev Growth (n : NodeID) (m : NodeState) := m.commitIndex < highestCommittableIndex m n

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

abbrev App := ∃ xs, c.event = .internal (.append xs)
abbrev Batch (p : Check) := App c ∧ ∃ xs sent, (∀ e ∈ xs, e.term = c.pre.currentTerm) ∧
  p c.actor {c.pre with log := c.pre.log ++ xs,sentIndex := sent}
abbrev Ack (p : Check) := ∃ src r, c.event = .receive src (.appendEntriesResponse r) ∧
  src ∈ eligiblePeers c.pre c.actor ∧ c.pre.role = .primary ∧ r.success = true ∧ r.term = c.pre.currentTerm ∧
  p c.actor (Match.ack c.pre src r)

private theorem freshOld {m : NodeState} {n} (log : m.log = c.pre.log) (term : m.currentTerm = c.pre.currentTerm) :
    PromotionImpossibleB.Old (freshCandidate n m) := by
  intro e mem
  have le := c.inv.terms _ _ c.pre_now e (log ▸ mem)
  change e.term < m.currentTerm + 1; omega

private theorem tail_iff (p : Check) (grows : ∀ n m, p n m → Growth n m) :
    HandReadersTrunkBFactor.Tail.Working f t c p ↔ Batch c p ∨ Ack c p := by
  constructor
  · rintro (batch | ack | vote | timeout | prevote | propose)
    · obtain ⟨_,_,⟨_,xs,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,_,_,_,_,_,⟨⟨es,si,rfl,terms⟩,_⟩,_⟩,pass⟩ := batch
      exact .inl ⟨⟨xs,ev⟩,es,si,terms,pass⟩
    · obtain ⟨_,_,⟨_,src,r,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,admit,_,_,_,pr,ok,same,_,rfl⟩,w⟩ := ack
      exact .inr ⟨src,r,ev,Classical.byContradiction (fun no => admit ⟨trivial,no⟩),by simpa using pr,ok,same,w⟩
    · obtain ⟨n,_,⟨z,⟨⟨st,src,r,⟨_,⟨_,pre,_⟩,_⟩,_,_,_,_,g,camp,rfl⟩,_⟩,rfl⟩,cut⟩ := vote
      exact (PromotionImpossibleB.noAdvance (PromotionImpossibleB.campOld c pre camp) (grows n _ cut)).elim
    · obtain ⟨n,_,⟨_,⟨⟨_,⟨_,⟨⟨_,⟨_,rfl,_⟩,_⟩,_,_,_,_,_,rfl⟩,_⟩,rfl⟩,_⟩,rfl⟩,cut⟩ := timeout
      exact (PromotionImpossibleB.noAdvance (freshOld c rfl rfl) (grows n _ cut)).elim
    · obtain ⟨n,_,⟨_,⟨⟨_,⟨_,⟨_,_,⟨_,⟨_,rfl,_⟩,_⟩,_,_,_,_,_,_,_,rfl⟩,_⟩,rfl⟩,_⟩,rfl⟩,cut⟩ := prevote
      exact (PromotionImpossibleB.noAdvance (freshOld c rfl rfl) (grows n _ cut)).elim
    · obtain ⟨n,_,⟨_,⟨⟨_,⟨_,⟨_,⟨_,⟨_,rfl,_⟩,_⟩,_,_,_,rfl⟩,_⟩,rfl⟩,_⟩,rfl⟩,cut⟩ := propose
      exact (PromotionImpossibleB.noAdvance (freshOld c rfl rfl) (grows n _ cut)).elim
  · rintro (⟨⟨xs,ev⟩,es,si,terms,h⟩ | ⟨n,r,ev,peer,primary,ok,stamp,h⟩)
    · let s := HandReadersTrunkA.Batch.seed c ev
      left
      exact ⟨c.actor,_,⟨c.pre,xs,⟨_,⟨rfl,rfl,rfl⟩,_,ev,ev,rfl⟩,s.guards,s.guards.1,s.guards.2,
        s.guards,[],⟨⟨es,si,rfl,terms⟩,by simp⟩,BatchArmsB.start s⟩,h⟩
    · have stable := (observe_response c.pre r).resolve_left fun h => Nat.lt_irrefl _ (stamp ▸ h.2.1)
      right; left
      exact ⟨c.actor,_,⟨c.pre,n,r,⟨_,⟨rfl,rfl,rfl⟩,_,ev,ev,rfl⟩,fun bad=>bad.2 peer,stable,stable.1,stable.2,
        by simp [primary],ok,stamp,fun st hr ht hl hc hv hvs hm => quiet_summary
          (self := c.actor) (before := c.pre) (after := st) (event := .receive n (.appendEntriesResponse r))
          (sent := []) hr ht hl hc hv hvs hm no_bumping_sends (by simp),rfl⟩,h⟩
end

theorem working_iff (s : ActionProfile.Step) (p : Check) (grows : ∀ n m, p n m → Growth n m) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    Working s.frame s.after s.context p ↔ HandReadersBGate.Source s.context ∧ (Batch s.context p ∨ Ack s.context p) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  rw [HandReadersTrunkBFactor.Exact.Working _ _ _ p (HandReadersBGate.quiet s),tail_iff _ p grows]

end ConsensusCoverage.HandReadersTrunkD.Leader
