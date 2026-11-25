module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkBCampaignPack
import all ConsensusCoverage.HandReadersTrunkBCandidate
import all ConsensusCoverage.HandReadersTrunkBElect
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersTrunkB.CampaignRows

open Consensus Model Model.Node Proofs Safety

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 16384

inductive Origin (self : NodeID) (st : NodeState) (ev : Event) : NodeState → Prop where
  | fresh (h : Candidate.guard self st ev) : Origin self st ev (freshCandidate self st)
  | kept (n : NodeID) (q : RequestVoteResponse) (event : ev = .receive n (.requestVoteResponse q))
      (peer : n ∈ eligiblePeers st self) (g : st.role = .candidate ∧ q.term = st.currentTerm ∧ q.voteGranted = true) :
      Origin self st ev (Elect.candidate st n)

theorem Origin.campaign {self st ev cand} (o : Origin self st ev cand) : Campaign self st ev cand := by
  cases o with
  | fresh h =>
    apply fresh_campaign _ rfl rfl rfl
    rcases h with ⟨_,can,_⟩ | ⟨_,_,_,_,g,_⟩ | ⟨_,_,can⟩
    · exact canStartElection_engaged can
    · exact ⟨fun h => Role.noConfusion (g.1.symm.trans h),fun h => Role.noConfusion (g.1.symm.trans h.1)⟩
    · exact canStartElection_engaged can
  | kept n q ev _ g =>
    refine ⟨g.1,rfl,rfl,.inr ⟨g.1,rfl,.inl rfl,?_⟩⟩
    intro voter mem
    rcases CCF.Finset.mem_insert.mp mem with rfl | old
    · exact .inr ⟨q,ev,g.2⟩
    · exact .inl old

private abbrev elected (self : NodeID) (cand next : NodeState) (sent : List Model.Envelope) :=
  (next = cand ∧ sent = []) ∨ cand.role = .candidate ∧ hasQuorum cand.activeConfigurations cand.votesGranted ∧
    Advance self (primaryState cand) next ∧ ∀ e ∈ sent, LeaderStart self cand.currentTerm next e

private theorem kept_result {self st cand next sent} (same : st.currentTerm = cand.currentTerm)
    (role : cand.role = .candidate) : elected self cand next sent ↔ CampaignResult self st cand next sent := by
  constructor
  · rintro (⟨rfl,rfl⟩ | ⟨_,q,adv,ok⟩)
    · exact .inl ⟨rfl,by simp⟩
    · exact .inr ⟨q,adv,fun e h => .inl (ok e h)⟩
  · rintro (⟨rfl,requests⟩ | ⟨q,adv,requests⟩)
    · refine .inl ⟨rfl,?_⟩
      cases eq : sent with
      | nil => rfl
      | cons hd tl => exact (Nat.ne_of_lt (requests hd (eq ▸ .head _)).2.2 same).elim
    · exact .inr ⟨role,q,adv,fun e h => (requests e h).resolve_right (fun r => Nat.ne_of_lt r.2.2 same)⟩

theorem origin_iff [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t) (p : Effect) :
    HandReadersTrunkBFactor.Tail.CampaignCall f t c p ↔
    ∃ cand, Origin c.actor c.pre c.event cand ∧ ∃ next sent,
      CampaignResult c.actor c.pre cand next sent ∧ p c.actor c.pre cand next c.event sent := by
  constructor
  · rintro (⟨_,_,_,a,_,_,⟨⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,can,_,_,q,s,result,_,rfl,rfl,rfl⟩,yes⟩ |
      ⟨_,_,_,a,_,s,⟨n,q,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,pass,_,_,_,g,result,_,rfl,rfl⟩,yes⟩ |
      ⟨_,_,_,a,_,s,⟨n,q,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,pass,_,_,_,g,quorum,result,_,rfl,rfl⟩,yes⟩ |
      ⟨_,_,_,a,_,s,⟨n,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,_,can,result,_,rfl,rfl⟩,yes⟩)
    · exact ⟨_,.fresh (.inl ⟨ev,can,q⟩),a,_,result,by change p _ _ _ _ c.tr.event _; rwa [ev]⟩
    · exact ⟨_,.kept n q ev (Classical.byContradiction (fun no => pass ⟨trivial,no⟩)) g,a,s,
        (kept_result (cand := Elect.candidate c.pre n) rfl g.1).mp result,by change p _ _ _ _ c.tr.event _; rwa [ev]⟩
    · exact ⟨_,.fresh (.inr (.inl ⟨n,q,ev,Classical.byContradiction (fun no => pass ⟨trivial,no⟩),g,quorum⟩)),
        a,s,result,by change p _ _ _ _ c.tr.event _; rwa [ev]⟩
    · exact ⟨_,.fresh (.inr (.inr ⟨n,ev,can⟩)),a,s,result,by change p _ _ _ _ c.tr.event _; rwa [ev]⟩
  · rintro ⟨cand,o,a,s,result,yes⟩
    have camp := o.campaign
    cases o with
    | fresh entered =>
      rcases entered with ⟨ev,can,q⟩ | ⟨n,q,ev,peer,g,quorum⟩ | ⟨n,ev,can⟩
      · exact .inl ⟨_,_,_,a,_,_,⟨⟨c.event,⟨rfl,rfl,rfl⟩,_,ev,ev,rfl⟩,can,can,can,q,s,result,
          canStartElection_engaged can,rfl,rfl,rfl⟩,ev ▸ yes⟩
      · obtain higher | obs := observe_bumping c.pre (message := .requestPreVoteResponse q) trivial
        · exact (Nat.not_lt_of_ge (Nat.le_of_eq g.2.1) higher.1).elim
        have active : Engaged c.pre := ⟨fun h => Role.noConfusion (g.1.symm.trans h),
          fun h => Role.noConfusion (g.1.symm.trans h.1)⟩
        exact .inr (.inr (.inl ⟨_,_,_,a,_,s,⟨n,q,⟨c.event,⟨rfl,rfl,rfl⟩,_,ev,ev,rfl⟩,
          fun h => h.2 peer,obs,obs.1,obs.2,g,quorum,result,active,rfl,rfl⟩,ev ▸ yes⟩))
      · exact .inr (.inr (.inr ⟨_,_,_,a,_,s,⟨n,⟨c.event,⟨rfl,rfl,rfl⟩,_,ev,ev,rfl⟩,
          fun h => Bool.noConfusion h.1,can,result,canStartElection_engaged can,rfl,rfl⟩,ev ▸ yes⟩))
    | kept n q ev peer g =>
      obtain higher | obs := observe_bumping c.pre (message := .requestVoteResponse q) trivial
      · exact (Nat.not_lt_of_ge (Nat.le_of_eq g.2.1) higher.1).elim
      exact .inr (.inl ⟨_,_,_,a,_,s,⟨n,q,⟨c.event,⟨rfl,rfl,rfl⟩,_,ev,ev,rfl⟩,fun h => h.2 peer,
        obs,obs.1,obs.2,g,(kept_result (cand := Elect.candidate c.pre n) rfl g.1).mpr result,ev ▸ camp,rfl,rfl⟩,ev ▸ yes⟩)

end ConsensusCoverage.HandReadersTrunkB.CampaignRows
