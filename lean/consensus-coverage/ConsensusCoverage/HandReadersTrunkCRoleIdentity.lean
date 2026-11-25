module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkCRoleRoute
import all ConsensusCoverage.HandReadersTrunkCRoleStrict
import all ConsensusCoverage.HandReadersTrunkBCampaign
import all ConsensusCoverage.HandReadersTrunkBCampaignOrigin
import all ConsensusCoverage.HandReadersTrunkBFactor
import all ConsensusCoverage.HandReadersTrunkAFactor
import all ConsensusCoverage.HandReadersTrunkABatch
import all ConsensusCoverage.HandReadersASummary
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.SelfQuorumCasesB
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersTrunkC.RoleSites

open CCF Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses
open HandReadersA HandReadersTrunkB ActionProfile

set_option maxRecDepth 16384
set_option maxHeartbeats 1600000

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private abbrev Campaign (c : Ctx f t) := CampaignRows.test .win c.actor c.pre c.event c.post = true
private abbrev App (c : Ctx f t) := ∃ xs, c.event = .internal (.append xs)
private abbrev Tail := HandReadersBFactor.Tail.step_role_advance_inl f t c
private abbrev Quorum (_ : NodeID) (_ cand _ : NodeState) (_ : Event) (_ : List Model.Envelope) :=
  hasQuorum cand.activeConfigurations cand.votesGranted

private theorem fromQuorum (h : HandReadersTrunkBFactor.Tail.CampaignCall f t c Quorum) : Campaign c := by
  obtain ⟨cand,o,_,_,_,q⟩ := (CampaignRows.origin_iff c _).mp h
  exact (CampaignRows.site_test .win ..).mp ⟨cand,o,fun _ => rfl,fun _ => rfl,fun _ => q⟩

private theorem upper (h : Tail c) : App c ∨ Campaign c := by
  rcases h with h | h | h | h | h | h | h | h | h | h | h | h | h | h | h
  all_goals obtain ⟨n,m,src,_⟩ := h
  all_goals first
    | (obtain ⟨_,xs,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,_⟩ := src; exact .inl ⟨xs,ev⟩)
    | (obtain ⟨_,_,_,_,_,_,_,_,pr,_,_,_,_,adv,_,cand,_⟩ := src; exact (ack adv pr cand).elim)
    | (right; apply fromQuorum
       first
       | obtain ⟨pre,cand,ev,sent,call,_,q,_⟩ := src
         first | left; exact ⟨_,pre,cand,_,ev,sent,call,q⟩
               | right; left; exact ⟨_,pre,cand,_,ev,sent,call,q⟩
               | right; right; left; exact ⟨_,pre,cand,_,ev,sent,call,q⟩
               | right; right; right; exact ⟨_,pre,cand,_,ev,sent,call,q⟩
       | obtain ⟨i,pre,cand,ev,sent,call,_,q,_⟩ := src
         first | left; exact ⟨i,pre,cand,_,ev,sent,call,q⟩
               | right; left; exact ⟨i,pre,cand,_,ev,sent,call,q⟩
               | right; right; left; exact ⟨i,pre,cand,_,ev,sent,call,q⟩
               | right; right; right; exact ⟨i,pre,cand,_,ev,sent,call,q⟩)

private theorem appSupply (ap : App c) : Tail c := by
  obtain ⟨xs,ev⟩ := ap
  let s := HandReadersTrunkA.Batch.seed c ev
  let m := c.pre
  let e := SelfQuorumCasesB.heartbeat c.actor m
  let q : AppendEntriesRequest := ⟨m.currentTerm,0,termAt m.log 0,[],0⟩
  have ae := SelfQuorumCasesB.beat c.actor m
  have b : BatchState c.actor m m [e] := ⟨(BatchArmsB.start s).1,SelfQuorumCasesB.singleton ae⟩
  have a : Advance c.actor m m := .inl rfl
  have ok : AEOk c.actor e.target m q := ⟨Nat.succ_ne_self _,rfl,Nat.zero_le _,rfl,List.nil_prefix,Nat.zero_le _⟩
  have empty : ∀ p ∈ ([] : List Model.Envelope), p.source = c.actor ∧ p.payload = .proposeRequestVoteRequest m.currentTerm := by simp
  have eq : m = {m with log := m.log ++ [],sentIndex := m.sentIndex} := by simp
  have terms : ∀ e ∈ ([] : List Entry), e.term = m.currentTerm := by simp
  right; left
  exact ⟨c.actor,m,⟨m,xs,⟨_,⟨rfl,rfl,rfl⟩,_,ev,ev,rfl⟩,s.guards,s.guards.1,s.guards.2,s.guards,
    m,[e],b,[],⟨a,empty⟩,a,empty,b.1,b.2,[],⟨_,eq,terms⟩,m.sentIndex,⟨eq,terms⟩,eq,terms,
    e,.head _,.head _,q,⟨rfl,ok⟩,rfl,ok,BatchArmsB.start s,rfl,rfl,Nat.le_refl _,ae,rfl⟩,a⟩

private abbrev Ping (n : NodeID) (pre cand post : NodeState) (ev : Event) (sent : List Model.Envelope) :=
  post = primaryState cand ∧ sent = [SelfQuorumCasesB.heartbeat n (primaryState cand)] ∧
  Safety.Campaign n pre ev cand ∧ hasQuorum cand.activeConfigurations cand.votesGranted

private theorem campSupply (win : Campaign c) : Tail c := by
  obtain ⟨cand,o,guard⟩ := (CampaignRows.site_test .win ..).mpr win
  have q := guard.2.2 rfl
  have a : Advance c.actor (primaryState cand) (primaryState cand) := .inl rfl
  have beat := SelfQuorumCasesB.beat c.actor (primaryState cand)
  have packet : LeaderStart c.actor cand.currentTerm (primaryState cand) (SelfQuorumCasesB.heartbeat c.actor (primaryState cand)) := .inr beat
  have ready : CampaignResult c.actor c.pre cand (primaryState cand) [SelfQuorumCasesB.heartbeat c.actor (primaryState cand)] :=
    .inr ⟨q,a,SelfQuorumCasesB.singleton (.inl packet)⟩
  have src := (CampaignRows.origin_iff c Ping).mpr ⟨cand,o,_,_,ready,rfl,rfl,o.campaign,q⟩
  rcases src with site | site | site | site
  all_goals
    obtain ⟨n,pre,candidate,post,ev,sent,call,rfl,rfl,camp,quorum⟩ := site
    let leader := primaryState candidate
    let ping := SelfQuorumCasesB.heartbeat n leader
    have echo := SelfQuorumCasesB.beat n leader
    have envelope : LeaderStart n candidate.currentTerm leader ping := .inr echo
    have same : Advance n leader leader := .inl rfl
    have sends : ∀ e ∈ [ping], LeaderStart n candidate.currentTerm leader e ∨
        e.source = n ∧ e.payload = .requestVoteRequest (makeRequestVoteRequest candidate) ∧ pre.currentTerm < candidate.currentTerm :=
      SelfQuorumCasesB.singleton (.inl envelope)
    have ok := And.intro quorum (And.intro same sends)
    have result : CampaignResult n pre candidate leader [ping] := .inr ok
    have won : Wins n pre ev leader := ⟨candidate,camp,quorum,same⟩
    have le : pre.currentTerm ≤ candidate.currentTerm := by rcases camp.2.2.2 with h | h <;> have x := h.2.1 <;> omega
    have engaged : Engaged pre := by rcases camp.2.2.2 with h | h; exact h.1; simp [Engaged,h.1]
    have notLeader : pre.role = .primary → candidate.currentTerm = pre.currentTerm → False := by
      rcases camp.2.2.2 with h | h
      · intro _ x; have inc := h.2.1; omega
      · simp [h.1]
    have keep : candidate.currentTerm = pre.currentTerm → ∀ v, pre.votedFor = some v → candidate.votedFor = some v := by
      rcases camp.2.2.2 with h | h
      · intro x; have inc := h.2.1; omega
      · rcases h.2.2.1 with eq | no <;> simp [*]
    obtain ⟨req,payload,valid⟩ := echo.ok
    iterate 7 right
    first | left; refine ⟨n,leader,⟨pre,candidate,ev,[ping],call,?_⟩,same⟩
          | right; left; refine ⟨n,leader,⟨pre,candidate,ev,[ping],call,?_⟩,same⟩
          | right; right; left; refine ⟨n,leader,⟨pre,candidate,ev,[ping],call,?_⟩,same⟩
          | right; right; right; left; refine ⟨n,leader,⟨pre,candidate,ev,[ping],call,?_⟩,same⟩
    exact ⟨ok,quorum,ok.2,same,sends,ping,.head _,envelope,echo,req,⟨payload,valid⟩,payload,valid,camp,result,
      le,engaged,notLeader,keep,same,rfl,won,rfl⟩
end

private def test (n : NodeID) (st : NodeState) (ev : Event) (post : NodeState) :=
  (match ev with | .internal (.append _) => true | _ => false) || CampaignRows.test .win n st ev post

def identity : Exact .role_advance_inl where
  eval := SummaryRows.gated test
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff]
    change step_role_advance_inl _ _ _ ↔ _
    rw [HandReadersTrunkA.Factor.Split.step_role_advance_inl_iff,HandReadersBFactor.Exact.step_role_advance_inl _ _ _ (HandReadersBGate.quiet s),
      SummaryRows.gated,Bool.and_eq_true,actorRead_at,HandReadersBGate.live,and_comm]
    apply and_congr_left; intro _
    have exactTail : Tail s.context ↔ App s.context ∨ Campaign s.context :=
      ⟨upper _,fun h => h.elim (appSupply _) (campSupply _)⟩
    apply exactTail.trans
    unfold App Campaign
    cases s.context.event with
    | internal i => cases i <;> simp [test]
    | receive _ _ => simp [test]

end ConsensusCoverage.HandReadersTrunkC.RoleSites
