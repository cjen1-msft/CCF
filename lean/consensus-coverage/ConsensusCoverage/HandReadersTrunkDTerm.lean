module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkDTermRoute
import all ConsensusCoverage.HandReadersTrunkCMatch
import all ConsensusCoverage.HandReadersTrunkCMatchRoute
import all ConsensusCoverage.HandReadersTrunkCExtension
import all ConsensusCoverage.HandReadersTrunkCRoleIdentity
import all ConsensusCoverage.HandReadersTrunkCRoleStrict
import all ConsensusCoverage.HandReadersTrunkBCampaign
import all ConsensusCoverage.HandReadersTrunkBCampaignOrigin
import all ConsensusCoverage.HandReadersTrunkBFactor
import all ConsensusCoverage.HandReadersTrunkAFactor
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.HandReadersASummary
import all ConsensusCoverage.HandReadersTrunkDTermSites
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersTrunkD.Term

open Consensus Model Model.Node Proofs Safety ActionProfile SolvedWitnesses HandReadersA HandReadersTrunkC
open HandReadersTrunkB
set_option maxRecDepth 16384
set_option maxHeartbeats 1200000

private def test (strict : Bool) (n : NodeID) (st : NodeState) (ev : Event) (post : NodeState) :=
  Match.test strict n st ev post || (!strict && CampaignRows.test .win n st ev post)

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private abbrev Tail (strict : Bool) := if strict then HandReadersBFactor.Tail.Strict f t c else
  HandReadersBFactor.Tail.Identity f t c

private theorem necessary (k : Bool) (h : Tail c k) : test k c.actor c.pre c.event c.post := by
  cases k <;> rcases h with h | h | h | h | h | h
  case false.inl =>
    obtain ⟨_,_,⟨_,xs,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,_⟩,_⟩ := h
    rw [show c.event = .internal (.append xs) from ev]; simp [test,Match.test,Match.Grow]
  case true.inl =>
    obtain ⟨_,m,_,⟨_,xs,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,_,pr,_,_,app,_,b,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,rfl⟩,s,_⟩ := h
    rw [show c.event = .internal (.append xs) from ev]; simp only [test,Bool.not_true,Bool.false_and,Bool.or_false]
    obtain ⟨⟨es,si,eq,_⟩,_⟩ := b
    exact decide_eq_true fun _ => Extension.normalize c pr es si _ eq (s.2.2.2.2.2.2.2.1 ▸ s.2.2.2.2.2.2.1)
  case false.inr.inl =>
    obtain ⟨_,_,⟨_,n,r,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,pass,_,_,_,pr,pos,term,_⟩,_⟩ := h
    rw [show c.event = .receive n (.appendEntriesResponse r) from ev]
    exact Bool.or_eq_true_iff.mpr (.inl (decide_eq_true ⟨Classical.byContradiction (fun no => pass ⟨trivial,no⟩),
      by simpa using pr,pos,term,by simp [Match.Grow]⟩))
  case true.inr.inl =>
    obtain ⟨_,_,_,⟨_,n,r,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,pass,_,_,_,pr,pos,term,_,_,_,_,_,_,rfl⟩,s,_⟩ := h
    rw [show c.event = .receive n (.appendEntriesResponse r) from ev]
    exact Bool.or_eq_true_iff.mpr (.inl (decide_eq_true ⟨Classical.byContradiction (fun no => pass ⟨trivial,no⟩),
      by simpa using pr,pos,term,fun _ => s.2.2.2.2.2.2.2.1 ▸ s.2.2.2.2.2.2.1⟩))
  all_goals first
    | change test false _ _ _ _ = true
      obtain ⟨_,_,⟨pre,cand,ev,sent,call,_,q,_⟩,_⟩ := h
      apply Bool.or_eq_true_iff.mpr; right
      change CampaignRows.test .win c.actor c.pre c.event c.post = true
      apply RoleSites.fromQuorum c
      repeat' first | exact ⟨_,pre,cand,_,ev,sent,call,q⟩ | exact Or.inl ⟨_,pre,cand,_,ev,sent,call,q⟩ | apply Or.inr
      done
    | change test true _ _ _ _ = true
      obtain ⟨_,m,_,⟨pre,cand,_,_,call,_,_,_,_,_,camp,rest⟩,s,_⟩ := h
      have pin : m = primaryState cand := by repeat' first | exact rest | obtain ⟨_,rest⟩ := rest
      have bef : pre = c.pre := by
        first | obtain ⟨⟨_,⟨_,e,_⟩,_⟩,_⟩ := call; exact e
              | obtain ⟨_,_,⟨_,⟨_,e,_⟩,_⟩,_⟩ := call; exact e
              | obtain ⟨_,⟨_,⟨_,e,_⟩,_⟩,_⟩ := call; exact e
      exact (RoleSites.campaign c bef camp pin (s.2.2.2.2.2.2.2.1 ▸ s.2.2.2.2.2.2.1)).elim

private theorem base (k : Bool) (h : Match.test k c.actor c.pre c.event c.post) : Tail c k := by
  have yes := (Match.tail_iff c k).mpr h
  cases k
  all_goals rcases yes with h | h
  case' false.inl => obtain ⟨n,m,site,a⟩ := h; left; refine ⟨n,m,?_,a⟩
  case' false.inr => obtain ⟨n,m,site,a⟩ := h; right; left; refine ⟨n,m,?_,a⟩
  case' true.inl => obtain ⟨n,m,post,site,s,a⟩ := h; left; refine ⟨n,m,post,?_,s,a⟩
  case' true.inr => obtain ⟨n,m,post,site,s,a⟩ := h; right; left; refine ⟨n,m,post,?_,s,a⟩
  all_goals first
    | obtain ⟨st,xs,call,g,pr,gn,g',app,sent,b,later,pair,a',empty,b0,b1,es,ex,si,ex',eq,terms,_,_,_,start,_,log,role,le,meq⟩ := site
      exact ⟨st,xs,call,g,pr,gn,g',app,sent,b,later,pair,a',empty,b0,b1,es,ex,si,ex',eq,terms,start,log,role,le,meq⟩
    | obtain ⟨st,n,r,call,pass,obs,lo,stable,pr,yes,stamp,sent,pair,a',empty,_,_,_,quiet,no,meq⟩ := site
      exact ⟨st,n,r,call,pass,obs,lo,stable,pr,yes,stamp,sent,pair,a',empty,quiet,no,meq⟩

private abbrev Simple (n : NodeID) (pre cand post : NodeState) (ev : Event) (sent : List Model.Envelope) :=
  post = primaryState cand ∧ sent = [] ∧ Campaign n pre ev cand ∧ hasQuorum cand.activeConfigurations cand.votesGranted

private theorem campaign (win : CampaignRows.test .win c.actor c.pre c.event c.post) : Tail c false := by
  obtain ⟨cand,o,guard⟩ := (CampaignRows.site_test .win ..).mpr win
  have q := guard.2.2 rfl
  have a : Advance c.actor (primaryState cand) (primaryState cand) := .inl rfl
  have ready : CampaignResult c.actor c.pre cand (primaryState cand) [] := .inr ⟨q,a,by simp⟩
  have src := (CampaignRows.origin_iff c Simple).mpr ⟨cand,o,_,_,ready,rfl,rfl,o.campaign,q⟩
  rcases src with h | h | h | h
  all_goals
    obtain ⟨n,pre,z,_,ev,_,call,rfl,rfl,camp,quorum⟩ := h
    let leader := primaryState z
    have same : Advance n leader leader := .inl rfl
    have result : CampaignResult n pre z leader [] := .inr ⟨quorum,same,by simp⟩
    have won : Wins n pre ev leader := ⟨z,camp,quorum,same⟩
    have le : pre.currentTerm ≤ z.currentTerm := by rcases camp.2.2.2 with g | g <;> have stamp := g.2.1 <;> omega
    have engaged : Engaged pre := by rcases camp.2.2.2 with g | g; exact g.1; simp [Engaged,g.1]
    repeat' first | (left; refine ⟨n,leader,⟨pre,z,ev,[],call,?_⟩,same⟩)
                  | refine ⟨n,leader,⟨pre,z,ev,[],call,?_⟩,same⟩ | apply Or.inr
    exact ⟨⟨quorum,same,by simp⟩,quorum,⟨same,by simp⟩,same,by simp,camp,result,le,engaged,
      leaderImpossible camp,keepVote camp,same,won,by change ¬ Role.primary = .candidate; decide,rfl⟩

private theorem tail_iff (k : Bool) : Tail c k ↔ test k c.actor c.pre c.event c.post := by
  refine ⟨necessary c k,?_⟩
  rintro h
  rcases Bool.or_eq_true_iff.mp h with b | camp
  · exact base c k b
  · cases k <;> simp at camp
    exact campaign c camp
end

private def column (k : Bool) : Classes.StepBranch := if k then .term_advance_inr else .term_advance_inl

def exactReader (k : Bool) : Exact (column k) where
  eval := SummaryRows.gated (test k)
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff,SummaryRows.gated,Bool.and_eq_true,actorRead_at,HandReadersBGate.live,and_comm,←tail_iff]
    cases k
    · change step_term_advance_inl _ _ _ ↔ _
      rw [Identity_iff,HandReadersTrunkA.Factor.Split.Identity_iff]
      exact HandReadersBFactor.Exact.Identity _ _ _ (HandReadersBGate.quiet s)
    · change step_term_advance_inr _ _ _ ↔ _
      rw [Strict_iff,HandReadersTrunkA.Factor.Split.Strict_iff]
      exact HandReadersBFactor.Exact.Strict _ _ _ (HandReadersBGate.quiet s)

end ConsensusCoverage.HandReadersTrunkD.Term
