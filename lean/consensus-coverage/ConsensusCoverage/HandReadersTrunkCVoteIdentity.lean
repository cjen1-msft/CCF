module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkCVote
import all ConsensusCoverage.HandReadersTrunkCMatch
import all ConsensusCoverage.HandReadersTrunkBCampaignOrigin
import all ConsensusCoverage.HandReadersTrunkBFactor
import all ConsensusCoverage.HandReadersTrunkBElect
import all ConsensusCoverage.HandReadersTrunkAFactor
import all ConsensusCoverage.HandReadersASummary
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersTrunkC.VoteSites

open CCF Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses
open HandReadersA HandReadersTrunkB ActionProfile

set_option maxRecDepth 16384
set_option maxHeartbeats 1500000

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private abbrev WinsVoted (_ : NodeID) (pre cand _ : NodeState) (_ : Event) (_ : List Model.Envelope) :=
  cand.currentTerm = pre.currentTerm ∧ (∃ v, pre.votedFor = some v) ∧
    hasQuorum cand.activeConfigurations cand.votesGranted

private theorem campUpper (h : Camp c false) : Elect.guard true c.actor c.pre c.event ∧ Voted c := by
  have packed : HandReadersTrunkBFactor.Tail.CampaignCall f t c WinsVoted := by
    rcases h with h | h | h | h
    all_goals
      obtain ⟨n,m,⟨before,cand,ev,sent,call,_,quorum,_,_,_,same,v,vote,_,_,_,_,_,_,_,stamp,_⟩,_⟩ := h
      have g : WinsVoted n before cand m ev sent := ⟨stamp.symm.trans same,⟨v,vote⟩,quorum⟩
      first | left; exact ⟨n,before,cand,m,ev,sent,call,g⟩
            | right; left; exact ⟨n,before,cand,m,ev,sent,call,g⟩
            | right; right; left; exact ⟨n,before,cand,m,ev,sent,call,g⟩
            | right; right; right; exact ⟨n,before,cand,m,ev,sent,call,g⟩
  obtain ⟨cand,origin,_,_,_,same,vote,q⟩ := (CampaignRows.origin_iff c _).mp packed
  cases origin with
  | fresh => exact (Nat.succ_ne_self _ same).elim
  | kept n r ev peer g => exact ⟨⟨n,r,ev,peer,g,fun _ => q⟩,vote⟩

private theorem campLower (g : Elect.guard true c.actor c.pre c.event) (voted : Voted c) : Camp c false := by
  obtain ⟨n,r,ev,peer,yes,quorum⟩ := g
  obtain ⟨v,vote⟩ := voted
  let cand := Elect.candidate c.pre n
  let m := primaryState cand
  have origin := CampaignRows.Origin.kept (self := c.actor) (st := c.pre) n r ev peer yes
  have camp : Campaign c.actor c.pre c.event cand := origin.campaign
  have a : Advance c.actor m m := .inl rfl
  have empty {p : Model.Envelope → Prop} : ∀ e ∈ [], p e := by simp
  have q : hasQuorum cand.activeConfigurations cand.votesGranted := quorum rfl
  have won : Wins c.actor c.pre c.event m := ⟨cand,camp,q,a⟩
  have result : CampaignResult c.actor c.pre cand m [] := .inr ⟨q,a,empty⟩
  have pass : ¬(True ∧ ¬n ∈ eligiblePeers c.pre c.actor) := fun h => h.2 peer
  obtain raised | stable := observe_bumping c.pre (message := .requestVoteResponse r) trivial
  · exact (Nat.not_lt_of_ge (Nat.le_of_eq yes.2.1) raised.1).elim
  right; left
  refine ⟨c.actor,m,⟨c.pre,cand,_,[],⟨n,r,⟨_,⟨rfl,rfl,rfl⟩,_,ev,ev,rfl⟩,pass,stable,stable.1,stable.2,
    yes,Or.inr ⟨yes.1,q,a,empty⟩,?_,rfl,rfl⟩,⟨q,a,empty⟩,q,⟨a,empty⟩,a,empty,rfl,v,vote,
    ?_,result,Nat.le_refl _,?_,?_,?_,a,rfl,ev ▸ won,fun p => Role.noConfusion p,rfl⟩,a⟩
  · exact ev ▸ camp
  · exact ev ▸ camp
  · simp [Engaged,yes.1]
  · intro p _; exact Role.noConfusion (yes.1.symm.trans p)
  · intro _ _ h; exact h

private theorem idIff : HandReadersBFactor.Tail.step_votedFor_advance_inl f t c ↔
    (Match.test false c.actor c.pre c.event c.post ∨ Elect.guard true c.actor c.pre c.event) ∧ Voted c := by
  change (_ ∨ _ ∨ Camp c false) ↔ _
  rw [←or_assoc]
  change (Base c false ∨ Camp c false) ↔ _
  rw [or_and_right]
  exact or_congr ⟨baseUpper c false,fun ⟨g,v⟩ => baseLower c false g v⟩
    ⟨campUpper c,fun ⟨g,v⟩ => campLower c g v⟩
end

def identity : Exact .votedFor_advance_inl where
  eval := SummaryRows.gated fun n st ev post => (Match.test false n st ev post || Elect.test true n st ev post) && st.votedFor.isSome
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff]
    change step_votedFor_advance_inl _ _ _ ↔ _
    rw [HandReadersTrunkA.Factor.Split.step_votedFor_advance_inl_iff,
      HandReadersBFactor.Exact.step_votedFor_advance_inl _ _ _ (HandReadersBGate.quiet s),idIff,
      SummaryRows.gated,Bool.and_eq_true,actorRead_at,HandReadersBGate.live,and_comm]
    simp only [Bool.and_eq_true,Bool.or_eq_true,Option.isSome_iff_exists,←Elect.guard_iff,Voted]

end ConsensusCoverage.HandReadersTrunkC.VoteSites
