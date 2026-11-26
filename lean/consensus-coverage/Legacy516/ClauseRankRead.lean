module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersElectionRank
import all ConsensusCoverage.HandReadersElectionRankSites
import all ConsensusCoverage.SolvedWitnesses
public import ConsensusCoverage.ActionProfile
import all ConsensusCoverage.ActionProfile
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.ClauseRankRead

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open ActionProfile HandReadersElection SolvedWitnesses

set_option maxHeartbeats 0
set_option maxRecDepth 8192

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private theorem retained_iff :
    sig c .rankAtGrant_persist_inl ↔ Rank.Evidence c .ahead ∨ Rank.Evidence c .tied := by
  constructor
  · intro h
    repeat' (change _ ∨ _ at h; rcases h with h | h)
    all_goals
      obtain ⟨v,n,term,r,k,l,i,site,st,_,post,edge,_,_,_,_,_,_,_,_,_,up,sub,_⟩ := h
      have input : RankSites.Input c v n term r k l i := RankSites.necessary c (by
        repeat' first | exact site | left; exact site | right)
      rcases up with ahead | tied
      · exact .inl ⟨_,_,_,_,_,_,_,_,_,input,edge.1,edge.2.1,edge.2.2.1,edge.2.2.2.1,
          edge.2.2.2.2.1,sub,decide_eq_true ahead⟩
      · exact .inr ⟨_,_,_,_,_,_,_,_,_,input,edge.1,edge.2.1,edge.2.2.1,edge.2.2.2.1,
          edge.2.2.2.2.1,sub,Bool.and_eq_true_iff.mpr ⟨beq_iff_eq.mpr tied.1,decide_eq_true tied.2⟩⟩
  · rintro (e | e)
    all_goals
      obtain ⟨v,n,term,r,k,l,i,st,post,input,pre,now,le,stamp,vote,sub,cut⟩ := e
      have hit := input.2.1
      obtain ⟨_,_,_,seen,_,signed,atI⟩ := id input
      have up : voteLogUpToDate st r := Rank.cut_up _ cut
      have edge := And.intro pre (And.intro now (And.intro le (And.intro stamp (And.intro vote up))))
      obtain a | a := RankSites.sufficient c input
      · left
        exact ⟨v,n,term,r,k,l,i,a,st,⟨post,edge⟩,post,edge,pre,edge.2,now,edge.2.2,le,
          edge.2.2.2,stamp,⟨vote,up⟩,vote,up,sub,seen,signed,atI,hit⟩
      · right; left
        exact ⟨v,n,term,r,k,l,i,a,st,⟨post,edge⟩,post,edge,pre,edge.2,now,edge.2.2,le,
          edge.2.2.2,stamp,⟨vote,up⟩,vote,up,sub,seen,signed,atI,hit⟩
end

public def retained (s : Step) :=
  Rank.reader .ahead s.cfg s.before s.act s.after s.past ||
    Rank.reader .tied s.cfg s.before s.act s.after s.past

public theorem retained_eq (s : Step) : label s (.step .rankAtGrant_persist_inl) = retained s := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  apply Bool.eq_iff_iff.mpr
  have a := (Rank.exactReader .ahead).eq_label s
  have t := (Rank.exactReader .tied).eq_label s
  change _ = Rank.reader .ahead s.cfg s.before s.act s.after s.past at a
  change _ = Rank.reader .tied s.cfg s.before s.act s.after s.past at t
  rw [retained,Bool.or_eq_true,←a,←t,label_true,label_true,label_true]
  change PinnedClasses.sig s.context _ ↔ PinnedClasses.sig s.context _ ∨ PinnedClasses.sig s.context _
  simp only [SolvedWitnesses.sig_iff]
  exact (retained_iff s.context).trans (or_congr
    ⟨Rank.sufficient s.context .ahead, Rank.necessary s.context .ahead⟩
    ⟨Rank.sufficient s.context .tied, Rank.necessary s.context .tied⟩)

end ConsensusCoverage.ClauseRankRead
