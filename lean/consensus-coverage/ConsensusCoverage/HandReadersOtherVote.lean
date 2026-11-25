module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersACampaign
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersOther.Vote

open Consensus Model Model.Node Proofs Safety Ledger ActionProfile SolvedWitnesses HandReadersA

set_option maxRecDepth 8192

private theorem alias [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t) :
    step_vals_upToDate_lt_or_eq_of_le_inr f t c ↔ step_campaign_votes_campaign_inl f t c := by
  constructor
  · intro h
    repeat' (change _ ∨ _ at h; rcases h with h | h)
    all_goals
      obtain ⟨_,⟨⟨cand,site,r,rest,log,rest',com,alts,fresh,eng,fo,term,vv,vote,votes,
        _,_,camp,postTerm,postVote,_,_⟩,_⟩,_⟩ := h
      repeat' first
        | exact ⟨cand,site,r,rest,log,rest',com,alts,fresh,eng,fo,term,vv,vote,votes,camp,postTerm,postVote⟩
        | exact Or.inl ⟨cand,site,r,rest,log,rest',com,alts,fresh,eng,fo,term,vv,vote,votes,camp,postTerm,postVote⟩
        | apply Or.inr
  · intro h
    obtain ⟨higher,sites⟩ := CampaignRows.necessary c true true h
    obtain ⟨cand,camp,postTerm,postVote,site⟩ := CampaignRows.supply c true sites
    have lt := of_decide_eq_true higher
    have ⟨r,log,com,alts⟩ := camp
    have fresh := alts.resolve_right fun old => (Nat.ne_of_lt lt) (postTerm.trans old.2.1).symm
    have mem : c.actor ∈ cand.votesGranted := by rw [fresh.2.2.2]; exact CCF.Finset.mem_singleton.mpr rfl
    have bound : c.pre.commitIndex ≤ maxCommittableIndex c.pre.log := by
      rcases Nat.eq_zero_or_pos c.pre.commitIndex with e | p
      · rw [e]; exact Nat.zero_le _
      · exact signatureIndex_le_maxCommittableIndex ((c.inv.frontier _ _ c.pre_now).2 p)
    have same : maxCommittableTerm c.pre.log =
        termAt c.pre.log (max c.pre.commitIndex (maxCommittableIndex c.pre.log)) := by rw [Nat.max_eq_right bound]; rfl
    rcases site with site | site
    case' inl => left
    case' inr => right; left
    all_goals
      exact ⟨c.pre,⟨⟨cand,site,r,camp.2,log,camp.2.2,com,alts,fresh,fresh.1,fresh.2,fresh.2.1,
        fresh.2.2,fresh.2.2.1,fresh.2.2.2,c.actor,mem,camp,postTerm,postVote,rfl,postTerm⟩,
        c.term_le,postVote.trans fresh.2.2.1,rfl⟩,same,c.pre_sorted,c.frontier_pre,Nat.le_of_eq same⟩

def exactReader : Exact .vals_upToDate_lt_or_eq_of_le_inr where
  eval := CampaignRows.reader true true
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    apply Eq.trans _ ((CampaignRows.exactReader true true).eq_label s)
    apply Bool.eq_iff_iff.mpr
    rw [label_true,label_true,holds,holds,sig_iff,sig_iff]
    exact alias s.context

end ConsensusCoverage.HandReadersOther.Vote
