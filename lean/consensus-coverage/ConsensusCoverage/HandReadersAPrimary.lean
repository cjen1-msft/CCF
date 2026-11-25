module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersAWin
import all ConsensusCoverage.ReadersShapes
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersA.Primary

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety ActionProfile SolvedWitnesses
set_option maxRecDepth 8192
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

def identityReader : Reader := actorRead fun _ pre _ post =>
  decide (post.role = .primary ∧ ¬(pre.role = .primary ∧ post.currentTerm = pre.currentTerm))

def column (pos : Bool) : Classes.StepBranch :=
  if pos then .primaryState_log_prefix_commit_pos else .primaryState_log_prefix_commit_neg

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)

private theorem root (won : Wins c.actor c.pre c.event c.post) :
    (reach% step_primaryState_log_prefix_commit_pos[2,0]) f t c c := by
  have fresh := ((ReadersShapes.wins_recorded c).mp won).2
  exact ⟨⟨_,_,c.post_now,fun prev => by
    have eq := c.now_pre prev
    exact fresh ⟨eq ▸ ((ReadersShapes.wins_recorded c).mp won).1,congrArg NodeState.currentTerm eq⟩,
    rfl⟩,c.post_now,c.post_now,c.post_now,c.inv.terms _ _ c.pre_now,rfl⟩

private theorem phase (pos : Bool) : sig c (column pos) ↔
    Wins c.actor c.pre c.event c.post ∧ decide (0 < c.pre.commitIndex) = pos := by
  constructor
  · intro h
    cases pos
    all_goals
      rcases h with h | h | h | h | h | h | h
      all_goals
        obtain ⟨st,⟨_,won,_,facts,_⟩,cut⟩ := h
        rw [facts.1.2.2.1] at cut
        first | exact ⟨won,decide_eq_false cut⟩ | exact ⟨won,decide_eq_true cut⟩
  · rintro ⟨won,cut⟩
    obtain ⟨st,camp,quorum,log,term,vote,peers,role,le⟩ := Wins.facts won
    have site : (reach% step_primaryState_log_prefix_commit_pos[2]) f t c st :=
      ⟨root c won,won,rfl,⟨camp,quorum,log,term,vote,peers,role,le⟩,camp,
        ⟨quorum,log,term,vote,peers,role,le⟩,camp.1,camp.2,camp.2.1,camp.2.2,
        quorum,log,term,vote,peers,role,le⟩
    rw [←camp.2.2.1] at cut
    cases pos
    all_goals
      refine Or.inr (Or.inr (Or.inl ⟨st,site,?_⟩))
      first | exact of_decide_eq_true cut | exact of_decide_eq_false cut

private theorem identity_iff : step_facts_advance_inl_2 f t c ↔ Wins c.actor c.pre c.event c.post := by
  constructor
  · intro h
    rcases h with h | h | h | h | h | h | h | h | h | h | h | h | h | h | h | h | h
    all_goals
      obtain ⟨_,_,_,_,site,_⟩ := h
      try (change _ ∨ _ at site; rcases site with site | site)
      all_goals repeat' first | exact site | exact site.1 | obtain ⟨_,site⟩ := site
  · intro won
    have site : (reach% step_facts_advance_inl_2[4]) f t c c.actor c.pre c.event c.post :=
      ⟨root c won,won,rfl,rfl,rfl,rfl,rfl⟩
    obtain ⟨cand,camp,quorum,adv⟩ := won
    have same := adv.resolve_right fun growth => by
      have lt := growth.2.2.2.2.2.2.1
      rw [growth.2.2.2.2.2.2.2.1] at lt
      exact (Nat.not_lt_of_le (ReadersShapes.campaign_no_advance camp)) lt
    iterate 4 right
    exact Or.inl ⟨_,_,_,_,site,cand,⟨camp,quorum,adv⟩,camp,⟨quorum,adv⟩,quorum,adv,
      camp.1,camp.2.1,camp.2.2.1,camp.2.2.2,same,⟨cand,camp,quorum,adv⟩⟩
end

def exactReader (pos : Bool) : Exact (column pos) where
  eval := Win.reader pos
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff,phase,ReadersShapes.wins_recorded,Win.reader,actorRead_at,Win.test,
      decide_eq_true_eq,and_assoc]

def exactIdentity : Exact .facts_advance_inl_2 where
  eval := identityReader
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff,identityReader,actorRead_at,decide_eq_true_eq,←ReadersShapes.wins_recorded]
    exact identity_iff s.context

end ConsensusCoverage.HandReadersA.Primary
