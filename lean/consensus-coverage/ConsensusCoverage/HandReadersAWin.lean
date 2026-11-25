module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersABase
import all ConsensusCoverage.DeepLeaderCases
import all ConsensusCoverage.ReadersShapes
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersA.Win

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety ActionProfile SolvedWitnesses
set_option maxRecDepth 8192
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

def column (positive : Bool) : Classes.StepBranch :=
  if positive then .wins_elect_committed_pos else .wins_elect_committed_neg

def test (pos : Bool) (_ : NodeID) (pre : NodeState) (_ : Event) (post : NodeState) : Bool :=
  decide (post.role = .primary ∧ ¬(pre.role = .primary ∧ post.currentTerm = pre.currentTerm) ∧
    decide (0 < pre.commitIndex) = pos)

def reader (pos : Bool) : Reader := actorRead (test pos)

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private theorem iff_test (pos : Bool) : sig c (column pos) ↔ test pos c.actor c.pre c.event c.post = true := by
  rw [test,decide_eq_true_eq]
  constructor
  · intro h
    cases pos
    all_goals
      rcases h with h | h | h | h | h | h | h | h | h | h
      all_goals
        obtain ⟨_,cand,facts⟩ := h
        have campaign := facts.1.1
        have same : cand.commitIndex = c.pre.commitIndex := campaign.2.2.1
        have won : Wins c.actor c.pre c.event c.post := by
          repeat' first | assumption | rcases facts with ⟨item,facts⟩
        obtain ⟨role,fresh⟩ := (ReadersShapes.wins_recorded c).mp won
        refine ⟨role,fresh,?_⟩
        first | rw [decide_eq_true_eq] | rw [decide_eq_false_iff_not]
        rw [←same]
        repeat' first | assumption | rcases facts with ⟨_,facts⟩
  · rintro ⟨primary,fresh,cut⟩
    have now := c.post_now
    have win := (ReadersShapes.wins_recorded c).mpr ⟨primary,fresh⟩
    have root : (reach% step_leader_logs_commit_pos[0]) f t c c c.actor c.post := by
      refine ⟨now,primary,?_,rfl⟩
      rintro ⟨old,_⟩
      have eq := c.now_pre old
      exact fresh ⟨eq ▸ primary,congrArg NodeState.currentTerm eq⟩
    obtain ⟨candidate,facts⟩ := Wins.facts win
    obtain ⟨campaign,quorum,postLog,term,vote,matchEq,role,le⟩ := facts
    have three := c.campaign_three campaign
    obtain ⟨candRole,candLog,candCommit,active⟩ := campaign
    rw [←candCommit] at cut
    obtain ⟨bound,terms⟩ := three
    cases pos
    all_goals
      first | rw [decide_eq_true_eq] at cut | rw [decide_eq_false_iff_not] at cut
      refine Or.inl ⟨⟨root,now,primary,now,win,now,primary,rfl⟩,candidate,?_⟩
      repeat' first | assumption | apply And.intro
end

def exactReader (pos : Bool) : Exact (column pos) where
  eval := reader pos
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    rw [reader,actorRead_at]
    exact Bool.eq_iff_iff.mpr ((label_true s _).trans ((sig_iff _ _).trans (iff_test s.context pos)))

end ConsensusCoverage.HandReadersA.Win
