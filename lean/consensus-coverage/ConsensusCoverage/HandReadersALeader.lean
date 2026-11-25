module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersABase
import all ConsensusCoverage.ReadersShapes
import all ConsensusCoverage.DeepLeaderCases
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersA.Leader

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses ActionProfile

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192

def column (positive : Bool) : Classes.StepBranch :=
  if positive then .leader_logs_commit_pos else .leader_logs_commit_neg

def test (positive : Bool) (_ : NodeID) (pre : NodeState) (_ : Event) (post : NodeState) : Bool :=
  decide (post.role = .primary ∧ ¬(pre.role = .primary ∧ post.currentTerm = pre.currentTerm) ∧
    pre.log ≠ [] ∧ decide (0 < pre.commitIndex) = positive)

private theorem iff_test [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)
    (pos : Bool) : sig c (column pos) ↔ test pos c.actor c.pre c.event c.post = true := by
  rw [test, decide_eq_true_eq]
  constructor
  · intro h
    cases pos
    all_goals
      obtain ⟨_,_,_,_,win,candidate,facts⟩ := h
      obtain ⟨primary,fresh⟩ := (ReadersShapes.wins_recorded c).mp win
      refine ⟨primary,fresh,?_,?_⟩ <;> grind (splits := 0)
  · rintro ⟨primary,fresh,log,cut⟩
    have now := c.post_now
    have win := (ReadersShapes.wins_recorded c).mpr ⟨primary,fresh⟩
    have root : (reach% step_leader_logs_commit_pos[0]) f t c c c.actor c.post := by
      refine ⟨now,primary,?_,rfl⟩
      rintro ⟨old,_⟩
      have eq := c.now_pre old
      exact fresh ⟨eq ▸ primary,congrArg NodeState.currentTerm eq⟩
    obtain ⟨candidate, facts⟩ := Wins.facts win
    obtain ⟨campaign,quorum,postLog,term,vote,matchEq,role,le⟩ := facts
    obtain ⟨candRole,candLog,candCommit,active⟩ := campaign
    rw [← candCommit] at cut
    cases pos
    all_goals
      refine ⟨root,now,primary,now,win,candidate,?_⟩
      first | rw [decide_eq_false_iff_not] at cut | rw [decide_eq_true_eq] at cut
      repeat' first | assumption | apply And.intro

def exactReader (pos : Bool) : Exact (column pos) where
  eval := actorRead (test pos)
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    rw [actorRead_at]
    exact Bool.eq_iff_iff.mpr ((label_true s _).trans ((sig_iff _ _).trans (iff_test s.context pos)))

end ConsensusCoverage.HandReadersA.Leader
