module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkCReplyBound
import all ConsensusCoverage.HandReadersTrunkCReplySites
import all ConsensusCoverage.HandReadersTrunkARoles
import all ConsensusCoverage.HandReadersTrunkARoleRoute
import all ConsensusCoverage.HandReadersTrunkARequest
import all ConsensusCoverage.AssistConflictA
import all ConsensusCoverage.AssistReplyBranchesA
import all ConsensusCoverage.AssistReplyA
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersTrunkC.Reply

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses
open HandReadersA HandReadersTrunkA HandReadersTrunkA.Request ActionProfile AssistReplyA AssistReplyBranchesA AssistConflictA

set_option maxRecDepth 16384
set_option maxHeartbeats 1600000

private abbrev Guard (pos : Bool) (z : NodeState) (q : AppendEntriesRequest) :=
  if pos then stepsDown z q else ¬stepsDown z q

private abbrev SitesAt (pos : Bool) := if pos then Route.step_aeReply_stepDown_pos else Route.step_aeReply_stepDown_neg

local macro "fill_fields" : tactic => `(tactic| repeat' first | assumption | rfl | apply And.intro)

private theorem supply (pos : Bool) (n src : NodeID) (z : NodeState) (q : AppendEntriesRequest)
    (le : q.term ≤ z.currentTerm) (g : Guard pos z q) : SitesAt pos n src z q := by
  let w := prepared z q
  let v := base z q
  obtain ⟨term,log,commit,vote,rep,role,cand,stays⟩ := fields z q
  by_cases reject : Rejected z q
  · by_cases missing : q.term < w.currentTerm ∨ termAt w.log q.prevLogIndex = 0
    · cases pos <;> left <;> exact ⟨reject,missing,g,le,log,commit,vote,rep,role,cand,stays⟩
    · cases pos <;> right <;> left <;> exact ⟨reject,missing,g,le,log,commit,vote,rep,role,cand,stays⟩
  have same := Nat.le_antisymm le (term ▸ Nat.le_of_not_lt (not_or.mp reject).1)
  have notCand := stays same
  by_cases bad : Bad z q
  · cases pos <;> right <;> right <;> left <;> exact ⟨reject,bad,g,le,log,commit,vote,rep,role,cand,stays,same,notCand⟩
  have matched : appendEntryMatchesLog z q := by
    simpa only [appendEntryMatchesLog,log] using Classical.not_not.mp (not_or.mp reject).2
  have safe : z.commitIndex ≤ q.prevLogIndex := by
    rw [←commit]; exact Nat.le_of_not_lt (fun e => bad (.inl e))
  have eq : firstTermConflictIndex v q = conflictIndex z.log q := by
    rw [firstTermConflictIndex_eq]; change conflictIndex w.log q = _; rw [log]
  cases found : firstTermConflictIndex v q with
  | none =>
    obtain ⟨rt,rv,rm,vs,rr,rl,rc,response⟩ := fromLeader_spec n v q
    have pair : handleAppendEntiresFromPrimary n v q = ((handleAppendEntiresFromPrimary n v q).1,
        {term := v.currentTerm,success := true,lastLogIndex := q.prevLogIndex+q.entries.length}) := Prod.ext rfl response
    cases pos <;> right <;> right <;> right <;> left
    all_goals refine ⟨reject,bad,found,found,_,pair,?_⟩; fill_fields
  | some i =>
    let m := {v with log := v.log.take (i-1),isNewFollower := false}
    obtain ⟨rt,rv,rm,vs,rr,rl,rc,response⟩ := fromLeader_spec n m q
    have pair : handleAppendEntiresFromPrimary n m q = ((handleAppendEntiresFromPrimary n m q).1,
        {term := m.currentTerm,success := true,lastLogIndex := q.prevLogIndex+q.entries.length}) := Prod.ext rfl response
    cases pos <;> right <;> right <;> right <;> right
    all_goals refine ⟨reject,bad,i,found,found,_,pair,?_⟩; fill_fields

def column (pos : Bool) : Classes.StepBranch := if pos then .aeReply_stepDown_pos else .aeReply_stepDown_neg

def reader (pos : Bool) : Exact (column pos) :=
  Request.exactOfTail _ (fun _ st q => if pos then decide (stepsDown (observed st q) q) else decide (¬stepsDown (observed st q) q))
    fun s => by
      letI : Config.InitialConfiguration := ⟨s.cfg⟩
      let c := s.context
      have quiet := HandReadersBGate.quiet s
      constructor
      · intro live
        cases pos
        all_goals first
          | have h := Bound.step_aeReply_stepDown_neg_bound_necessary _ _ c live
            rw [HandReadersBFactor.Exact.step_aeReply_stepDown_neg_bound _ _ _ quiet,
              Route.step_aeReply_stepDown_neg_bound_iff] at h
          | have h := Bound.step_aeReply_stepDown_pos_bound_necessary _ _ c live
            rw [HandReadersBFactor.Exact.step_aeReply_stepDown_pos_bound _ _ _ quiet,
              Route.step_aeReply_stepDown_pos_bound_iff] at h
        all_goals
          obtain ⟨active,src,q,ev,guard⟩ := h
          refine ⟨active,src,q,ev,?_⟩
          rcases guard with guard | guard <;> simpa only [Bool.false_eq_true,ite_false,ite_true,decide_eq_true_eq] using guard
      · rintro ⟨active,src,q,ev,yes⟩
        have le : q.term ≤ (observed c.pre q).currentTerm := by
          obtain raised | stable := observe_bumping c.pre (message := .appendEntriesRequest q) trivial
          · rw [show observed c.pre q = _ from raised.2]; exact Nat.le_refl _
          · rw [show observed c.pre q = _ from stable.2]; exact stable.1
        have guard : Guard pos (observed c.pre q) q := by
          cases pos <;> simpa only [Guard,Bool.false_eq_true,ite_false,ite_true,decide_eq_true_eq] using yes
        have site := supply pos c.actor src (observed c.pre q) q le guard
        cases pos
        · apply Sites.step_aeReply_stepDown_neg_supply
          rw [HandReadersBFactor.Exact.step_aeReply_stepDown_neg _ _ _ quiet,Route.step_aeReply_stepDown_neg_iff]
          exact ⟨active,src,q,ev,site⟩
        · apply Sites.step_aeReply_stepDown_pos_supply
          rw [HandReadersBFactor.Exact.step_aeReply_stepDown_pos _ _ _ quiet,Route.step_aeReply_stepDown_pos_iff]
          exact ⟨active,src,q,ev,site⟩

end ConsensusCoverage.HandReadersTrunkC.Reply
