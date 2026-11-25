module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkARoleRoute
import all ConsensusCoverage.HandReadersTrunkARequest
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.AssistConflictA
import all ConsensusCoverage.AssistReplyBranchesA
import all ConsensusCoverage.AssistReplyA
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersTrunkARoleRoute

namespace ConsensusCoverage.HandReadersTrunkA.Request

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses
open HandReadersA ActionProfile AssistReplyA AssistConflictA AssistReplyBranchesA

set_option maxRecDepth 16384
set_option maxHeartbeats 1800000

inductive RoleCase where | retain | retired | unchanged | follower

def roleColumn : RoleCase → Classes.StepBranch
  | .retain => .aeReply_role_inl
  | .retired => .aeReply_role_inr
  | .unchanged => .aeReply_wRole_inl
  | .follower => .aeReply_wRole_inr

private def branches : RoleCase → NodeID → NodeID → NodeState → AppendEntriesRequest → Prop
  | .retain => Route.step_aeReply_role_inl
  | .retired => Route.step_aeReply_role_inr
  | .unchanged => Route.step_aeReply_wRole_inl
  | .follower => Route.step_aeReply_wRole_inr

private abbrev Rejected (z : NodeState) (q : AppendEntriesRequest) :=
  q.term < (prepared z q).currentTerm ∨ ¬appendEntryMatchesLog (prepared z q) q

private def roleTest (k : RoleCase) (self : NodeID) (z : NodeState) (q : AppendEntriesRequest) : Bool :=
  let w := prepared z q
  let out := if Rejected z q ∨ Bad z q then w.role else
    let v := base z q
    let m := match firstTermConflictIndex v q with
      | none => v
      | some i => {v with log := v.log.take (i-1),isNewFollower := false}
    (handleAppendEntiresFromPrimary self m q).1.role
  match k with
  | .retain => decide (out = w.role)
  | .retired => decide (out = .none)
  | .unchanged => decide (out = w.role ∧ w.role = z.role)
  | .follower => decide (out = w.role ∧ w.role = .follower)

private abbrev RoleOK (k : RoleCase) (result work observed : Role) : Prop :=
  match k with
  | .retain => result = work
  | .retired => result = .none
  | .unchanged => result = work ∧ work = observed
  | .follower => result = work ∧ work = .follower

private theorem testEarly (k : RoleCase) {n z q} (early : Rejected z q ∨ Bad z q) :
    roleTest k n z q ↔ RoleOK k (prepared z q).role (prepared z q).role z.role := by
  cases k <;> simp only [roleTest,early,ite_true,decide_eq_true_eq,RoleOK]

private def working (z : NodeState) (q : AppendEntriesRequest) : NodeState :=
  let v := base z q
  match firstTermConflictIndex v q with
  | none => v
  | some i => {v with log := v.log.take (i-1),isNewFollower := false}

private theorem testLater (k : RoleCase) {n z q} (late : ¬(Rejected z q ∨ Bad z q)) :
    roleTest k n z q ↔ RoleOK k (handleAppendEntiresFromPrimary n (working z q) q).1.role
      (prepared z q).role z.role := by
  cases k <;> simp only [roleTest,late,ite_false,decide_eq_true_eq,RoleOK,working]

private theorem workNone {z q} (h : firstTermConflictIndex (base z q) q = none) :
    working z q = base z q := by simp only [working,h]

private theorem workSome {z q i} (h : firstTermConflictIndex (base z q) q = some i) :
    working z q = {base z q with log := (base z q).log.take (i-1),isNewFollower := false} := by
  simp only [working,h]

local macro "use_fields" : tactic => `(tactic|
  repeat' first | assumption | rfl | exact Or.inl rfl | exact Or.inr rfl | apply And.intro)

private theorem role_iff (k : RoleCase) (n src : NodeID) (z : NodeState) (q : AppendEntriesRequest)
    (lo : q.term ≤ z.currentTerm) : branches k n src z q ↔ roleTest k n z q := by
  let w := prepared z q
  let v := base z q
  have ⟨term,log,commit,vote,match_,role,cand,stays⟩ := fields z q
  constructor
  · cases k
    all_goals
      rintro (⟨r,_,h⟩ | ⟨r,_,h⟩ | ⟨_,b,h⟩ | ⟨nr,nb,found,_,res,pair,h⟩ |
        ⟨nr,nb,i,found,_,res,pair,h⟩)
    all_goals first
      | (apply (testEarly _ (.inl r)).mpr
         repeat' rcases h with ⟨a,h⟩
         use_fields
         done)
      | (apply (testEarly _ (.inr b)).mpr
         repeat' rcases h with ⟨a,h⟩
         use_fields
         done)
      | (apply (testLater _ (not_or.mpr ⟨nr,nb⟩)).mpr
         first | rw [workNone found] | rw [workSome found]
         simp only [RoleOK,pair]
         repeat' rcases h with ⟨a,h⟩
         use_fields)
  · intro yes
    by_cases reject : Rejected z q
    · have ok := (testEarly k (.inl reject)).mp yes
      by_cases missing : q.term < w.currentTerm ∨ termAt w.log q.prevLogIndex = 0
      · cases k <;> left <;> first | (use_fields; done) | (rcases ok with ⟨_,h⟩; use_fields)
      · cases k <;> right <;> left <;> first | (use_fields; done) | (rcases ok with ⟨_,h⟩; use_fields)
    have same := Nat.le_antisymm lo (term ▸ Nat.le_of_not_lt (not_or.mp reject).1)
    have notCand := stays same
    by_cases bad : Bad z q
    · have ok := (testEarly k (.inr bad)).mp yes
      cases k <;> right <;> right <;> left <;> first | (use_fields; done) | (rcases ok with ⟨_,h⟩; use_fields)
    have ok := (testLater k (not_or.mpr ⟨reject,bad⟩)).mp yes
    have matched : appendEntryMatchesLog z q := by
      simpa only [appendEntryMatchesLog,log] using Classical.not_not.mp (not_or.mp reject).2
    have safe : z.commitIndex ≤ q.prevLogIndex := by
      rw [← commit]; exact Nat.le_of_not_lt (fun e => bad (.inl e))
    have eq : firstTermConflictIndex v q = conflictIndex z.log q := by
      rw [firstTermConflictIndex_eq]; change conflictIndex w.log q = _; rw [log]
    cases found : firstTermConflictIndex v q with
    | none =>
      obtain ⟨rt,rv,rm,vs,rr,rl,rc,response⟩ := fromLeader_spec n v q
      have pair : handleAppendEntiresFromPrimary n v q = ((handleAppendEntiresFromPrimary n v q).1,
          {term := v.currentTerm,success := true,lastLogIndex := q.prevLogIndex+q.entries.length}) := Prod.ext rfl response
      rw [workNone found] at ok
      cases k <;> right <;> right <;> right <;> left
      all_goals
        refine ⟨reject,bad,found,found,_,pair,?_⟩
        first | (use_fields; done) | (rcases ok with ⟨_,h⟩; use_fields)
    | some i =>
      let m := {v with log := v.log.take (i-1),isNewFollower := false}
      obtain ⟨rt,rv,rm,vs,rr,rl,rc,response⟩ := fromLeader_spec n m q
      have pair : handleAppendEntiresFromPrimary n m q = ((handleAppendEntiresFromPrimary n m q).1,
          {term := m.currentTerm,success := true,lastLogIndex := q.prevLogIndex+q.entries.length}) := Prod.ext rfl response
      rw [workSome found] at ok
      cases k <;> right <;> right <;> right <;> right
      all_goals
        refine ⟨reject,bad,i,found,found,_,pair,?_⟩
        first | (use_fields; done) | (rcases ok with ⟨_,h⟩; use_fields)

private theorem roleAt (s : Step) (k : RoleCase) : letI : Config.InitialConfiguration := ⟨s.cfg⟩
    sig s.context (roleColumn k) ↔ HandReadersBGate.Source s.context ∧ At s.context (branches k) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have no := HandReadersBGate.quiet s
  cases k
  all_goals first
    | exact (HandReadersBFactor.Exact.step_aeReply_role_inl _ _ _ no).trans
        (and_congr_right fun _ => Route.step_aeReply_role_inl_iff _ _ _)
    | exact (HandReadersBFactor.Exact.step_aeReply_role_inr _ _ _ no).trans
        (and_congr_right fun _ => Route.step_aeReply_role_inr_iff _ _ _)
    | exact (HandReadersBFactor.Exact.step_aeReply_wRole_inl _ _ _ no).trans
        (and_congr_right fun _ => Route.step_aeReply_wRole_inl_iff _ _ _)
    | exact (HandReadersBFactor.Exact.step_aeReply_wRole_inr _ _ _ no).trans
        (and_congr_right fun _ => Route.step_aeReply_wRole_inr_iff _ _ _)

def roleReader (k : RoleCase) : Exact (roleColumn k) :=
  exactOfTail _ (fun n st q => roleTest k n (observed st q) q) fun s => by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    rw [roleAt]
    apply and_congr_right
    intro _
    apply exists_congr; intro src
    apply exists_congr; intro q
    apply and_congr_right; intro _
    apply role_iff
    obtain raised | stable := observe_bumping s.context.pre (message := .appendEntriesRequest q) trivial
    · rw [show observed s.context.pre q = _ from raised.2]; exact Nat.le_refl _
    · rw [show observed s.context.pre q = _ from stable.2]; exact stable.1

end ConsensusCoverage.HandReadersTrunkA.Request
