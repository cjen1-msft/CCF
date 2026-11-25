module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkARequest
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.AssistConflictA
import all ConsensusCoverage.AssistReplyBranchesA
import all ConsensusCoverage.AssistReplyA
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersBFactor

namespace ConsensusCoverage.HandReadersTrunkA.Request

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses
open HandReadersA ActionProfile AssistReplyA AssistReplyBranchesA AssistConflictA

set_option maxHeartbeats 1400000
set_option maxRecDepth 16384

open Lean Elab Command in
run_cmd liftTermElabM do
  for n in #[``step_aeReply_conflict_none,``step_aeReply_conflict_some] do
    HandReadersBFactor.compile n

def conflictColumn (overlap : Bool) : Classes.StepBranch :=
  if overlap then .aeReply_conflict_some else .aeReply_conflict_none

private def pass (overlap : Bool) (_ : NodeID) (st : NodeState) (q : AppendEntriesRequest) : Bool :=
  let z := observed st q
  decide (q.term = z.currentTerm ∧ appendEntryMatchesLog z q ∧ z.commitIndex ≤ q.prevLogIndex ∧
    ¬Bad z q) && ((firstTermConflictIndex (base z q) q).isSome == overlap)

private theorem conflictIff (s : Step) (overlap : Bool) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    sig s.context (conflictColumn overlap) ↔ HandReadersBGate.Source s.context ∧ ∃ src q,
      s.context.event = .receive src (.appendEntriesRequest q) ∧ pass overlap s.context.actor s.context.pre q := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  cases overlap
  all_goals first
    | rw [show sig s.context (conflictColumn false) = step_aeReply_conflict_none _ _ _ from rfl,
        HandReadersBFactor.Exact.step_aeReply_conflict_none _ _ _ (HandReadersBGate.quiet s)]
    | rw [show sig s.context (conflictColumn true) = step_aeReply_conflict_some _ _ _ from rfl,
        HandReadersBFactor.Exact.step_aeReply_conflict_some _ _ _ (HandReadersBGate.quiet s)]
  all_goals
    apply and_congr_right
    intro _
    constructor
  case false.mp =>
    rintro ⟨self,src,z,q,call,_,proceed,clear,_,_,_,_,_,_,_,_,_,_,_,same,_,matched,safe,_⟩
    obtain ⟨rfl,ev,rfl⟩ := (call_iff c self src z q).mp call
    exact ⟨src,q,ev,Bool.and_eq_true_iff.mpr ⟨decide_eq_true ⟨same,matched,safe,proceed⟩,
      by change ((firstTermConflictIndex _ _).isSome == false) = true; rw [clear]; rfl⟩⟩
  case true.mp =>
    rintro ⟨self,src,z,q,call,_,proceed,i,found,_,_,_,_,_,_,_,_,_,_,_,same,_,matched,safe,_⟩
    obtain ⟨rfl,ev,rfl⟩ := (call_iff c self src z q).mp call
    exact ⟨src,q,ev,Bool.and_eq_true_iff.mpr ⟨decide_eq_true ⟨same,matched,safe,proceed⟩,
      by change ((firstTermConflictIndex _ _).isSome == true) = true; rw [found]; rfl⟩⟩
  all_goals
    rintro ⟨src,q,ev,yes⟩
    let z := observed c.pre q
    let w := prepared z q
    have call := (call_iff c c.actor src z q).mpr ⟨rfl,ev,rfl⟩
    obtain ⟨g,over⟩ := Bool.and_eq_true_iff.mp yes
    obtain ⟨same,matched,safe,proceed⟩ := of_decide_eq_true g
    have p := fields z q
    have accept : ¬(q.term < w.currentTerm ∨ ¬appendEntryMatchesLog w q) := by
      rintro (lt | mismatch)
      · exact (Nat.not_lt_of_ge (Nat.le_of_eq (p.term.trans same.symm))) lt
      · exact mismatch (by simpa only [appendEntryMatchesLog,w,p.log] using matched)
    have eq : firstTermConflictIndex (base z q) q = conflictIndex z.log q := by
      rw [firstTermConflictIndex_eq]
      change conflictIndex w.log q = _
      rw [p.log]
    have lo := Nat.le_of_eq same
  case false.mpr =>
    have clear : firstTermConflictIndex (base z q) q = none :=
      Option.isNone_iff_eq_none.mp (Option.isSome_eq_false_iff.mp (beq_iff_eq.mp over))
    exact ⟨_,src,z,q,call,accept,proceed,clear,clear,lo,p.term,p.log,p.commit,p.vote,p.match_,p.role,p.cand,p.stays,
      common c.actor src z q,same,p.stays same,matched,safe,tail c.actor src z q same safe matched,eq⟩
  case true.mpr =>
    obtain ⟨i,found⟩ := Option.isSome_iff_exists.mp (beq_iff_eq.mp over)
    exact ⟨_,src,z,q,call,accept,proceed,i,found,found,lo,p.term,p.log,p.commit,p.vote,p.match_,p.role,p.cand,p.stays,
      common c.actor src z q,same,p.stays same,matched,safe,tail c.actor src z q same safe matched,eq⟩

def conflictReader (overlap : Bool) : Exact (conflictColumn overlap) :=
  exactOfTail _ (pass overlap) (conflictIff · overlap)

end ConsensusCoverage.HandReadersTrunkA.Request
