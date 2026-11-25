module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkCRoute
import all ConsensusCoverage.HandReadersTrunkCFold
import all ConsensusCoverage.HandReadersTrunkARoles
import all ConsensusCoverage.HandReadersTrunkALoopGate
import all ConsensusCoverage.HandReadersTrunkARequest
import all ConsensusCoverage.HandReadersAObserve
import all ConsensusCoverage.AssistConflictA
import all ConsensusCoverage.AssistReplyBranchesA
import all ConsensusCoverage.AssistReplyA
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersTrunkC.Fold

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses
open HandReadersA HandReadersTrunkA ActionProfile AssistReplyA AssistReplyBranchesA AssistConflictA

set_option maxRecDepth 16384
set_option maxHeartbeats 1400000

private def test (r : Bool) (n : NodeID) (st : NodeState) (q : AppendEntriesRequest) :=
  Loop.accepted n st q && check r n (Request.working (observed st q) q) q

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private abbrev Good (r : Bool) :=
  ∃ src q, c.event = .receive src (.appendEntriesRequest q) ∧ test r c.actor c.pre q

omit [Config.InitialConfiguration] in
private theorem lo (st : NodeState) (q : AppendEntriesRequest) :
    q.term ≤ (observed st q).currentTerm := by
  obtain raised | stable := observe_bumping st (message := .appendEntriesRequest q) trivial
  · rw [show observed st q = _ from raised.2]; exact Nat.le_refl _
  · rw [show observed st q = _ from stable.2]; exact stable.1

private theorem direct (r : Bool) (h : guarded r
    ((reach% step_handleAppendEntiresFromPrimary_eq_roleCase__inl[0]) f t c)) :
    HandReadersBGate.Source c ∧ Good c r := by
  obtain ⟨n,st,q,⟨caller,_⟩,yes⟩ := h
  rcases caller with ⟨z,entry,nr,nb,found,_,_,_,_,eq⟩ | ⟨z,entry,nr,nb,i,found,_,_,_,_,_,eq⟩
  all_goals
    obtain ⟨pre,src,_,call,_,rfl,_,_,_,rfl⟩ := entry
    obtain ⟨fresh,rfl,rfl,ev⟩ := (Observe.receive_iff c).mp call
    refine ⟨.node fresh,src,q,ev,Bool.and_eq_true_iff.mpr ⟨decide_eq_true (Loop.acceptsOf (lo _ _) nr nb),?_⟩⟩
    first | rw [Request.workNone found] | rw [Request.workSome found]
    subst st; exact yes

private abbrev Tail (r : Bool) := if r then HandReadersBFactor.Tail.RetiredSummary f t c
  else HandReadersBFactor.Tail.SameSummary f t c

private theorem tail_iff (r : Bool) : Tail c r ↔ Good c r := by
  constructor
  · cases r
    all_goals
      rintro (⟨n,st,q,⟨src,z,call,nr,nb,found,h⟩,yes⟩ |
        ⟨n,st,q,⟨src,z,call,nr,nb,found,h⟩,yes⟩ |
        ⟨n,st,q,⟨src,z,call,nr,nb,i,found,h⟩,yes⟩ |
        ⟨n,st,q,⟨src,z,call,nr,nb,i,found,h⟩,yes⟩)
    all_goals
      have co : Request.Call f t c n src z q := by first | exact .inl call | exact .inr call
      obtain ⟨rfl,ev,rfl⟩ := (Request.call_iff c _ _ _ _).mp co
      refine ⟨src,q,ev,Bool.and_eq_true_iff.mpr ⟨decide_eq_true (Loop.acceptsOf (lo _ _) nr nb),?_⟩⟩
      first | rw [Request.workNone found] | rw [Request.workSome found]
      obtain ⟨_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,eq⟩ := h
      subst st; exact yes
  · rintro ⟨src,q,ev,enabled⟩
    obtain ⟨ok,yes⟩ := Bool.and_eq_true_iff.mp enabled
    let z := observed c.pre q
    let v := base z q
    obtain ⟨same,matched,safe,proceed⟩ := of_decide_eq_true ok
    have p := fields z q
    have accept : ¬(q.term < (prepared z q).currentTerm ∨ ¬appendEntryMatchesLog (prepared z q) q) := by
      rintro (lt | mismatch)
      · exact (Nat.not_lt_of_ge (Nat.le_of_eq (p.term.trans same.symm))) lt
      · exact mismatch (by simpa only [appendEntryMatchesLog,p.log] using matched)
    have eq : firstTermConflictIndex v q = conflictIndex z.log q := by
      rw [firstTermConflictIndex_eq]; change conflictIndex (prepared z q).log q = _; rw [p.log]
    have call := (Request.call_iff c c.actor src z q).mpr ⟨rfl,ev,rfl⟩
    have bound := Nat.le_of_eq same
    cases found : firstTermConflictIndex v q with
    | none =>
      rw [Request.workNone found] at yes
      rcases call with call | call <;> cases r
      all_goals first | left; refine ⟨_,_,q,⟨src,z,call,?_⟩,yes⟩ | right; left; refine ⟨_,_,q,⟨src,z,call,?_⟩,yes⟩
      all_goals exact ⟨accept,proceed,found,found,_,_,rfl,bound,p.term,p.log,p.commit,p.vote,p.match_,p.role,
        p.cand,p.stays,common c.actor src z q,same,p.stays same,matched,safe,eq,rfl⟩
    | some i =>
      rw [Request.workSome found] at yes
      rcases call with call | call <;> cases r
      all_goals right; right
      all_goals first | left; refine ⟨_,_,q,⟨src,z,call,?_⟩,yes⟩ | right; refine ⟨_,_,q,⟨src,z,call,?_⟩,yes⟩
      all_goals exact ⟨accept,proceed,i,found,found,_,_,rfl,bound,p.term,p.log,p.commit,p.vote,p.match_,p.role,
        p.cand,p.stays,common c.actor src z q,same,p.stays same,matched,safe,eq,rfl⟩
end

def column (retired : Bool) : Classes.StepBranch :=
  if retired then .handleAppendEntiresFromPrimary_eq_roleCase__inr else .handleAppendEntiresFromPrimary_eq_roleCase__inl

def reader (retired : Bool) : Exact (column retired) := Request.exactOfTail _ (test retired) fun s => by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  cases retired
  · change step_handleAppendEntiresFromPrimary_eq_roleCase__inl _ _ _ ↔ _
    rw [SameSummary_iff,Factor.Split.SameSummary_iff,HandReadersBFactor.Exact.SameSummary _ _ _ (HandReadersBGate.quiet s)]
    exact (or_congr Iff.rfl (and_congr_right fun _ => tail_iff _ false)).trans
      (or_iff_right_of_imp (direct _ false))
  · change step_handleAppendEntiresFromPrimary_eq_roleCase__inr _ _ _ ↔ _
    rw [RetiredSummary_iff,Factor.Split.RetiredSummary_iff,HandReadersBFactor.Exact.RetiredSummary _ _ _ (HandReadersBGate.quiet s)]
    exact (or_congr Iff.rfl (and_congr_right fun _ => tail_iff _ true)).trans
      (or_iff_right_of_imp (direct _ true))

end ConsensusCoverage.HandReadersTrunkC.Fold
