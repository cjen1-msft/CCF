module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersASummary
import all ConsensusCoverage.HandReadersTrunkBFactor
import all ConsensusCoverage.SelfQuorumCasesB
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersTrunkBFactor

namespace ConsensusCoverage.HandReadersTrunkB.Candidate

open Consensus Model Model.Node Proofs Safety ActionProfile HandReadersA HandReadersBGate SolvedWitnesses
open Lean Elab Command

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxHeartbeats 3000000
set_option maxRecDepth 16384

def test (win : Bool) (self : NodeID) (st : NodeState) (ev : Event) (_ : NodeState) : Bool :=
  let live := match ev with
    | .internal (.timeout .election) => decide (canStartElection st self ∧ hasQuorum st.activeConfigurations {self})
    | .receive n (.requestPreVoteResponse q) =>
      decide (n ∈ eligiblePeers st self ∧ st.role = .preVoteCandidate ∧ q.term = st.currentTerm ∧
        q.voteGranted = true ∧ hasQuorum st.activeConfigurations (insert n st.preVotesGranted))
    | .receive _ (.proposeRequestVoteRequest term) => decide (term = st.currentTerm ∧ canStartElection st self)
    | _ => false
  live && decide (win = true → hasQuorum st.activeConfigurations {self})

private def guard (self : NodeID) (st : NodeState) (ev : Event) : Prop :=
  (ev = .internal (.timeout .election) ∧ canStartElection st self ∧ hasQuorum st.activeConfigurations {self}) ∨
  (∃ n q, ev = .receive n (.requestPreVoteResponse q) ∧ n ∈ eligiblePeers st self ∧
    (st.role = .preVoteCandidate ∧ q.term = st.currentTerm ∧ q.voteGranted = true) ∧
    hasQuorum st.activeConfigurations (insert n st.preVotesGranted)) ∨
  (∃ n, ev = .receive n (.proposeRequestVoteRequest st.currentTerm) ∧ canStartElection st self)

private theorem guard_iff (self st ev win post) :
    (guard self st ev ∧ (win = true → hasQuorum st.activeConfigurations {self})) ↔ test win self st ev post = true := by
  cases ev with
  | internal i =>
    cases i
    case timeout k => cases k <;> cases win <;> simp [guard,test,canStartElection,hasQuorum]
    all_goals simp [guard,test]
  | receive n m => cases m <;> simp [guard,test] <;> grind

run_cmd liftTermElabM do
  HandReadersTrunkBFactor.query ``step_becomeCandidate_result_done_inl
    `ConsensusCoverage.HandReadersTrunkB.Candidate.ResultCall

open Elab.Term in
local elab "guard_of% " q:ident : term => do
  HandReadersTrunkBFactor.guardOf (←realizeGlobalConstNoOverloadWithInfo q)

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)

private theorem interpret (win : Bool) (p : NodeID → NodeState → NodeState → Prop)
    (atCall : ∀ self (st before : NodeState), st.currentTerm = before.currentTerm →
      (p self st before ↔ (win = true → hasQuorum st.activeConfigurations {self}))) :
    HandReadersTrunkBFactor.Tail.ResultCall f t c p ↔
      guard c.actor c.pre c.event ∧ (win = true → hasQuorum c.pre.activeConfigurations {c.actor}) := by
  constructor
  · rintro (⟨_,_,_,⟨⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,can,_,_,quorum,_,rfl⟩,yes⟩ |
      ⟨_,_,_,⟨n,q,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,pass,_,_,_,g,quorum,_,rfl⟩,yes⟩ |
      ⟨_,_,_,⟨n,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,_,can,_,rfl⟩,yes⟩)
    · exact ⟨.inl ⟨ev,can,quorum⟩,(atCall _ (SelfQuorumCasesB.pre c.actor c.pre) c.pre rfl).mp yes⟩
    · exact ⟨.inr (.inl ⟨n,q,ev,Classical.byContradiction (fun no => pass ⟨trivial,no⟩),g,quorum⟩),
        (atCall _ {c.pre with preVotesGranted := insert n c.pre.preVotesGranted} c.pre rfl).mp yes⟩
    · exact ⟨.inr (.inr ⟨n,ev,can⟩),(atCall _ _ _ rfl).mp yes⟩
  · rintro ⟨⟨ev,can,quorum⟩ | ⟨n,q,ev,peer,g,quorum⟩ | ⟨n,ev,can⟩,winGuard⟩
    · refine .inl ⟨_,_,_,⟨⟨c.event,⟨rfl,rfl,rfl⟩,_,ev,ev,rfl⟩,can,can,can,quorum,
        canStartElection_engaged can,rfl⟩,?_⟩
      exact (atCall _ (SelfQuorumCasesB.pre c.actor c.pre) c.pre rfl).mpr winGuard
    · obtain higher | obs := observe_bumping c.pre (message := .requestPreVoteResponse q) trivial
      · exact (Nat.not_lt_of_ge (Nat.le_of_eq g.2.1) higher.1).elim
      have engaged : Engaged c.pre := ⟨fun h => Role.noConfusion (g.1.symm.trans h),
        fun h => Role.noConfusion (g.1.symm.trans h.1)⟩
      refine .inr (.inl ⟨_,_,_,⟨n,q,⟨c.event,⟨rfl,rfl,rfl⟩,_,ev,ev,rfl⟩,fun h => h.2 peer,
        obs,obs.1,obs.2,g,quorum,engaged,rfl⟩,?_⟩)
      exact (atCall _ {c.pre with preVotesGranted := insert n c.pre.preVotesGranted} c.pre rfl).mpr winGuard
    · exact .inr (.inr ⟨_,_,_,⟨n,⟨c.event,⟨rfl,rfl,rfl⟩,_,ev,ev,rfl⟩,fun h => Bool.noConfusion h.1,
        can,canStartElection_engaged can,rfl⟩,(atCall _ _ _ rfl).mpr winGuard⟩)
end

inductive Kind where | wait | win | start | ballot

def column : Kind → Classes.StepBranch
  | .wait => .becomeCandidate_result_done_inl
  | .win => .becomeCandidate_result_done_inr
  | .start => .becomeCandidate_result_started_inl
  | .ballot => .becomeCandidate_result_started_inr

def requireWin : Kind → Bool | .wait => false | _ => true

private def localGuard : Kind → NodeID → NodeState → NodeState → Prop
  | .wait => guard_of% step_becomeCandidate_result_done_inl
  | .win => guard_of% step_becomeCandidate_result_done_inr
  | .start => guard_of% step_becomeCandidate_result_started_inl
  | .ballot => guard_of% step_becomeCandidate_result_started_inr

private theorem query_eq [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t) (k : Kind) :
    sig c (column k) ↔ ResultCall f t c (localGuard k) := by cases k <;> rfl

private theorem local_iff (k : Kind) (self : NodeID) (st before : NodeState) (term : st.currentTerm = before.currentTerm) :
    localGuard k self st before ↔ (requireWin k = true → hasQuorum st.activeConfigurations {self}) := by
  let fresh := freshCandidate self st
  let leader := primaryState fresh
  let nom := SelfQuorumCasesB.successor self fresh.currentTerm
  let ballot := SelfQuorumCasesB.ballot self fresh
  let vote := fun (e : Model.Envelope) => e.source = self ∧ e.payload = .requestVoteRequest (makeRequestVoteRequest fresh)
  have v : vote ballot := ⟨rfl,rfl⟩
  have n : LeaderStart self fresh.currentTerm leader nom := .inl ⟨rfl,rfl⟩
  have sends : ∀ e ∈ [nom,ballot], LeaderStart self fresh.currentTerm leader e ∨ vote e := by
    intro e h
    simp only [List.mem_cons,List.not_mem_nil,or_false] at h
    rcases h with rfl | rfl
    · exact .inl n
    · exact .inr v
  have incr : before.currentTerm < fresh.currentTerm := term ▸ Nat.lt_succ_self _
  constructor
  · cases k
    · simp [requireWin]
    all_goals rintro ⟨_,_,_,ready,_⟩ _; exact ready.1
  · intro w
    cases k
    · have empty : ∀ e ∈ [], vote e := by simp
      exact ⟨[],.inl empty,empty,empty,term,incr⟩
    all_goals
      have adv : Advance self leader leader := .inl rfl
      have ready := And.intro (w rfl) (And.intro adv sends)
      refine ⟨leader,[nom,ballot],.inr ready,ready,ready.1,ready.2,adv,sends,?_⟩
    · exact ⟨term,incr⟩
    · exact ⟨nom,.head _,n,term,incr⟩
    · exact ⟨ballot,.tail _ (.head _),v,v.1,v.2,term,incr⟩

def exactReader (k : Kind) : Exact (column k) where
  eval := SummaryRows.gated (test (requireWin k))
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    let c := s.context
    apply Bool.eq_iff_iff.mpr
    rw [label_true,show holds s (.step (column k)) ↔ sig c (column k) from sig_iff _ _,query_eq,
      HandReadersTrunkBFactor.Exact.ResultCall _ _ _ _ (quiet s),interpret c _ _ (local_iff k),
      SummaryRows.gated,Bool.and_eq_true,actorRead_at,live,and_comm,←guard_iff]

end ConsensusCoverage.HandReadersTrunkB.Candidate
