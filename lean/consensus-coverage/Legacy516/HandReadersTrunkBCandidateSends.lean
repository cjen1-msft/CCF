module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkBCandidate
import all ConsensusCoverage.HandReadersASummary
import all ConsensusCoverage.HandReadersTrunkBFactor
import all ConsensusCoverage.SelfQuorumCasesB
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersTrunkBFactor

namespace ConsensusCoverage.HandReadersTrunkB.CandidateSends

open Consensus Model Model.Node Proofs Safety ActionProfile HandReadersA HandReadersBGate SolvedWitnesses
open Lean Elab Command

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxHeartbeats 3000000
set_option maxRecDepth 16384

def column : Candidate.Kind → Classes.StepBranch
  | .wait => .becomeCandidate_sends_elected_inl
  | .win => .becomeCandidate_sends_elected_inr
  | .start => .becomeCandidate_sends_mem_append_inl
  | .ballot => .becomeCandidate_sends_mem_append_inr

open Elab.Term in
local elab "guard_of% " q:ident : term => do
  HandReadersTrunkBFactor.guardOf (←realizeGlobalConstNoOverloadWithInfo q)

private def localGuard : Candidate.Kind → NodeID → NodeState → Prop
  | .wait => guard_of% step_becomeCandidate_sends_elected_inl
  | .win => guard_of% step_becomeCandidate_sends_elected_inr
  | .start => guard_of% step_becomeCandidate_sends_mem_append_inl
  | .ballot => guard_of% step_becomeCandidate_sends_mem_append_inr

private theorem shift (a : NodeID → NodeState → NodeState → Prop) (p : NodeID → NodeState → Prop) :
    (∃ x y, (∃ z, a x y z ∧ y.currentTerm = z.currentTerm) ∧ p x y) ↔
      ∃ x y z, a x y z ∧ y.currentTerm = z.currentTerm ∧ p x y :=
  ⟨fun ⟨x,y,⟨z,h,e⟩,q⟩ => ⟨x,y,z,h,e,q⟩,fun ⟨x,y,z,h,e,q⟩ => ⟨x,y,⟨z,h,e⟩,q⟩⟩

private theorem query_eq [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)
    (k : Candidate.Kind) : sig c (column k) ↔ Candidate.ResultCall f t c
      (fun self st before => st.currentTerm = before.currentTerm ∧ localGuard k self st) := by
  cases k
  all_goals
    repeat' apply or_congr
    all_goals apply shift

private theorem local_iff (k : Candidate.Kind) (self : NodeID) (st before : NodeState) (term : st.currentTerm = before.currentTerm) :
    (st.currentTerm = before.currentTerm ∧ localGuard k self st) ↔
      (Candidate.requireWin k = true → hasQuorum st.activeConfigurations {self}) := by
  let fresh := freshCandidate self st
  let leader := primaryState fresh
  let nom := SelfQuorumCasesB.successor self fresh.currentTerm
  let ballot := SelfQuorumCasesB.ballot self fresh
  have start : ∀ e ∈ [nom], LeaderStart self fresh.currentTerm leader e :=
    SelfQuorumCasesB.singleton (.inl ⟨rfl,rfl⟩)
  have vote : ∀ e ∈ [ballot], e.source = self ∧ ¬e.target = self ∧
      e.payload = .requestVoteRequest (makeRequestVoteRequest fresh) :=
    SelfQuorumCasesB.singleton ⟨rfl,Nat.succ_ne_self _,rfl⟩
  constructor
  · rintro ⟨_,h⟩
    cases k
    · simp [Candidate.requireWin]
    · obtain ⟨_,_,_,_,_,_,q,_⟩ := h; exact fun _ => q
    all_goals obtain ⟨_,_,_,_,_,done_,_⟩ := h; exact fun _ => done_.2.1
  · intro w
    refine ⟨term,?_⟩
    cases k
    · exact ⟨.inl trivial,[],by simp⟩
    all_goals
      have adv : Advance self leader leader := .inl rfl
      have won := And.intro (show fresh.role = .candidate from rfl) (And.intro (w rfl) (And.intro adv start))
      refine ⟨leader,[nom],.inr won,[ballot],vote,?_⟩
    · exact won
    all_goals refine ⟨won,won.1,won.2,won.2.1,won.2.2,adv,start,?_⟩
    · exact ⟨nom,.head _,.head _⟩
    · exact ⟨ballot,.tail _ (.head _),.head _⟩

def exactReader (k : Candidate.Kind) : Exact (column k) where
  eval := SummaryRows.gated (Candidate.test (Candidate.requireWin k))
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    let c := s.context
    apply Bool.eq_iff_iff.mpr
    rw [label_true,show holds s (.step (column k)) ↔ sig c (column k) from sig_iff _ _,query_eq,
      HandReadersTrunkBFactor.Exact.ResultCall _ _ _ _ (quiet s),Candidate.interpret c _ _ (local_iff k),
      SummaryRows.gated,Bool.and_eq_true,actorRead_at,live,and_comm,←Candidate.guard_iff]

end ConsensusCoverage.HandReadersTrunkB.CandidateSends
