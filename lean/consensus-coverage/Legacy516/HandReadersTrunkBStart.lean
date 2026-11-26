module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersASummary
import all ConsensusCoverage.HandReadersTrunkBFactor
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersTrunkBFactor

namespace ConsensusCoverage.HandReadersTrunkB.Start

open Consensus Model Model.Node Proofs Safety ActionProfile HandReadersA HandReadersBGate SolvedWitnesses
open Lean Elab Command

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxHeartbeats 3000000
set_option maxRecDepth 16384

inductive Kind where | follower | preVote | candidate

def role : Kind → Role
  | .follower => .follower
  | .preVote => .preVoteCandidate
  | .candidate => .candidate

def column : Kind → Classes.StepBranch
  | .follower => .canStartElection_engaged_can_inl
  | .preVote => .canStartElection_engaged_can_inr_inl
  | .candidate => .canStartElection_engaged_can_inr_inr

def test (k : Kind) (self : NodeID) (st : NodeState) (ev : Event) (_ : NodeState) : Bool :=
  let start := match ev with
    | .internal (.timeout .election) => true
    | .receive _ (.proposeRequestVoteRequest term) => decide (term = st.currentTerm)
    | _ => false
  start && decide (st.role = role k ∧ canStartElection st self)

run_cmd liftTermElabM do
  for n in #[``step_canStartElection_engaged_can_inl, ``step_canStartElection_engaged_can_inr_inl,
      ``step_canStartElection_engaged_can_inr_inr] do HandReadersTrunkBFactor.compile n

private def electionEvent (ev : Event) (term : Nat) :=
  ev = .internal (.timeout .election) ∨ ∃ n, ev = .receive n (.proposeRequestVoteRequest term)

private theorem matches_test (k self) (st : NodeState) (ev post) :
    electionEvent ev st.currentTerm ∧ st.role = role k ∧ canStartElection st self ↔
      test k self st ev post = true := by
  cases ev with
  | internal i =>
    cases i
    case timeout kind => cases kind <;> simp [electionEvent,test]
    all_goals simp [electionEvent,test]
  | receive n m => cases m <;> simp [electionEvent,test] <;> grind

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)

private abbrev tail (k : Kind) := match k with
  | .follower => HandReadersTrunkBFactor.Tail.step_canStartElection_engaged_can_inl f t c
  | .preVote => HandReadersTrunkBFactor.Tail.step_canStartElection_engaged_can_inr_inl f t c
  | .candidate => HandReadersTrunkBFactor.Tail.step_canStartElection_engaged_can_inr_inr f t c

omit [Config.InitialConfiguration] in
private theorem wait (self : NodeID) (before cand : NodeState) :
    ∃ next sent, CampaignResult self before cand next sent :=
  ⟨cand,[],Or.inl ⟨rfl,by simp⟩⟩

private theorem tail_iff (k : Kind) :
    tail c k ↔ electionEvent c.event c.pre.currentTerm ∧ c.pre.role = role k ∧ canStartElection c.pre c.actor := by
  constructor
  · cases k
    all_goals
      rintro (⟨st,self,⟨⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,_,_,_,_,_⟩,rest⟩ |
        ⟨st,self,⟨⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,_,_,_,_,_⟩,rest⟩ |
        ⟨st,self,⟨n,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,_,_,_⟩,rest⟩)
      all_goals
        constructor
        · first | exact .inl ev | exact .inr ⟨_,ev⟩
        · first | exact rest | exact rest.2
  · rintro ⟨timeout | ⟨n,proposed⟩,r,can⟩
    · by_cases quorum : hasQuorum c.pre.activeConfigurations {c.actor}
      · cases k
        all_goals
          refine Or.inl ⟨_,_,⟨⟨c.event,⟨rfl,rfl,rfl⟩,_,timeout,timeout,rfl⟩,can,can,can,quorum,wait ..⟩,?_⟩
          first | exact ⟨r,can⟩ | exact ⟨.inl r,r,can⟩ | exact ⟨.inr r,r,can⟩
      · cases k
        all_goals
          refine Or.inr (Or.inl ⟨_,_,⟨⟨c.event,⟨rfl,rfl,rfl⟩,_,timeout,timeout,rfl⟩,can,can,can,quorum,
            [],by simp,Or.inl ⟨fun h => Role.noConfusion h,fun h => Role.noConfusion h.1⟩⟩,?_⟩)
          first | exact ⟨r,can⟩ | exact ⟨.inl r,r,can⟩ | exact ⟨.inr r,r,can⟩
    · cases k
      all_goals
        refine Or.inr (Or.inr ⟨_,_,⟨n,⟨c.event,⟨rfl,rfl,rfl⟩,_,proposed,proposed,rfl⟩,
          fun h => Bool.noConfusion h.1,can,wait ..⟩,?_⟩)
        first | exact ⟨r,can⟩ | exact ⟨.inl r,r,can⟩ | exact ⟨.inr r,r,can⟩
end

def exactReader (k : Kind) : Exact (column k) where
  eval := SummaryRows.gated (test k)
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    let c := s.context
    apply Bool.eq_iff_iff.mpr
    rw [label_true,show holds s (.step (column k)) ↔ sig c (column k) from sig_iff _ _,
      SummaryRows.gated,Bool.and_eq_true,actorRead_at,live,and_comm,←matches_test,←tail_iff]
    cases k
    · exact HandReadersTrunkBFactor.Exact.step_canStartElection_engaged_can_inl _ _ _ (quiet s)
    · exact HandReadersTrunkBFactor.Exact.step_canStartElection_engaged_can_inr_inl _ _ _ (quiet s)
    · exact HandReadersTrunkBFactor.Exact.step_canStartElection_engaged_can_inr_inr _ _ _ (quiet s)

end ConsensusCoverage.HandReadersTrunkB.Start
