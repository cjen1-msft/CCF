module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkBCandidate
import all ConsensusCoverage.HandReadersTrunkBElect
import all ConsensusCoverage.HandReadersASummary
import all ConsensusCoverage.HandReadersTrunkBFactor
import all ConsensusCoverage.SelfQuorumCasesB
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersTrunkBFactor

namespace ConsensusCoverage.HandReadersTrunkB.Primary

open Consensus Model Model.Node Proofs Safety ActionProfile HandReadersA HandReadersBGate SolvedWitnesses
open Lean Elab Command

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxHeartbeats 3000000
set_option maxRecDepth 16384

def column (heartbeat : Bool) : Classes.StepBranch :=
  if heartbeat then .becomePrimary_sends_mem_append_inr else .becomePrimary_sends_mem_append_inl

def test (self : NodeID) (st : NodeState) (ev : Event) (post : NodeState) : Bool :=
  (Elect.test true self st ev post || Candidate.test true self st ev post) && decide (¬st.isRetiredCommitted self)

run_cmd liftTermElabM do
  HandReadersTrunkBFactor.query ``step_becomePrimary_sends_mem_append_inl
    `ConsensusCoverage.HandReadersTrunkB.Primary.Promotion

open Elab.Term in
local elab "guard_of% " q:ident : term => do HandReadersTrunkBFactor.guardOf (←realizeGlobalConstNoOverloadWithInfo q)

private def localGuard : Bool → NodeID → NodeState → Prop
  | false => guard_of% step_becomePrimary_sends_mem_append_inl
  | true => guard_of% step_becomePrimary_sends_mem_append_inr

private theorem always (k : Bool) (self : NodeID) (candidate : NodeState) : localGuard k self candidate := by
  let st := primaryState candidate
  let nom := SelfQuorumCasesB.successor self st.currentTerm
  let ping := SelfQuorumCasesB.heartbeat self st
  have nomOK : ∀ e ∈ [nom], e.source = self ∧ e.payload = .proposeRequestVoteRequest st.currentTerm :=
    SelfQuorumCasesB.singleton ⟨rfl,rfl⟩
  have ae : ∀ e ∈ [ping], AEFrom self st.currentTerm st.commitIndex st.log e :=
    SelfQuorumCasesB.singleton (SelfQuorumCasesB.beat _ _)
  have adv : Advance self st st := .inl rfl
  cases k
  all_goals refine ⟨st,[nom],⟨adv,nomOK⟩,adv,nomOK,[ping],ae,?_⟩
  · exact ⟨nom,.head _,.head _⟩
  · exact ⟨ping,.tail _ (.head _),.head _⟩

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)

private theorem query_eq (k : Bool) : sig c (column k) ↔ Promotion f t c (localGuard k) := by cases k <;> rfl

private theorem tail_iff (k : Bool) : HandReadersTrunkBFactor.Tail.Promotion f t c (localGuard k) ↔
    (Elect.guard true c.actor c.pre c.event ∨ Candidate.guard c.actor c.pre c.event ∧
      (true = true → hasQuorum c.pre.activeConfigurations {c.actor})) ∧ ¬c.pre.isRetiredCommitted c.actor := by
  constructor
  · rintro (⟨_,_,⟨⟨_,n,q,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,pass,_,_,_,g,_,rfl⟩,_,quorum,live⟩,_⟩ |
      ⟨_,_,⟨⟨_,⟨_,⟨⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,can,_,_,q,_,rfl⟩,_⟩,rfl⟩,_,_,live⟩,_⟩ |
      ⟨_,_,⟨⟨_,⟨_,⟨n,q,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,pass,_,_,_,g,quorum,_,rfl⟩,_⟩,rfl⟩,_,qSelf,live⟩,_⟩ |
      ⟨_,_,⟨⟨_,⟨_,⟨n,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,_,can,_,rfl⟩,_⟩,rfl⟩,_,qSelf,live⟩,_⟩)
    · exact ⟨.inl ⟨n,q,ev,Classical.byContradiction (fun no => pass ⟨trivial,no⟩),g,fun _ => quorum⟩,live⟩
    · exact ⟨.inr ⟨.inl ⟨ev,can,q⟩,fun _ => q⟩,live⟩
    · exact ⟨.inr ⟨.inr (.inl ⟨n,q,ev,Classical.byContradiction (fun no => pass ⟨trivial,no⟩),g,quorum⟩),
        fun _ => qSelf⟩,live⟩
    · exact ⟨.inr ⟨.inr (.inr ⟨n,ev,can⟩),fun _ => qSelf⟩,live⟩
  · rintro ⟨vote | ⟨fresh,qSelf⟩,live⟩
    · obtain ⟨self,mid,_,_,⟨st,n,q,call,pass,obs,le,same,g,_,camp,rfl⟩,won,_⟩ :=
        (Elect.tail_iff c true).mpr vote
      refine .inl ⟨_,_,⟨⟨st,n,q,call,pass,obs,le,same,g,camp,rfl⟩,g.1,won.2.1,?_⟩,always ..⟩
      obtain ⟨_,⟨rfl,rfl,_⟩,_⟩ := call
      exact live
    · let p := fun (_ : NodeID) (_ _ : NodeState) => True
      have call := (Candidate.interpret c false p (by simp [p])).mpr ⟨fresh,by simp⟩
      rcases call with ⟨self,st,before,src,_⟩ | ⟨self,st,before,src,_⟩ | ⟨self,st,before,src,_⟩
      all_goals
        first
        | refine .inr (.inl ⟨_,_,⟨⟨st,⟨before,src,?_⟩,rfl⟩,rfl,?_,?_⟩,always ..⟩)
        | refine .inr (.inr (.inl ⟨_,_,⟨⟨st,⟨before,src,?_⟩,rfl⟩,rfl,?_,?_⟩,always ..⟩))
        | refine .inr (.inr (.inr ⟨_,_,⟨⟨st,⟨before,src,?_⟩,rfl⟩,rfl,?_,?_⟩,always ..⟩))
      all_goals
        first
        | obtain ⟨⟨_,⟨rfl,rfl,_⟩,_⟩,_,_,_,_,_,rfl⟩ := src <;> first | rfl | exact qSelf rfl | exact live
        | obtain ⟨_,_,⟨_,⟨rfl,rfl,_⟩,_⟩,_,_,_,_,_,_,_,rfl⟩ := src <;> first | rfl | exact qSelf rfl | exact live
        | obtain ⟨_,⟨_,⟨rfl,rfl,_⟩,_⟩,_,_,_,rfl⟩ := src <;> first | rfl | exact qSelf rfl | exact live
end

def exactReader (k : Bool) : Exact (column k) where
  eval := SummaryRows.gated test
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    let c := s.context
    apply Bool.eq_iff_iff.mpr
    rw [label_true,show holds s (.step (column k)) ↔ sig c (column k) from sig_iff _ _,query_eq,
      HandReadersTrunkBFactor.Exact.Promotion _ _ _ _ (quiet s),tail_iff,
      SummaryRows.gated,Bool.and_eq_true,actorRead_at,live,and_comm,test,Bool.and_eq_true,
      Bool.or_eq_true,decide_eq_true_eq,←Elect.guard_iff,←Candidate.guard_iff]

end ConsensusCoverage.HandReadersTrunkB.Primary
