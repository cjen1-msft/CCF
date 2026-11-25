module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkABatch
import all ConsensusCoverage.BatchArmsB
import all ConsensusCoverage.SelfQuorumCasesB
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersTrunkA.Batch

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses

set_option maxRecDepth 8192

private theorem identity [Config.InitialConfiguration] {f : Frame} {t : State} {c : Ctx f t}
    (s : BatchArmsB.Seed c) : step_commit_le_advance_inl f t c := by
  let m := s.before
  let e := SelfQuorumCasesB.heartbeat s.self m
  have packets : ∀ a ∈ [e], AEFrom s.self m.currentTerm m.commitIndex m.log a :=
    SelfQuorumCasesB.singleton (SelfQuorumCasesB.beat _ _)
  have batch : BatchState s.self m m [e] := ⟨(BatchArmsB.start s).1,packets⟩
  have adv : Advance s.self m m := .inl rfl
  have empty : ∀ msg ∈ ([] : List Model.Envelope), msg.source = s.self ∧
      msg.payload = .proposeRequestVoteRequest m.currentTerm := by simp
  have eq : m = {s.before with log := s.before.log ++ [], sentIndex := s.before.sentIndex} := by simp [m]
  have terms : ∀ a ∈ ([] : List Entry), a.term = s.before.currentTerm := by simp
  iterate 6 right
  left
  refine ⟨s.self,m,Or.inr (.inl ?_),adv⟩
  exact ⟨s.before,s.contents,s.entered,s.guards,s.guards.1,s.guards.2,s.guards,m,[e],batch,[],
    ⟨adv,empty⟩,adv,empty,batch.1,batch.2,[],⟨m.sentIndex,eq,terms⟩,m.sentIndex,⟨eq,terms⟩,eq,terms,
    e,.head _,.head _,BatchArmsB.start s,rfl,rfl,Or.inl s.guards.1,rfl⟩

def commitIdentity := exactOfSeed .commit_le_advance_inl (by decide +kernel) identity

end ConsensusCoverage.HandReadersTrunkA.Batch
