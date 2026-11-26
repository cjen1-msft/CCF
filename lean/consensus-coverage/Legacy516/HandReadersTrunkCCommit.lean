module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkCAppend
import all ConsensusCoverage.HandReadersTrunkCExtension
import all ConsensusCoverage.HandReadersTrunkAAdvance
import all ConsensusCoverage.HandReadersTrunkABatch
import all ConsensusCoverage.HandReadersTrunkAFactor
import all ConsensusCoverage.AdvanceArmsB
import all ConsensusCoverage.SelfQuorumCasesB
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersTrunkAFactor

namespace ConsensusCoverage.HandReadersTrunkC.Batch

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses
open HandReadersA ActionProfile

set_option maxRecDepth 16384
set_option maxHeartbeats 1400000

open Lean Elab Command in
run_cmd liftTermElabM do
  HandReadersTrunkA.Factor.compile ``step_commit_le_advance_inr

private theorem strictSupply [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)
    (g : Good c) : step_commit_le_advance_inr f t c := by
  obtain ⟨⟨xs,ev⟩,ahead⟩ := g
  let s := HandReadersTrunkA.Batch.seed c ev
  let m := AdvanceArmsB.appended c.pre
  let post := {m with commitIndex := highestCommittableIndex m c.actor}
  let e := SelfQuorumCasesB.heartbeat c.actor m
  let suffix : List Entry := [⟨c.pre.currentTerm,.signature⟩]
  have terms : ∀ x ∈ suffix, x.term = c.pre.currentTerm := by simp [suffix]
  have ae : AEFrom c.actor c.pre.currentTerm c.pre.commitIndex m.log e := SelfQuorumCasesB.beat _ _
  have batch : BatchState c.actor c.pre m [e] := ⟨⟨suffix,c.pre.sentIndex,rfl,terms⟩,SelfQuorumCasesB.singleton ae⟩
  have strict : post.log = m.log ∧ post.currentTerm = m.currentTerm ∧ post.votedFor = m.votedFor ∧
      post.matchIndex = m.matchIndex ∧ post.sentIndex = m.sentIndex ∧ post.votesGranted = m.votesGranted ∧
      m.commitIndex < post.commitIndex ∧ post.commitIndex = highestCommittableIndex m c.actor ∧
      (post.role = m.role ∨ post.role = .none) := ⟨rfl,rfl,rfl,rfl,rfl,rfl,ahead,rfl,.inl rfl⟩
  have a : Advance c.actor m post := .inr strict
  have empty : ∀ a ∈ ([] : List Model.Envelope), a.source = c.actor ∧ a.payload = .proposeRequestVoteRequest m.currentTerm := by simp
  iterate 6 right
  left
  refine ⟨c.actor,m,post,Or.inr (.inl ?_),strict,a⟩
  exact ⟨c.pre,xs,s.entered,s.guards,s.guards.1,s.guards.2,s.guards,m,[e],batch,[],
    ⟨a,empty⟩,a,empty,batch.1,batch.2,suffix,⟨_,rfl,terms⟩,c.pre.sentIndex,⟨rfl,terms⟩,rfl,terms,
    e,.head _,.head _,BatchArmsB.start s,rfl,rfl,.inl s.guards.1,rfl⟩

private theorem strictNecessary (s : Step) : letI : Config.InitialConfiguration := ⟨s.cfg⟩
    step_commit_le_advance_inr _ _ s.context → Good s.context := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  rw [HandReadersTrunkA.Factor.Split.step_commit_le_advance_inr_iff,
    HandReadersBFactor.Exact.step_commit_le_advance_inr _ _ _ (HandReadersBGate.quiet s)]
  rintro ⟨_,(⟨n,m,post,site,strict,_⟩ | ⟨n,m,post,site,strict,_⟩)⟩
  all_goals
    obtain ⟨_,xs,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,_,primary,_,_,app,_,batch,_,_,_,_,_,_,_,_,_,_,_,_,rest⟩ := site
    first | obtain ⟨_,_,_,_,_,_,_,eq⟩ := rest; subst m
          | obtain ⟨_,_,_,_,_,_,_,_,_,_,_,eq⟩ := rest; subst m
    obtain ⟨⟨es,si,eq,_⟩,_⟩ := batch
    exact ⟨⟨xs,ev⟩,Extension.normalize s.context primary es si app eq (strict.2.2.2.2.2.2.2.1 ▸ strict.2.2.2.2.2.2.1)⟩

def commitStrict := exactOfGood .commit_le_advance_inr fun s =>
  ⟨strictNecessary s,fun h => @strictSupply ⟨s.cfg⟩ _ _ s.context h⟩

end ConsensusCoverage.HandReadersTrunkC.Batch
