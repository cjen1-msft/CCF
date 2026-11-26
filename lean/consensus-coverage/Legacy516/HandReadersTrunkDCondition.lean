module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkDConditionNested
import all ConsensusCoverage.HandReadersTrunkDConditionEvents
import all ConsensusCoverage.HandReadersTrunkDConditionQueries
import all ConsensusCoverage.HandReadersTrunkDConditionRoute
import all ConsensusCoverage.HandReadersTrunkDConditionData
import all ConsensusCoverage.HandReadersTrunkABatch
import all ConsensusCoverage.HandReadersTrunkBFactor
import all ConsensusCoverage.HandReadersASummary
import all ConsensusCoverage.HandReadersBGate
import all ConsensusCoverage.AssistEffectA
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersTrunkD.Condition

open Consensus Model Model.Node Proofs Safety ActionProfile HandReadersA SolvedWitnesses
set_option maxRecDepth 16384
set_option maxHeartbeats 1200000
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private def column (b : Bool) : Classes.StepBranch := if b then .ite__condition_pos_2 else .ite__condition_neg_2

private theorem guard_iff [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t) (b : Bool) :
    sig c (column b) ↔ LocalGuards f t c b := by
  cases b
  · exact LocalGuards.negative ..
  · exact LocalGuards.positive ..

private theorem exact_iff (s : Step) (b : Bool) : letI : Config.InitialConfiguration := ⟨s.cfg⟩
    sig s.context (column b) ↔ HandReadersBGate.Source s.context ∧ Answer s.context b := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have q := HandReadersBGate.quiet s
  have route := LocalGuards.byFamily s.frame s.after c b
  rw [HandReadersTrunkBFactor.Exact.Timeout _ _ _ _ q,HandReadersTrunkBFactor.Exact.Ack _ _ _ _ q,
    HandReadersTrunkBFactor.Exact.Vote _ _ _ _ q,HandReadersTrunkBFactor.Exact.PreVote _ _ _ _ q,
    HandReadersTrunkBFactor.Exact.Proposal _ _ _ _ q,HandReadersTrunkBFactor.Exact.Batch _ _ _ _ q,
    HandReadersTrunkBFactor.Exact.Advance _ _ _ _ q,HandReadersTrunkBFactor.Exact.Request _ _ _ _ q,
    HandReadersTrunkBFactor.Exact.Elect _ _ _ _ q,timePhase,ackPhase,votePhase,preVotePhase,proposalPhase,requestPhase] at route
  simp only [←and_or_left] at route
  have eq := (guard_iff c b).trans route
  constructor
  · intro h
    obtain ⟨src,h⟩ := eq.mp h
    refine ⟨src,?_⟩
    rcases h with h | h | h | h | h | batch | adv | h | elect
    case inr.inr.inr.inr.inr.inl => exact batchPhase c b batch
    case inr.inr.inr.inr.inr.inr.inl => exact advancePhase c b adv
    case inr.inr.inr.inr.inr.inr.inr.inr => exact electPhase c b elect
    all_goals apply (events c b).mp; unfold EventCases; grind only
  · rintro ⟨src,yes⟩
    rcases (events c b).mpr yes with ⟨xs,ev⟩ | h | h | h | h | h | h
    · exact AssistEffectA.effects (HandReadersTrunkA.Batch.seed c ev) b
    all_goals apply eq.mpr; exact ⟨src,by grind only⟩

def exactReader (b : Bool) : HandReadersA.Exact (column b) where
  eval := SummaryRows.gated (test b)
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff,exact_iff,SummaryRows.gated,Bool.and_eq_true,actorRead_at,HandReadersBGate.live,and_comm]

end ConsensusCoverage.HandReadersTrunkD.Condition
