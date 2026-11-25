module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.CaseUnreachable
public import ConsensusCoverage.CaseUnreachableB
public import ConsensusCoverage.CaseWitnessesDeep
public import ConsensusCoverage.CaseWitnessesDeepB
public import ConsensusCoverage.CaseWitnessesQueued
public import ConsensusCoverage.CaseWitnessesRescueA
public import ConsensusCoverage.CensusBallots
public import ConsensusCoverage.ReadersWitnesses
public import ConsensusCoverage.ReadersWitnessesClosed
public import ConsensusCoverage.ReadersWitnessesQueue
import all ConsensusCoverage.CaseUnreachable
import all ConsensusCoverage.CaseUnreachableB
import all ConsensusCoverage.CaseWitnesses
import all ConsensusCoverage.CaseWitnessesDeep
import all ConsensusCoverage.CaseWitnessesDeepB
import all ConsensusCoverage.CaseWitnessesQueued
import all ConsensusCoverage.CaseWitnessesRescueA
import all ConsensusCoverage.DeepReceiveCases
import all ConsensusCoverage.DeepBatchCases
import all ConsensusCoverage.DeepPrefixCases
import all ConsensusCoverage.DeepListCases
import all ConsensusCoverage.DeepObserveCases
import all ConsensusCoverage.DeepHandlerCases
import all ConsensusCoverage.DeepSignedCases
import all ConsensusCoverage.DeepBoundCases
import all ConsensusCoverage.DeepWinningCases
import all ConsensusCoverage.DeepRankingCases
import all ConsensusCoverage.DeepHistoryCases
import all ConsensusCoverage.DeepQuorumCases
import all ConsensusCoverage.DeepCarriedCases
import all ConsensusCoverage.DeepCoreCases
import all ConsensusCoverage.DeepChainCases
import all ConsensusCoverage.DeepComparableCases
import all ConsensusCoverage.DeepLookupCases
import all ConsensusCoverage.DeepTipCases
import all ConsensusCoverage.DeepAcceptedCases
import all ConsensusCoverage.DeepShortenCases
import all ConsensusCoverage.DeepAdvanceCases
import all ConsensusCoverage.MaximumCasesB
import all ConsensusCoverage.ReceiveCasesB
import all ConsensusCoverage.CampaignCasesB
import all ConsensusCoverage.SelfQuorumCasesB
import all ConsensusCoverage.FollowerFoldCasesB
import all ConsensusCoverage.FollowerArmsB
import all ConsensusCoverage.PromotionArmsB
import all ConsensusCoverage.LoopSendCasesB
import all ConsensusCoverage.AdvanceArmsB
import all ConsensusCoverage.BatchArmsB
import all ConsensusCoverage.BatchPacketCasesB
import all ConsensusCoverage.NominationRetirementB
import all ConsensusCoverage.AckComparisonB
import all ConsensusCoverage.OverlapCasesB
import all ConsensusCoverage.AssistOverlapA
import all ConsensusCoverage.AssistFollowerA
import all ConsensusCoverage.AssistAcceptedA
import all ConsensusCoverage.AssistCampaignA
import all ConsensusCoverage.AssistEffectA
import all ConsensusCoverage.FullProfile
import all ConsensusCoverage.ReadersWitnesses
import all ConsensusCoverage.ReadersWitnessesClosed
import all ConsensusCoverage.Families
import all ConsensusCoverage.FreshHeartbeatResidual
import all ConsensusCoverage.ReadersWitnessesQueue
import all ConsensusCoverage.ReadersWitnessesCases
import all ConsensusCoverage.Readers
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReplayAnswers

namespace ConsensusCoverage.CensusPartition

open ActionProfile

set_option maxRecDepth 16384
set_option maxHeartbeats 0

public def witnessed : List Classes.StepBranch :=
  (CaseWitnesses.witnessed ++ CaseWitnessesDeep.witnessed ++ ReadersWitnesses.witnessed ++
    CaseWitnessesDeepB.witnessed ++ CaseWitnessesQueued.witnessed ++ ReadersWitnessesQueue.witnessed ++
    ReadersWitnessesClosed.witnessed ++ CaseWitnessesRescueA.witnessed).eraseDups

public def refuted : List Classes.StepBranch :=
  (CaseUnreachable.refuted ++ CaseUnreachableB.refuted ++
    ([.ballot_step_mem_after_inl, .ballot_step_mem_after_inr] : List Classes.StepBranch)).eraseDups

/-- Not yet certified in either direction. No bounded search is used to
declare a case impossible. -/
public def unsettled : List Classes.StepBranch :=
  FullProfile.stepBranches.toList.filter fun b => !(witnessed.contains b || refuted.contains b)

public theorem occurs {b : Classes.StepBranch} (mem : b ∈ witnessed) :
    ∃ s : Step, label s (.step b) = true := by
  simp only [witnessed, List.mem_eraseDups, List.mem_append] at mem
  rcases mem with ((((((census | deep) | readers) | deepB) | queued) | readerQueue) | closed) | rescue
  · exact CaseWitnesses.occurs census
  · exact CaseWitnessesDeep.occurs deep
  · exact ReadersWitnesses.occurs readers
  · exact CaseWitnessesDeepB.occurs deepB
  · exact CaseWitnessesQueued.occurs queued
  · exact ReadersWitnessesQueue.occurs readerQueue
  · exact ReadersWitnessesClosed.occurs closed
  · exact CaseWitnessesRescueA.occurs rescue

public theorem impossible {b : Classes.StepBranch} (mem : b ∈ refuted) (s : Step) :
    label s (.step b) = false := by
  simp only [refuted, List.mem_eraseDups, List.mem_append] at mem
  rcases mem with (prior | deepB) | ballots
  · exact CaseUnreachable.label_false prior s
  · exact CaseUnreachableB.label_false deepB s
  · exact CensusBallots.label_false s (by simpa only [List.mem_cons, List.not_mem_nil, or_false] using ballots)

public theorem disjoint {b : Classes.StepBranch} (yes : b ∈ witnessed) (no : b ∈ refuted) : False := by
  obtain ⟨s, eq⟩ := occurs yes
  rw [impossible no s] at eq
  cases eq

public theorem unsettled_iff (b : Classes.StepBranch) :
    b ∈ unsettled ↔ b ∉ witnessed ∧ b ∉ refuted := by
  have all : b ∈ FullProfile.stepBranches.toList := by
    rw [← FullProfile.step_get b, Array.mem_toList_iff]
    exact Array.getElem_mem _
  simp [unsettled, all]

public theorem witnessed_count : witnessed.Nodup ∧ witnessed.length = 474 := by decide +kernel

public theorem refuted_count : refuted.Nodup ∧ refuted.length = 29 := by decide +kernel

public theorem unsettled_count : unsettled.Nodup ∧ unsettled.length = 13 := by decide +kernel

/-- Every total generated or legacy reader is accounted for in a proved
class. One-sided readers may still give evidence about an unsettled case. -/
public theorem no_unsettled_total :
    unsettled.all (fun b => !(Readers.covered.contains b || ReplayAnswers.unconditional.contains b)) = true := by
  decide +kernel

end ConsensusCoverage.CensusPartition
