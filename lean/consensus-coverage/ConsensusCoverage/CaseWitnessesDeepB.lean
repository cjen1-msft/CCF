module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.MaximumCasesB
public import ConsensusCoverage.ReceiveCasesB
public import ConsensusCoverage.CampaignCasesB
public import ConsensusCoverage.SelfQuorumCasesB
public import ConsensusCoverage.FollowerFoldCasesB
public import ConsensusCoverage.FollowerArmsB
public import ConsensusCoverage.PromotionArmsB
public import ConsensusCoverage.LoopSendCasesB
public import ConsensusCoverage.BatchArmsB
public import ConsensusCoverage.NominationRetirementB
public import ConsensusCoverage.BatchPacketCasesB
public import ConsensusCoverage.AdvanceArmsB
public import ConsensusCoverage.AckComparisonB
public import ConsensusCoverage.OverlapCasesB
import all ConsensusCoverage.MaximumCasesB
import all ConsensusCoverage.ReceiveCasesB
import all ConsensusCoverage.CampaignCasesB
import all ConsensusCoverage.SelfQuorumCasesB
import all ConsensusCoverage.FollowerFoldCasesB
import all ConsensusCoverage.FollowerArmsB
import all ConsensusCoverage.PromotionArmsB
import all ConsensusCoverage.LoopSendCasesB
import all ConsensusCoverage.BatchArmsB
import all ConsensusCoverage.BatchPacketCasesB
import all ConsensusCoverage.AdvanceArmsB
import all ConsensusCoverage.AckComparisonB
import all ConsensusCoverage.OverlapCasesB

namespace ConsensusCoverage.CaseWitnessesDeepB

open ActionProfile

public def witnessed : List Classes.StepBranch :=
  MaximumCasesB.questions ++ ReceiveCasesB.witnessed ++ CampaignCasesB.witnessed ++ SelfQuorumCasesB.questions ++
    FollowerFoldCasesB.questions ++ FollowerArmsB.questions ++ PromotionArmsB.questions ++
    LoopSendCasesB.questions ++ BatchArmsB.questions ++ [.nominate_sends_successor_none] ++
    BatchPacketCasesB.questions ++ AdvanceArmsB.questions ++ AckComparisonB.questions ++ OverlapCasesB.questions

public theorem count : witnessed.Nodup ∧ witnessed.length = 109 := by decide +kernel

public theorem occurs {b : Classes.StepBranch} (mem : b ∈ witnessed) :
    ∃ s : Step, label s (.step b) = true := by
  simp only [witnessed, List.mem_append, List.mem_singleton] at mem
  rcases mem with ((((((((((((maximum | message) | campaign) | selfQuorum) | follower) | fold) | promotion) | loop) | batch) | rfl) | packet) | advance) | ack) | overlap
  · exact MaximumCasesB.occurs maximum
  · exact ReceiveCasesB.occurs message
  · exact CampaignCasesB.occurs campaign
  · exact SelfQuorumCasesB.occurs selfQuorum
  · exact FollowerFoldCasesB.occurs follower
  · exact FollowerArmsB.occurs fold
  · exact PromotionArmsB.occurs promotion
  · exact LoopSendCasesB.occurs loop
  · exact BatchArmsB.occurs batch
  · exact NominationRetirementB.occurs
  · exact BatchPacketCasesB.occurs packet
  · exact AdvanceArmsB.occurs advance
  · exact AckComparisonB.occurs ack
  · exact OverlapCasesB.occurs overlap

end ConsensusCoverage.CaseWitnessesDeepB
