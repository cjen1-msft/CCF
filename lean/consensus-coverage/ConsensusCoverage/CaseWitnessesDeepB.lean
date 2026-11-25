module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.MaximumCasesB
public import ConsensusCoverage.ReceiveCasesB
public import ConsensusCoverage.CampaignCasesB
public import ConsensusCoverage.SelfQuorumCasesB
import all ConsensusCoverage.MaximumCasesB
import all ConsensusCoverage.ReceiveCasesB
import all ConsensusCoverage.CampaignCasesB
import all ConsensusCoverage.SelfQuorumCasesB

namespace ConsensusCoverage.CaseWitnessesDeepB

open ActionProfile

public def witnessed : List Classes.StepBranch :=
  MaximumCasesB.questions ++ ReceiveCasesB.witnessed ++ CampaignCasesB.witnessed ++ SelfQuorumCasesB.questions

public theorem count : witnessed.Nodup ∧ witnessed.length = 40 := by decide +kernel

public theorem occurs {b : Classes.StepBranch} (mem : b ∈ witnessed) :
    ∃ s : Step, label s (.step b) = true := by
  simp only [witnessed, List.mem_append] at mem
  rcases mem with ((maximum | message) | campaign) | selfQuorum
  · exact MaximumCasesB.occurs maximum
  · exact ReceiveCasesB.occurs message
  · exact CampaignCasesB.occurs campaign
  · exact SelfQuorumCasesB.occurs selfQuorum

end ConsensusCoverage.CaseWitnessesDeepB
