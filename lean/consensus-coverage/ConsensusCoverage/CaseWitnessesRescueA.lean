module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ActionProfile
import all ConsensusCoverage.AssistAcceptedA
import all ConsensusCoverage.AssistCampaignA
import all ConsensusCoverage.AssistConflictA
import all ConsensusCoverage.AssistEffectA
import all ConsensusCoverage.AssistFollowerA
import all ConsensusCoverage.AssistOverlapA
import all ConsensusCoverage.AssistReplyA
import all ConsensusCoverage.AssistReplyBranchesA
import all ConsensusCoverage.QueueSamplesA

namespace ConsensusCoverage.CaseWitnessesRescueA

open ActionProfile

private def certificates : List QueueSamplesA.Certificate :=
  AssistOverlapA.certificates ++ AssistFollowerA.certificates ++ AssistAcceptedA.certificates ++
    AssistCampaignA.certificates ++ AssistEffectA.certificates ++ AssistReplyA.certificates ++
    AssistReplyBranchesA.certificates ++ AssistConflictA.certificates

public def witnessed : List Classes.StepBranch := certificates.map Subtype.val

public theorem count : witnessed.Nodup ∧ witnessed.length = 26 := by decide +kernel

public theorem occurs {b : Classes.StepBranch} (mem : b ∈ witnessed) :
    ∃ s : Step, label s (.step b) = true := by
  obtain ⟨w,_,rfl⟩ := List.mem_map.mp mem
  exact w.property

end ConsensusCoverage.CaseWitnessesRescueA
