module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.MaximumCasesB
public import ConsensusCoverage.ReceiveCasesB
import all ConsensusCoverage.MaximumCasesB
import all ConsensusCoverage.ReceiveCasesB

namespace ConsensusCoverage.CaseWitnessesDeepB

open ActionProfile

public def witnessed : List Classes.StepBranch := MaximumCasesB.questions ++ ReceiveCasesB.witnessed

public theorem count : witnessed.Nodup ∧ witnessed.length = 25 := by decide +kernel

public theorem occurs {b : Classes.StepBranch} (mem : b ∈ witnessed) :
    ∃ s : Step, label s (.step b) = true := by
  rcases List.mem_append.mp mem with maximum | message
  · exact MaximumCasesB.occurs maximum
  · exact ReceiveCasesB.occurs message

end ConsensusCoverage.CaseWitnessesDeepB
