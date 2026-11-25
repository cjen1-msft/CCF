module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.MaximumCasesB
import all ConsensusCoverage.MaximumCasesB

namespace ConsensusCoverage.CaseWitnessesDeepB

open ActionProfile

public def witnessed : List Classes.StepBranch := MaximumCasesB.questions

public theorem count : witnessed.Nodup ∧ witnessed.length = 7 := by decide +kernel

public theorem occurs {b : Classes.StepBranch} (mem : b ∈ witnessed) :
    ∃ s : Step, label s (.step b) = true :=
  MaximumCasesB.occurs mem

end ConsensusCoverage.CaseWitnessesDeepB
