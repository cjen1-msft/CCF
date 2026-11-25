module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.CensusPartition
public import ConsensusCoverage.HandReadersA
public import ConsensusCoverage.HandReadersB
import all ConsensusCoverage.CensusPartition
import all ConsensusCoverage.CaseUnreachable
import all ConsensusCoverage.CaseUnreachableB
import all ConsensusCoverage.HandReadersA
import all ConsensusCoverage.HandReadersB
import all ConsensusCoverage.FullProfile
import all ConsensusCoverage.Readers
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReplayAnswers

/-! How many step questions have an exact reader, counting every source:
the compiled readers, the unconditional replay readers, the hand-written
readers, and the impossible cases (constant false). This counts the lists;
it does not combine the readers into one function. -/

namespace ConsensusCoverage.ReaderInventory

set_option maxRecDepth 16384
set_option maxHeartbeats 0

public def exact (b : Classes.StepBranch) : Bool :=
  Readers.covered.contains b || ReplayAnswers.unconditional.contains b ||
    CensusPartition.refuted.contains b || HandReadersA.covered.contains b ||
    HandReadersB.covered.contains b

public def readable : List Classes.StepBranch :=
  FullProfile.stepBranches.toList.filter exact

public def unread : List Classes.StepBranch :=
  FullProfile.stepBranches.toList.filter fun b => !exact b

public theorem count : readable.length = 319 ∧ unread.length = 197 := by decide +kernel

end ConsensusCoverage.ReaderInventory
