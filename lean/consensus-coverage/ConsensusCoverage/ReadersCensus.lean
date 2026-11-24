module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.Readers
public import ConsensusCoverage.ReplayAnswers
import all ConsensusCoverage.Readers
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReplayAnswers

namespace ConsensusCoverage.Readers

set_option maxRecDepth 8192

public theorem covered_count : covered.length = 184 := by decide

/-- Additional total readers, relative to the baseline before composition. -/
public theorem beyond_baseline_count :
    (covered.filter (· ∉ ReplayAnswers.unconditional)).length = 146 := by decide

public theorem combined_count :
    (covered ++ ReplayAnswers.unconditional).eraseDups.length = 186 := by decide

end ConsensusCoverage.Readers
