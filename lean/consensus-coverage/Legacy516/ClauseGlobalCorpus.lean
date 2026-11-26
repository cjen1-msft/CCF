module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseWideTree
import all ConsensusCoverage.ClauseWideTree
import all ConsensusCoverage.ClauseGlobalSamples
import all ConsensusCoverage.ClauseGlobalBatchA
import all ConsensusCoverage.ClauseGlobalBatchB
import all ConsensusCoverage.ClauseGlobalBatchC
import all ConsensusCoverage.ClauseGlobalBatchD
import all ConsensusCoverage.ReadersTotal

namespace ConsensusCoverage.ClauseGlobalCorpus

open ClauseQuestions ClauseGlobalSamples ClauseWideTree

set_option maxRecDepth 16384
set_option maxHeartbeats 0

private def samples := ClauseGlobalBatchA.samples ++ ClauseGlobalBatchB.samples ++ ClauseGlobalBatchC.samples ++ ClauseGlobalBatchD.samples

private def keys := checkedKeys splitKeys samples

private theorem certified : keys.length = 412 ∧ keys.Nodup := by decide +kernel

/-- Every observed distinction on the corpus also separates true initialized
labels. The corpus witnesses a lower bound, not global exhaustion. -/
public theorem global_bound (rows : List RestrictedProfile)
    (complete : ∀ s, restrictedLabel ReadersTotal.covered s ∈ rows) : 412 ≤ rows.length :=
  checked_bound _ _ _ _ certified rows complete

end ConsensusCoverage.ClauseGlobalCorpus
