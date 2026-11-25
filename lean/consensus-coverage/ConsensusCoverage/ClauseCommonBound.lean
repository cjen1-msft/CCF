module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseSharedTrees
import all ConsensusCoverage.ClauseSharedTrees
import all ConsensusCoverage.ClauseCommonSamples
import all ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.ClauseSampleBound

namespace ConsensusCoverage.ClauseCommonBound

open ClauseQuestions ClauseSampleBound ClauseCommonSamples

set_option maxHeartbeats 0
set_option maxRecDepth 16384

public def clauses := Clause.all.filter fun c =>
  c != .frontier && c != .distinct && c != .owners && c != .observed

private def leaves := picks.filterMap (lookup .active trees)

private theorem checked : leaves.length = 106 ∧ leaves.Nodup := by decide +kernel

private theorem supported : clauses.all (fun c => ClauseSharedTrees.usesOnly .active c trees) = true :=
  by decide +kernel

public theorem count : clauses.length = 26 := by decide +kernel

/-- The common slice already distinguishes all 106 observed ballot-clause
labels. The other 25 clauses containing the queried sites inherit the same
bound, even when a given site's local slot differs. -/
public theorem common_bound {c : Clause} (member : c ∈ clauses) (rows : List RestrictedProfile)
    (complete : ∀ s, clauseLabel c s ∈ rows) : 106 ≤ rows.length :=
  ClauseSharedTrees.bound .active c trees (List.all_eq_true.mp supported c member)
    picks _ checked rows complete

end ConsensusCoverage.ClauseCommonBound
