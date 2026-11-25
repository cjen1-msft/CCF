module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseLogCluster
import all ConsensusCoverage.ClauseLogCluster
import all ConsensusCoverage.ReadersCorpus

namespace ConsensusCoverage.ClauseLogCluster.Replay

open ActionProfile ClauseQuestions

private def endpoint (code : Nat) : StateCoverage.Row := (code.testBit 1, code.testBit 0)

public def row (pre : Nat) (bits : String) (post : Nat) : RestrictedProfile :=
  ⟨endpoint pre, bits.toList.map (· == '1'), endpoint post⟩

public abbrev Sample := {r : RestrictedProfile // ∃ s : Step, nonTrunkLabel .copyLogs s = r}

public theorem certify (i j : Nat) (r : RestrictedProfile)
    (h : (ReadersCorpus.stepAt i j).map (readLabel .copyLogs) = some r) :
    ∃ s : Step, nonTrunkLabel .copyLogs s = r := by
  obtain ⟨s, _, read⟩ := Option.map_eq_some_iff.mp h
  exact ⟨s, (readLabel_eq (by decide) s).symm.trans read⟩

scoped macro "sample! " i:num j:num pre:num bits:str post:num : term =>
  `(show Sample from
    ⟨row $pre $bits $post, certify $i $j _ (by decide +kernel)⟩)

end ConsensusCoverage.ClauseLogCluster.Replay
