module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseMatchAck
import all ConsensusCoverage.ClauseExactTables
import all ConsensusCoverage.ClauseMatchAck
import all ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.ReadersTotal

namespace ConsensusCoverage.ClauseFrontierExact

open ActionProfile ClauseExactTables ClauseQuestions

set_option maxHeartbeats 0
set_option maxRecDepth 8192

public def nonTrunk (c : Clause) : List Classes.StepBranch := ClauseMatchAck.nonTrunk c

public noncomputable def nonTrunkLabel (c : Clause) (s : Step) : RestrictedProfile :=
  restrictedLabel (nonTrunk c) s

public theorem column_count : (nonTrunk .frontier).length = 61 := by decide +kernel

public theorem columns_covered : ∀ q ∈ nonTrunk .frontier, q ∈ ReadersTotal.covered := by
  decide +kernel

/-- The exact replay reader for this projection of the proof label. -/
public def read (s : Step) : RestrictedProfile :=
  let query := ReadersTotal.read s.cfg s.before s.act s.after s.past
  ⟨(endpoints s).1, (nonTrunk .frontier).map (fun q => (query q).getD false), (endpoints s).2⟩

public theorem read_eq (s : Step) : read s = nonTrunkLabel .frontier s := by
  have bits : (nonTrunk .frontier).map
      (fun q => (ReadersTotal.read s.cfg s.before s.act s.after s.past q).getD false) =
      (nonTrunk .frontier).map (fun q => label s (.step q)) := by
    apply List.map_congr_left
    intro q h
    rw [ReadersTotal.read_total s (columns_covered q h), Option.getD_some]
  simpa only [read, nonTrunkLabel, restrictedLabel, endpoints, RestrictedProfile.mk.injEq,
    true_and, and_true] using bits

end ConsensusCoverage.ClauseFrontierExact
