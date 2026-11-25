module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.CensusPartition

namespace ConsensusCoverage.ReadersRefuted

open ActionProfile

/-- Columns with a proof of falsity on every initialized step. -/
public def covered : List Classes.StepBranch := CensusPartition.refuted

public theorem impossible {b : Classes.StepBranch} (mem : b ∈ covered) (s : Step) :
    label s (.step b) = false :=
  CensusPartition.impossible mem s

public def read? (b : Classes.StepBranch) : Option Bool :=
  if b ∈ covered then some false else none

public theorem read?_at (s : Step) {b : Classes.StepBranch} (mem : b ∈ covered) :
    read? b = some (label s (.step b)) := by
  simp only [read?, ite_eq_left mem, impossible mem s]

public theorem read?_correct (s : Step) {b : Classes.StepBranch} {v : Bool}
    (h : read? b = some v) : label s (.step b) = v := by
  unfold read? at h
  split at h
  · exact (impossible ‹_› s).trans (Option.some.inj h)
  · cases h

end ConsensusCoverage.ReadersRefuted
