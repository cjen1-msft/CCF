module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.Families
import all ConsensusCoverage.Families
import all ConsensusCoverage.FreshHeartbeat
import all ConsensusCoverage.FreshHeartbeatResidual
import all ConsensusCoverage.FullProfile

namespace ConsensusCoverage.ReadersWitnessesClosed

open ActionProfile FullProfile

set_option maxHeartbeats 0
set_option maxRecDepth 8192

private def rows : List Profile := Families.closedRows ++ [FreshHeartbeatResidual.read]

private theorem realized {p : Profile} (mem : p ∈ rows) : Realized p := by
  simp only [rows, List.mem_append, List.mem_singleton] at mem
  rcases mem with closed | rfl
  · obtain ⟨s, _, eq⟩ := (Families.exact.2.2 p).mp closed
    exact ⟨s, eq⟩
  · exact ⟨FreshHeartbeat.witness, FreshHeartbeatResidual.exact_profile.symm⟩

/-- Every positive coordinate of the already-certified full profiles. -/
public def witnessed : List Classes.StepBranch :=
  stepBranches.toList.filter fun b => rows.any fun p => p (.step b)

public theorem count : witnessed.Nodup ∧ witnessed.length = 47 := by decide

public theorem occurs {b : Classes.StepBranch} (mem : b ∈ witnessed) :
    ∃ s : Step, label s (.step b) = true := by
  obtain ⟨p, present, yes⟩ := List.any_eq_true.mp (List.mem_filter.mp mem).2
  obtain ⟨s, eq⟩ := realized present
  exact ⟨s, eq ▸ yes⟩

end ConsensusCoverage.ReadersWitnessesClosed
