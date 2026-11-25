module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ActionProfile
import ConsensusCoverage.CaseUnreachable
import ConsensusCoverage.CaseUnreachableB
import ConsensusCoverage.CensusBallots

namespace ConsensusCoverage.ReadersRefuted

open ActionProfile

private structure Roster where
  columns : List Classes.StepBranch
  impossible : ∀ {b}, b ∈ columns → ∀ s : Step, label s (.step b) = false

private def ballots : Roster :=
  ⟨[.ballot_step_mem_after_inl, .ballot_step_mem_after_inr], fun mem s =>
    CensusBallots.label_false s (by
      simpa only [List.mem_cons, List.not_mem_nil, or_false] using mem)⟩

private def rosters : List Roster :=
  [⟨CaseUnreachable.refuted, CaseUnreachable.label_false⟩,
   ⟨CaseUnreachableB.refuted, CaseUnreachableB.label_false⟩, ballots]

/-- Columns with a proof of falsity on every initialized step. -/
public def covered : List Classes.StepBranch := (rosters.flatMap Roster.columns).eraseDups

public theorem impossible {b : Classes.StepBranch} (mem : b ∈ covered) (s : Step) :
    label s (.step b) = false := by
  obtain ⟨source, _, found⟩ := List.mem_flatMap.mp (List.mem_eraseDups.mp mem)
  exact source.impossible found s

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
