module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.HandReadersABase
import all ConsensusCoverage.HandReadersTrunkBElect
import all ConsensusCoverage.HandReadersTrunkBStart

namespace ConsensusCoverage.HandReadersTrunkB

open Consensus ActionProfile

private def lookup : (b : Classes.StepBranch) → Option (HandReadersA.Exact b)
  | .canStartElection_engaged_can_inl => some (Start.exactReader .follower)
  | .canStartElection_engaged_can_inr_inl => some (Start.exactReader .preVote)
  | .canStartElection_engaged_can_inr_inr => some (Start.exactReader .candidate)
  | .elect_result_elected_inl => some (Elect.exactReader false)
  | .elect_result_elected_inr => some (Elect.exactReader true)
  | _ => none

public def covered : List Classes.StepBranch :=
  FullProfile.stepBranches.toList.filter fun b => (lookup b).isSome

public def read (cfg : FullProfile.Configuration) (before : Model.State) (act : Model.Action)
    (after : Model.State) (past : List Model.State) (b : Classes.StepBranch) : Option Bool :=
  (lookup b).map fun r => r.eval cfg before act after past

public theorem read_correct (s : Step) {b v} (h : read s.cfg s.before s.act s.after s.past b = some v) :
    label s (.step b) = v := by
  obtain ⟨r,_,rfl⟩ := Option.map_eq_some_iff.mp h
  exact r.eq_label s

public theorem read_total (s : Step) {b} (h : b ∈ covered) :
    (read s.cfg s.before s.act s.after s.past b).isSome := by
  simpa only [read,Option.isSome_map] using (List.mem_filter.mp h).2

set_option maxRecDepth 8192 in
public theorem count : covered.Nodup ∧ covered.length = 5 := by decide +kernel

end ConsensusCoverage.HandReadersTrunkB
