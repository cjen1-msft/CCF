module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.HandReadersABase
import all ConsensusCoverage.HandReadersElectionBKeys
import all ConsensusCoverage.HandReadersElectionBFind
import all ConsensusCoverage.HandReadersElectionBChoice
import all ConsensusCoverage.HandReadersElectionBLed

namespace ConsensusCoverage.HandReadersElectionB

open Consensus ActionProfile HandReadersA

private def lookup : (b : Classes.StepBranch) → Option (Exact b)
  | .replaceNode_keys_here_pos => some Keys.positive
  | .replaceNode_keys_here_neg => some Keys.negative
  | .find_of_mem_here_pos => some Find.positive
  | .find_of_mem_here_neg => some Find.negative
  | .activeConfigurations_overlap_chosen_bound_inl => some (Choice.exactReader true)
  | .activeConfigurations_overlap_chosen_bound_inr => some (Choice.exactReader false)
  | .led_after_led_inl => some LedRows.bootstrap
  | .led_after_led_inr => some LedRows.elected
  | .led_after_elected_after_inl => some LedRows.previous
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

public theorem read_total (s : Step) {b} (mem : b ∈ covered) :
    (read s.cfg s.before s.act s.after s.past b).isSome = true := by
  simpa only [read,Option.isSome_map] using (List.mem_filter.mp mem).2

set_option maxRecDepth 8192 in
public theorem count : covered.Nodup ∧ covered.length = 9 := by decide +kernel

end ConsensusCoverage.HandReadersElectionB
