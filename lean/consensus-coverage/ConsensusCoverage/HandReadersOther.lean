module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.HandReadersABase
import all ConsensusCoverage.HandReadersOtherAdvance
import all ConsensusCoverage.HandReadersOtherFrontier

namespace ConsensusCoverage.HandReadersOther

open Consensus ActionProfile HandReadersA

private def lookup : (b : Classes.StepBranch) → Option (Exact b)
  | .advance_backed_advance_inl => some (Advance.exactReader .identity)
  | .advance_backed_advance_inr => some (Advance.exactReader .growth)
  | .advance_backed_postRole_inl => some (Advance.exactReader .retained)
  | .advance_backed_postRole_inr => some (Advance.exactReader .retired)
  | .advance_backed_self_pos => some (Advance.exactReader .self)
  | .advance_backed_self_neg => some (Advance.exactReader .peer)
  | .advance_le_total_inl => some (Frontier.exactReader true)
  | .advance_le_total_inr => some (Frontier.exactReader false)
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
    (read s.cfg s.before s.act s.after s.past b).isSome = true := by
  simpa only [read, Option.isSome_map] using (List.mem_filter.mp h).2

set_option maxRecDepth 8192 in
public theorem count : covered.Nodup ∧ covered.length = 8 := by decide +kernel

end ConsensusCoverage.HandReadersOther
