module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.HandReadersABase
import all ConsensusCoverage.HandReadersOtherAdvance
import all ConsensusCoverage.HandReadersOtherConditionBuild
import all ConsensusCoverage.HandReadersOtherFacts
import all ConsensusCoverage.HandReadersOtherFold
import all ConsensusCoverage.HandReadersOtherFoldNil
import all ConsensusCoverage.HandReadersOtherFrontier
import all ConsensusCoverage.HandReadersOtherPromotion
import all ConsensusCoverage.HandReadersOtherPrefix
import all ConsensusCoverage.HandReadersOtherShorten
import all ConsensusCoverage.HandReadersOtherTransfer
import all ConsensusCoverage.HandReadersOtherVote
import all ConsensusCoverage.HandReadersOtherWeaken

namespace ConsensusCoverage.HandReadersOther

open Consensus ActionProfile HandReadersA

private def lookup : (b : Classes.StepBranch) → Option (Exact b)
  | .facts_advance_inl => some (Facts.exactReader false)
  | .facts_advance_inr => some (Facts.exactReader true)
  | .ite__condition_pos => some (Condition.exactReader true)
  | .ite__condition_neg => some (Condition.exactReader false)
  | .advance_backed_advance_inl => some (Advance.exactReader .identity)
  | .advance_backed_advance_inr => some (Advance.exactReader .growth)
  | .advance_backed_postRole_inl => some (Advance.exactReader .retained)
  | .advance_backed_postRole_inr => some (Advance.exactReader .retired)
  | .advance_backed_self_pos => some (Advance.exactReader .self)
  | .advance_backed_self_neg => some (Advance.exactReader .peer)
  | .foldl_select_max_values_nil => some Fold.nilExact
  | .foldl_select_max_values_cons => some (Fold.exactReader .cons)
  | .foldl_select_max_ih_inl => some (Fold.exactReader .kept)
  | .foldl_select_max_chosen_pos => some (Fold.exactReader .selected)
  | .foldl_select_max_le_total_inl => some (Fold.exactReader .smaller)
  | .foldl_select_max_le_total_inr => some (Fold.exactReader .larger)
  | .foldl_select_max_chosen_neg => some (Fold.exactReader .rejected)
  | .foldl_select_max_ih_inr => some (Fold.exactReader .found)
  | .advance_le_total_inl => some (Frontier.exactReader true)
  | .advance_le_total_inr => some (Frontier.exactReader false)
  | .prefix_small_inr => some Prefix.exactReader
  | .shorten_backed_inl => some (Shorten.exactReader true)
  | .shorten_backed_inr => some (Shorten.exactReader false)
  | .transfer_backed_inl => some (Transfer.exactReader true)
  | .transfer_backed_inr => some (Transfer.exactReader false)
  | .promotedLog_committed_pos => some (Promotion.exactReader true)
  | .promotedLog_committed_neg => some (Promotion.exactReader false)
  | .vals_upToDate_lt_or_eq_of_le_inr => some Vote.exactReader
  | .weaken_backed_inl => some (Weaken.exactReader true)
  | .weaken_backed_inr => some (Weaken.exactReader false)
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
public theorem count : covered.Nodup ∧ covered.length = 30 := by decide +kernel

end ConsensusCoverage.HandReadersOther
