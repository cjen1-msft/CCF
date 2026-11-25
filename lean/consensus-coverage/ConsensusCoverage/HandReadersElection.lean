module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.HandReadersABase
public import ConsensusCoverage.HandReadersElectionTables
import all ConsensusCoverage.HandReadersElectionAgreement
import all ConsensusCoverage.HandReadersElectionCarried
import all ConsensusCoverage.HandReadersElectionChosen
import all ConsensusCoverage.HandReadersElectionCore
import all ConsensusCoverage.HandReadersElectionFilter
import all ConsensusCoverage.HandReadersElectionGrant
import all ConsensusCoverage.HandReadersElectionLater
import all ConsensusCoverage.HandReadersElectionMono
import all ConsensusCoverage.HandReadersElectionOrder
import all ConsensusCoverage.HandReadersElectionRank
import all ConsensusCoverage.HandReadersElectionRooted
import all ConsensusCoverage.HandReadersElectionTip
import all ConsensusCoverage.HandReadersElectionZip

namespace ConsensusCoverage.HandReadersElection

open Consensus ActionProfile HandReadersA

private def lookup : (b : Classes.StepBranch) → Option (Exact b)
  | .agree_or_contained_lt_or_ge_inl => some (Agreement.exactReader true)
  | .agree_or_contained_lt_or_ge_inr => some (Agreement.exactReader false)
  | .carried_of_chain_certificate_fresh => some (Carried.exactReader .fresh)
  | .carried_of_chain_certificate_backed => some (Carried.exactReader .backed)
  | .carried_of_chain_agreement_inl => some (Carried.exactReader .contained)
  | .carried_of_chain_agreement_inr => some (Carried.exactReader .agree)
  | .core_covered_pos => some (Core.exactReader .covered)
  | .core_covered_neg => some (Core.exactReader .uncovered)
  | .core_rank_bound_inl => some (Core.exactReader .ahead)
  | .core_rank_bound_inr => some (Core.exactReader .tied)
  | .core_lt_or_eq_of_le_inl => some (Core.exactReader .strict)
  | .core_lt_or_eq_of_le_inr => some (Core.exactReader .equal)
  | .grantFactsBefore_grant_inr => some (Grant.exactReader .recorded)
  | .grantFactsBefore_supported_inl => some (Grant.exactReader .self)
  | .grantFactsBefore_supported_inr => some (Grant.exactReader .seen)
  | .rankAtGrant_up_to_date_inl => some (Rank.exactReader .ahead)
  | .rankAtGrant_up_to_date_inr => some (Rank.exactReader .tied)
  | .rankAtGrant_term_inl => some (Rank.exactReader .older)
  | .rankAtGrant_term_inr => some (Rank.exactReader .same)
  | .tip_chain_fresh => some (Tip.exactReader true)
  | .tip_chain_backed => some (Tip.exactReader false)
  | .zipIdx_sorted_log_nil => some (Zip.exactReader false)
  | .zipIdx_sorted_log_cons => some (Zip.exactReader true)
  | .getElem_le_of_lt_length_filter_i_inl => some (Filter.exactReader true)
  | .getElem_le_of_lt_length_filter_i_inr => some (Filter.exactReader false)
  | .chosen_bound_counted_pos => some (Chosen.exactReader .counted)
  | .chosen_bound_counted_neg => some (Chosen.exactReader .none)
  | .chosen_bound_mem_cons_inl => some (Chosen.exactReader .head)
  | .chosen_bound_mem_cons_inr => some Later.exactReader
  | .rooted_overlap_eq_zero_or_pos_inl => some (RootedRows.exactReader .zero)
  | .rooted_overlap_eq_zero_or_pos_inr => some (RootedRows.exactReader .positive)
  | .rooted_overlap_bound_inl => some (RootedRows.exactReader .within)
  | .rooted_overlap_bound_inr => some (RootedRows.exactReader .first)
  | .termAt_mono_eq_zero_or_pos_inr => some (Mono.exactReader .positive)
  | .termAt_mono_eq_or_lt_of_le_inl => some (Mono.exactReader .equal)
  | .termAt_mono_eq_or_lt_of_le_inr => some (Mono.exactReader .short)
  | .activeConfigurations_overlap_le_total_inl => some (Order.exactReader true)
  | .activeConfigurations_overlap_le_total_inr => some (Order.exactReader false)
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
public theorem count : covered.Nodup ∧ covered.length = 38 := by decide +kernel

end ConsensusCoverage.HandReadersElection
