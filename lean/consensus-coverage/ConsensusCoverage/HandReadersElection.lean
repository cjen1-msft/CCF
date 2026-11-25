module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.HandReadersABase
import all ConsensusCoverage.HandReadersElectionCarried
import all ConsensusCoverage.HandReadersElectionGrant
import all ConsensusCoverage.HandReadersElectionRank

namespace ConsensusCoverage.HandReadersElection

open Consensus ActionProfile HandReadersA

private def lookup : (b : Classes.StepBranch) → Option (Exact b)
  | .carried_of_chain_certificate_fresh => some (Carried.exactReader .fresh)
  | .carried_of_chain_certificate_backed => some (Carried.exactReader .backed)
  | .carried_of_chain_agreement_inl => some (Carried.exactReader .contained)
  | .carried_of_chain_agreement_inr => some (Carried.exactReader .agree)
  | .grantFactsBefore_grant_inr => some (Grant.exactReader .recorded)
  | .grantFactsBefore_supported_inl => some (Grant.exactReader .self)
  | .grantFactsBefore_supported_inr => some (Grant.exactReader .seen)
  | .rankAtGrant_up_to_date_inl => some (Rank.exactReader .ahead)
  | .rankAtGrant_up_to_date_inr => some (Rank.exactReader .tied)
  | .rankAtGrant_term_inl => some (Rank.exactReader .older)
  | .rankAtGrant_term_inr => some (Rank.exactReader .same)
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
public theorem count : covered.Nodup ∧ covered.length = 11 := by decide +kernel

end ConsensusCoverage.HandReadersElection
