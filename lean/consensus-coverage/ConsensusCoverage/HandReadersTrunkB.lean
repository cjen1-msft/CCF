module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.HandReadersABase
import all ConsensusCoverage.HandReadersTrunkBCampaign
import all ConsensusCoverage.HandReadersTrunkBCandidate
import all ConsensusCoverage.HandReadersTrunkBCandidateSends
import all ConsensusCoverage.HandReadersTrunkBElect
import all ConsensusCoverage.HandReadersTrunkBLoop
import all ConsensusCoverage.HandReadersTrunkBPrimary
import all ConsensusCoverage.HandReadersTrunkBStart

namespace ConsensusCoverage.HandReadersTrunkB

open Consensus ActionProfile

private def lookup : (b : Classes.StepBranch) → Option (HandReadersA.Exact b)
  | .canStartElection_engaged_can_inl => some (Start.exactReader .follower)
  | .canStartElection_engaged_can_inr_inl => some (Start.exactReader .preVote)
  | .canStartElection_engaged_can_inr_inr => some (Start.exactReader .candidate)
  | .elect_result_elected_inl => some (Elect.exactReader false)
  | .elect_result_elected_inr => some (Elect.exactReader true)
  | .becomeCandidate_result_done_inl => some (Candidate.exactReader .wait)
  | .becomeCandidate_result_done_inr => some (Candidate.exactReader .win)
  | .becomeCandidate_result_started_inl => some (Candidate.exactReader .start)
  | .becomeCandidate_result_started_inr => some (Candidate.exactReader .ballot)
  | .becomeCandidate_sends_elected_inl => some (CandidateSends.exactReader .wait)
  | .becomeCandidate_sends_elected_inr => some (CandidateSends.exactReader .win)
  | .becomeCandidate_sends_mem_append_inl => some (CandidateSends.exactReader .start)
  | .becomeCandidate_sends_mem_append_inr => some (CandidateSends.exactReader .ballot)
  | .becomePrimary_sends_mem_append_inl => some (Primary.exactReader false)
  | .becomePrimary_sends_mem_append_inr => some (Primary.exactReader true)
  | .campaign_summary_result_inl => some (CampaignRows.exactReader .wait)
  | .campaign_summary_campaign_inl => some (CampaignRows.exactReader .fresh)
  | .campaign_summary_campaign_inr => some (CampaignRows.exactReader .kept)
  | .campaign_summary_result_inr => some (CampaignRows.exactReader .win)
  | .campaign_summary_role_inl => some (CampaignRows.exactReader .role)
  | .campaign_summary_started_inl => some (CampaignRows.exactReader .nominate)
  | .campaign_summary_started_inr_inl => some (CampaignRows.exactReader .ping)
  | .campaign_summary_started_inr_inr => some (CampaignRows.exactReader .ballot)
  | .forIn__items_nil => some (Loops.exactReader .nil)
  | .forIn__items_cons => some (Loops.exactReader .cons)
  | .forIn__step_done => some (Loops.exactReader .done_)
  | .forIn__step_yield => some (Loops.exactReader .yield_)
  | .forIn__mem_append_inl => some (Loops.exactReader .head)
  | .forIn__mem_append_inr => some (Loops.exactReader .tail)
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
public theorem count : covered.Nodup ∧ covered.length = 29 := by decide +kernel

end ConsensusCoverage.HandReadersTrunkB
