module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.HandReadersABase
import all ConsensusCoverage.HandReadersAAppend
import all ConsensusCoverage.HandReadersABatch
import all ConsensusCoverage.HandReadersACampaign
import all ConsensusCoverage.HandReadersAChain
import all ConsensusCoverage.HandReadersACommitTerm
import all ConsensusCoverage.HandReadersAElection
import all ConsensusCoverage.HandReadersAHandler
import all ConsensusCoverage.HandReadersALeader
import all ConsensusCoverage.HandReadersAObserve
import all ConsensusCoverage.HandReadersAOtherPeer
import all ConsensusCoverage.HandReadersAPrimary
import all ConsensusCoverage.HandReadersAReplyRole
import all ConsensusCoverage.HandReadersASeen
import all ConsensusCoverage.HandReadersASummary
import all ConsensusCoverage.HandReadersAVoter
import all ConsensusCoverage.HandReadersAWin
import all ConsensusCoverage.HandReadersBSummary

namespace ConsensusCoverage.HandReadersA

open Consensus ActionProfile

private def summary (k : HandReadersBSummary.Kind) : Exact (HandReadersBSummary.column k) :=
  ⟨(HandReadersBSummary.answer · · · · · k),(HandReadersBSummary.exact_answer · k)⟩

private def lookup : (b : Classes.StepBranch) → Option (Exact b)
  | .commit_backed_fromSource_neg => some OtherPeer.exactReader
  | .leader_logs_commit_pos => some (Leader.exactReader true)
  | .leader_logs_commit_neg => some (Leader.exactReader false)
  | .wins_elect_committed_pos => some (Win.exactReader true)
  | .wins_elect_committed_neg => some (Win.exactReader false)
  | .commit_backed_eq_zero_or_pos_inl => some (Win.backingReader false)
  | .commit_backed_eq_zero_or_pos_inr => some (Win.backingReader true)
  | .primaryState_log_prefix_commit_pos => some (Primary.exactReader true)
  | .primaryState_log_prefix_commit_neg => some (Primary.exactReader false)
  | .facts_advance_inl_2 => some Primary.exactIdentity
  | .advance_chain_fresh => some (Chain.exactReader true)
  | .advance_chain_backed => some (Chain.exactReader false)
  | .commitChains_step_led_inl => some (CommitTerm.exactReader true)
  | .commitChains_step_led_inr => some (CommitTerm.exactReader false)
  | .campaign_three_campaign_inl => some (CampaignRows.exactReader false true)
  | .campaign_three_campaign_inr => some (CampaignRows.exactReader false false)
  | .campaign_votes_campaign_inl => some (CampaignRows.exactReader true true)
  | .campaign_votes_campaign_inr => some (CampaignRows.exactReader true false)
  | .campaign_votes_more_inl => some (Voter.exactReader true)
  | .campaign_votes_more_inr => some (Voter.exactReader false)
  | .seen_after_seen_inl => some (SeenRows.exactReader .old)
  | .seen_after_seen_inr => some (SeenRows.exactReader .post)
  | .seen_after_now_after_inl => some (SeenRows.exactReader .actor)
  | .led_after_elected_after_inr => some Election.exactReader
  | .elect_backed_termCase_inl => some (Election.termExact true)
  | .elect_backed_termCase_inr => some (Election.termExact false)
  | .initAsBackup_summary_eq_zero_or_pos_inl => some (SummaryRows.exactReader .empty)
  | .initAsBackup_summary_eq_zero_or_pos_inr => some (SummaryRows.exactReader .signed)
  | .appendEntriesRequest_summary_observe_bumping_inl => some (SummaryRows.exactReader .bump)
  | .appendEntriesRequest_summary_role_inl => some (ReplyRole.exactReader .same)
  | .appendEntriesRequest_summary_role_inr_inl => some (ReplyRole.exactReader .followerRole)
  | .appendEntriesRequest_summary_role_inr_inr => some (ReplyRole.exactReader .noneRole)
  | .appendEntriesRequest_summary_follower_inl => some (ReplyRole.exactReader .follower)
  | .appendEntriesRequest_summary_follower_inr => some (ReplyRole.exactReader .retired)
  | .appendEntriesResponse_summary_observe_response_inl => some (SummaryRows.exactReader .higherAck)
  | .appendEntriesResponse_summary_observe_response_inr => some (SummaryRows.exactReader .otherAck)
  | .appendEntry_configuration_none => some (Append.exactReader .none)
  | .appendEntry_configuration_some => some (Append.exactReader .some)
  | .foldlM__items_cons => some (Append.exactReader .cons)
  | .appendBatch_summary_mem_append_inl => some (Batch.exactReader false)
  | .appendBatch_summary_mem_append_inr => some (Batch.exactReader true)
  | .appendBatch_summary_role_inl => some Batch.retained
  | .handleAppendEntriesRequest_stepDown_pos => some (Handler.exactReader .down)
  | .handleAppendEntriesRequest_stepDown_neg => some (Handler.exactReader .stay)
  | .handleAppendEntriesRequest_conflict_none => some (Handler.exactReader .clear)
  | .handleAppendEntriesRequest_conflict_some => some (Handler.exactReader .conflict)
  | .summary_event_internal => some (summary .internal)
  | .summary_input_append => some (summary .append)
  | .summary_input_sendEntries => some (summary .send)
  | .summary_input_timeout => some (summary .timeout)
  | .summary_kind_election => some (summary .election)
  | .observeTerm_log_message_appendEntriesResponse => some (Observe.ackAlias true)
  | .observeTerm_commitIndex_message_appendEntriesResponse => some (Observe.ackAlias false)
  | .observeTerm_log_message_proposeRequestVoteRequest => some (Observe.exactReader true .call)
  | .observeTerm_log_primary_pos => some (Observe.exactReader true .primary)
  | .observeTerm_log_primary_neg => some (Observe.exactReader true .backup)
  | .observeTerm_log_newer_pos => some (Observe.exactReader true .higher)
  | .observeTerm_log_newer_neg => some (Observe.exactReader true .stable)
  | .observeTerm_log_message_other => some (Observe.exactReader true .other)
  | .observeTerm_commitIndex_message_proposeRequestVoteRequest => some (Observe.exactReader false .call)
  | .observeTerm_commitIndex_primary_pos => some (Observe.exactReader false .primary)
  | .observeTerm_commitIndex_primary_neg => some (Observe.exactReader false .backup)
  | .observeTerm_commitIndex_newer_pos => some (Observe.exactReader false .higher)
  | .observeTerm_commitIndex_newer_neg => some (Observe.exactReader false .stable)
  | .observeTerm_commitIndex_message_other => some (Observe.exactReader false .other)
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
  simpa only [read, Option.isSome_map] using (List.mem_filter.mp h).2

set_option maxRecDepth 8192 in
public theorem count : covered.Nodup ∧ covered.length = 65 := by decide +kernel

end ConsensusCoverage.HandReadersA
