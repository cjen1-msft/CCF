module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ReadersWitnessProof
public import ConsensusCoverage.CaseWitnesses
import all ConsensusCoverage.ReadersWitnessProof
import all ConsensusCoverage.ReadersCorpus
import all ConsensusCoverage.Readers
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersPolarGenerated
import all ConsensusCoverage.ReadersPolar
import all ConsensusCoverage.ReplayAnswers
import all ConsensusCoverage.CaseWitnesses

namespace ConsensusCoverage.ReadersWitnesses

open ActionProfile ReadersWitnessProof

set_option maxHeartbeats 0
set_option maxRecDepth 8192

-- Replay the observed offsets with the kernel; the measurements are not proofs.
private def claim0 : Claim :=
  ⟨0, 0, [
    .act_input_append, .active_now_after_inl, .anchor_lt_or_ge_inl, .anchor_lt_or_ge_inr,
    .anchor_now_after_inl, .anchor_post_log_inr_inl, .canon_mono_canon_after_inl,
    .canon_mono_canon_after_inr, .canon_mono_now_after_inl, .commitChains_step_committed_inr,
    .commitFrontier_invariant_event_internal, .commit_backed_kind_append,
    .commit_backed_now_after_inl, .copyLogs_step_canon_inr, .election_safety_led_after_inl,
    .foldlM__items_nil, .foldlM__items_nil_2, .foldl_select_max_values_nil,
    .inv_step_frontier_now_inl, .inv_step_term_mono_now_inl, .inv_step_term_mono_seen_inl,
    .inv_step_term_mono_seen_inr, .keep_log_kind_append, .leader_led_leader_inl,
    .leader_led_now_after_inl, .leader_logs_leader_inl, .leader_logs_now_after_inl,
    .led_cur_led_after_inl, .led_cur_led_cur_inr, .led_cur_lt_or_eq_of_le_inr,
    .led_cur_now_after_inl, .persist_now_after_inl, .persist_seen_after_inr,
    .post_log_kind_append, .post_log_role_inl, .post_two_active_inl, .post_two_active_inr_inl,
    .rooted_now_after_inl, .rooted_post_log_inr_inl, .seen_after_now_after_inl,
    .seen_after_seen_inl, .seen_after_seen_inr, .sorted_now_after_inl, .sorted_post_log_inr_inl,
    .summary_input_append, .terms_mem_append_inl, .terms_mem_append_inr, .terms_now_after_inl,
    .terms_post_log_inr_inl
  ], by decide +kernel⟩
private def claim1 : Claim :=
  ⟨0, 1, [
    .persist_persist_inl, .persist_pre_kind_append, .persist_seen_after_inl
  ], by decide +kernel⟩
private def claim2 : Claim :=
  ⟨1, 0, [.rooted_now_after_inr, .sorted_now_after_inr], by decide +kernel⟩
private def claim3 : Claim :=
  ⟨2, 1, [.persist_pre_kind_same], by decide +kernel⟩
private def claim4 : Claim :=
  ⟨3, 2, [
    .act_kind_election, .message_terms_h_requestPreVoteRequest,
    .new_message_h_requestPreVoteRequest
  ], by decide +kernel⟩
private def claim5 : Claim :=
  ⟨3, 3, [
    .message_terms_h_requestPreVoteResponse, .new_message_h_requestPreVoteResponse,
    .preVoteRequest_summary_observe_bumping_inr, .summary_message_requestPreVoteRequest
  ], by decide +kernel⟩
private def claim6 : Claim :=
  ⟨3, 4, [
    .led_cur_lt_or_eq_of_le_inl, .receive_message_requestPreVoteResponse,
    .summary_message_requestPreVoteResponse
  ], by decide +kernel⟩
private def claim7 : Claim :=
  ⟨3, 5, [
    .message_terms_h_requestVoteResponse, .new_message_h_requestVoteResponse,
    .receive_message_requestVoteRequest, .receive_vote_pos, .rv_stable_now_after_inr,
    .summary_message_requestVoteRequest
  ], by decide +kernel⟩
private def claim8 : Claim :=
  ⟨3, 6, [
    .canon_mono_elected_after_inr, .commit_backed_kind_elect, .election_safety_led_after_inr,
    .freshCampaign_term_inr, .freshCert_backing_inl, .keep_backed_led_after_inr,
    .leader_led_leader_inr, .leader_logs_leader_inr, .led_cur_led_after_inr, .led_cur_led_cur_inl,
    .led_cur_role_inl, .persist_pre_kind_elect, .post_led_origin_inr, .post_log_kind_elect,
    .previousBacking_elected_inr, .rankedElections_elected_inr,
    .receive_message_requestVoteResponse
  ], by decide +kernel⟩
private def claim9 : Claim :=
  ⟨15, 0, [
    .mem_network_mem_append_inr, .messages_mem_network_inr,
    .new_message_h_proposeRequestVoteRequest, .summary_event_internal,
    .summary_input_nominateSuccessor
  ], by decide +kernel⟩
private def claim10 : Claim :=
  ⟨18, 0, [
    .commit_backed_kind_same, .keep_backed_led_after_inl, .message_terms_h_appendEntriesRequest,
    .message_terms_mem_network_inr, .new_message_h_appendEntriesRequest, .post_led_origin_inl,
    .summary_input_sendEntries
  ], by decide +kernel⟩
private def claim11 : Claim :=
  ⟨19, 0, [
    .act_input_initAsBackup, .post_log_kind_same, .prefix_small_inl, .rooted_post_log_inl,
    .rooted_post_log_inr_inr, .sorted_post_log_inl, .sorted_post_log_inr_inr,
    .summary_input_initAsBackup
  ], by decide +kernel⟩
private def claim12 : Claim :=
  ⟨20, 1, [
    .accept_backed_max_eq_or_inl, .accept_backed_max_eq_or_inr, .accept_backed_shape_inr,
    .accept_shape_eq_zero_or_pos_inl, .accept_shape_shape_neg,
    .appendEntriesRequest_summary_observe_bumping_inr, .commitFrontier_invariant_event_receive,
    .commit_backed_kind_accept, .new_message_h_appendEntriesResponse, .post_log_kind_accept,
    .post_two_active_inr_inr_inl, .receive_message_appendEntriesRequest, .summary_event_receive,
    .summary_message_appendEntriesRequest
  ], by decide +kernel⟩
private def claim13 : Claim :=
  ⟨21, 2, [
    .receive_message_appendEntriesResponse, .summary_message_appendEntriesResponse
  ], by decide +kernel⟩
private def claim14 : Claim :=
  ⟨26, 0, [
    .act_input_sendEntries, .anchor_post_log_inl, .anchor_post_log_inr_inr, .terms_post_log_inl,
    .terms_post_log_inr_inr
  ], by decide +kernel⟩
private def claim15 : Claim :=
  ⟨26, 2, [
    .commit_backed_fromSource_pos, .commit_backed_kind_ack, .commit_backed_max_eq_or_inr,
    .keep_log_kind_ack, .match_ack_matchIndex_inr, .match_ack_now_after_inl, .post_log_kind_ack
  ], by decide +kernel⟩
private def claim16 : Claim :=
  ⟨26, 3, [.match_ack_matchIndex_inl], by decide +kernel⟩
private def claim17 : Claim :=
  ⟨32, 1, [
    .accept_backed_shape_inl, .accept_shape_shape_pos, .post_log_accept_shape_inl
  ], by decide +kernel⟩
private def claim18 : Claim :=
  ⟨35, 9, [.candidate_candidate_inl, .candidate_kind_inr], by decide +kernel⟩
private def claim19 : Claim :=
  ⟨44, 0, [
    .act_input_timeout, .act_kind_checkQuorum, .summary_input_timeout, .summary_kind_checkQuorum
  ], by decide +kernel⟩
private def claim20 : Claim :=
  ⟨46, 1, [
    .commit_backed_kind_install, .leader_floor_led_inl, .post_log_kind_install,
    .post_two_active_inr_inr_inr
  ], by decide +kernel⟩
private def claim21 : Claim :=
  ⟨46, 2, [.anchor_now_after_inr, .terms_now_after_inr], by decide +kernel⟩
private def claim22 : Claim :=
  ⟨52, 2, [.persist_pre_kind_ack], by decide +kernel⟩
private def claim23 : Claim :=
  ⟨59, 4, [.accept_persist_shape_inl, .persist_pre_kind_accept], by decide +kernel⟩
private def claim24 : Claim :=
  ⟨70, 4, [.accept_persist_inSender_pos, .accept_persist_shape_inr], by decide +kernel⟩
private def claim25 : Claim :=
  ⟨73, 6, [.receive_vote_neg], by decide +kernel⟩
private def claim26 : Claim :=
  ⟨73, 8, [.freshCampaign_term_inl], by decide +kernel⟩
private def claim27 : Claim :=
  ⟨109, 6, [.completeness_committed_inl], by decide +kernel⟩
private def claim28 : Claim :=
  ⟨112, 7, [.canon_mono_elected_after_inl], by decide +kernel⟩
private def claim29 : Claim :=
  ⟨130, 6, [.canon_mono_now_after_inr, .completeness_committed_inr], by decide +kernel⟩
private def claim30 : Claim :=
  ⟨131, 3, [
    .campaign_backed_pre_split_inl, .candidate_kind_inl, .candidate_now_after_inl,
    .message_terms_h_requestVoteRequest, .new_message_h_requestVoteRequest,
    .receive_message_proposeRequestVoteRequest, .summary_message_proposeRequestVoteRequest
  ], by decide +kernel⟩
private def claim31 : Claim :=
  ⟨131, 5, [.receive_message_requestPreVoteRequest], by decide +kernel⟩

private def claims : List Claim := [
  claim0, claim1, claim2, claim3, claim4, claim5, claim6, claim7, claim8, claim9, claim10,
  claim11, claim12, claim13, claim14, claim15, claim16, claim17, claim18, claim19, claim20,
  claim21, claim22, claim23, claim24, claim25, claim26, claim27, claim28, claim29, claim30,
  claim31
]

/-- Cases witnessed by an executable reader on a replayed corpus step. -/
public def witnessed : List Classes.StepBranch := claims.flatMap (·.questions)

public theorem count : witnessed.Nodup ∧ witnessed.length = 171 := by decide

public theorem union_count :
    (witnessed ++ CaseWitnesses.witnessed).eraseDups.length = 176 := by decide

public theorem occurs {b : Classes.StepBranch} (mem : b ∈ witnessed) :
    ∃ s : Step, label s (.step b) = true := by
  obtain ⟨c, _, found⟩ := List.mem_flatMap.mp mem
  exact c.occurs found

end ConsensusCoverage.ReadersWitnesses
