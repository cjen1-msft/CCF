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
    .active_now_after_inl, .commitChains_step_committed_inr, .leader_led_leader_inl,
    .leader_led_now_after_inl, .led_cur_led_after_inl, .led_cur_led_cur_inr,
    .led_cur_lt_or_eq_of_le_inr, .led_cur_now_after_inl, .persist_now_after_inl,
    .persist_seen_after_inr, .rooted_now_after_inl, .seen_after_now_after_inl,
    .seen_after_seen_inl, .seen_after_seen_inr, .sorted_now_after_inl, .summary_input_append,
    .terms_now_after_inl
  ], by decide +kernel⟩
private def claim1 : Claim :=
  ⟨0, 1, [.persist_persist_inl, .persist_seen_after_inl], by decide +kernel⟩
private def claim2 : Claim :=
  ⟨3, 2, [
    .message_terms_h_requestPreVoteRequest, .new_message_h_requestPreVoteRequest
  ], by decide +kernel⟩
private def claim3 : Claim :=
  ⟨3, 3, [
    .message_terms_h_requestPreVoteResponse, .new_message_h_requestPreVoteResponse,
    .summary_message_requestPreVoteRequest
  ], by decide +kernel⟩
private def claim4 : Claim :=
  ⟨3, 4, [.led_cur_lt_or_eq_of_le_inl, .summary_message_requestPreVoteResponse], by decide +kernel⟩
private def claim5 : Claim :=
  ⟨3, 5, [
    .message_terms_h_requestVoteResponse, .new_message_h_requestVoteResponse,
    .summary_message_requestVoteRequest
  ], by decide +kernel⟩
private def claim6 : Claim :=
  ⟨3, 6, [.leader_led_leader_inr, .led_cur_led_cur_inl], by decide +kernel⟩
private def claim7 : Claim :=
  ⟨15, 0, [
    .mem_network_mem_append_inr, .messages_mem_network_inr,
    .new_message_h_proposeRequestVoteRequest, .summary_event_internal,
    .summary_input_nominateSuccessor
  ], by decide +kernel⟩
private def claim8 : Claim :=
  ⟨18, 0, [
    .message_terms_h_appendEntriesRequest, .message_terms_mem_network_inr,
    .new_message_h_appendEntriesRequest, .summary_input_sendEntries
  ], by decide +kernel⟩
private def claim9 : Claim :=
  ⟨19, 0, [
    .rooted_post_log_inl, .sorted_post_log_inl, .summary_input_initAsBackup
  ], by decide +kernel⟩
private def claim10 : Claim :=
  ⟨20, 1, [
    .new_message_h_appendEntriesResponse, .summary_event_receive,
    .summary_message_appendEntriesRequest
  ], by decide +kernel⟩
private def claim11 : Claim :=
  ⟨26, 0, [.terms_post_log_inl], by decide +kernel⟩
private def claim12 : Claim :=
  ⟨26, 2, [.match_ack_now_after_inl], by decide +kernel⟩
private def claim13 : Claim :=
  ⟨26, 3, [.match_ack_matchIndex_inl], by decide +kernel⟩
private def claim14 : Claim :=
  ⟨44, 0, [.summary_input_timeout, .summary_kind_checkQuorum], by decide +kernel⟩
private def claim15 : Claim :=
  ⟨46, 2, [.terms_now_after_inr], by decide +kernel⟩
private def claim16 : Claim :=
  ⟨131, 3, [
    .message_terms_h_requestVoteRequest, .new_message_h_requestVoteRequest
  ], by decide +kernel⟩

private def claims : List Claim := [
  claim0, claim1, claim2, claim3, claim4, claim5, claim6, claim7, claim8, claim9, claim10,
  claim11, claim12, claim13, claim14, claim15, claim16
]

/-- Cases witnessed by an executable reader on a replayed corpus step. -/
public def witnessed : List Classes.StepBranch := claims.flatMap (·.questions)

public theorem count : witnessed.Nodup ∧ witnessed.length = 54 := by decide

public theorem union_count :
    (witnessed ++ CaseWitnesses.witnessed).eraseDups.length = 59 := by decide

public theorem occurs {b : Classes.StepBranch} (mem : b ∈ witnessed) :
    ∃ s : Step, label s (.step b) = true := by
  obtain ⟨c, _, found⟩ := List.mem_flatMap.mp mem
  exact c.occurs found

end ConsensusCoverage.ReadersWitnesses
