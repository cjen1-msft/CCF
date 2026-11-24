module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.JointWitnesses
import all Consensus.Proofs.VoteFacts
import all ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.JointWitnesses
import all ConsensusCoverage.ReplayAnswers
import all ConsensusCoverage.CensusReplay
import all ConsensusCoverage.Readers
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReadersShapes
import all ConsensusCoverage.ReadersIndex
import all ConsensusCoverage.ReadersVoteReply

/-! Positive answers from initialized, replayed schedules. This witnesses
individual proof cases, not a complete joint table of step labels. -/

namespace ConsensusCoverage.CaseWitnesses

open ActionProfile FrontierRows

set_option maxRecDepth 8192
set_option maxHeartbeats 0

private structure Certificate where
  questions : List Classes.StepBranch
  checked : ∀ b ∈ questions, ∃ s : Step, label s (.step b) = true

local instance (r : Run) : Decidable r.valid :=
  inferInstanceAs (Decidable (r.cfg.Nonempty ∧ r.nodes.Nodup))

private def accepts (s : Step) (questions : List Classes.StepBranch) : Bool :=
  let old := ReplayAnswers.read s.cfg s.before s.act s.after s.past
  let generated := Readers.read s.cfg s.before s.act s.after s.past
  questions.all fun b => decide (CensusReplay.answer old generated b = some true)

private def selected (r : Run) (choices : List (Nat × Nat)) (valid : r.valid)
    (offset : Nat) : Option Step := do
  let steps ← JointWitnesses.recordedAt {r with schedule := r.schedule.take (offset + 1)} valid choices
  return (← steps[offset]?).val

private structure Claim (r : Run) (choices : List (Nat × Nat)) (valid : r.valid) where
  offset : Nat
  questions : List Classes.StepBranch
  checked : (selected r choices valid offset).any (accepts · questions) = true

-- The explorer exports offsets and named questions. The kernel replays the
-- selected prefixes and checks each positive answer.
private def certify (r : Run) (choices : List (Nat × Nat)) (valid : r.valid)
    (claims : List (Claim r choices valid)) : Certificate := by
  refine ⟨claims.flatMap (·.questions), ?_⟩
  intro b hb
  obtain ⟨c, _, mem⟩ := List.mem_flatMap.mp hb
  have checked := c.checked
  cases step : selected r choices valid c.offset with
  | none => simp [step] at checked
  | some s =>
    simp only [step, Option.any_some, accepts] at checked
    exact ⟨s, CensusReplay.correct s b (of_decide_eq_true (List.all_eq_true.mp checked b mem))⟩

local macro "caseAt " offset:term:arg questions:term:arg : term =>
  `(⟨$offset, $questions, by decide +kernel⟩)

-- BEGIN GENERATED CERTIFICATES
-- explore.lean --cases --depth 1 --walks 10 --length 20 --seed 20261123
-- --seed-prefixes --retirement --four-nodes.
private def run0 : Run :=
  ⟨{0}, [0, 1], [
    .input 1 (.initAsBackup []),
    .input 0 (.append [{content := .transaction 1 {configuration := some {0, 1}}},
      {content := .signature, flushes := [(1, 3)]}, {content := .signature}]),
    .input 0 (.append [{content := .transaction 1 {}}]),
    .input 0 .nominateSuccessor,
    .input 0 .nominateSuccessor,
    .input 0 .nominateSuccessor,
    .input 0 .nominateSuccessor,
    .deliver 0 1,
    .deliver 0 1,
    .deliver 1 0,
    .deliver 0 1,
    .input 0 (.append [{content := .transaction 1 {configuration := some {1}}},
      {content := .signature, flushes := [(1, 7)]}]),
    .input 0 (.timeout .checkQuorum),
    .deliver 0 1,
    .deliver 0 1,
    .deliver 0 1,
    .deliver 1 0,
    .deliver 0 1,
    .input 1 (.sendEntries 0 7),
    .deliver 1 0]⟩
private def choices0 : List (Nat × Nat) := [(7, 2), (8, 1), (14, 3), (16, 3), (17, 3), (19, 3)]
private theorem valid0 : run0.valid := by decide
private def run0At0 : Claim run0 choices0 valid0 :=
  caseAt 0 [.sorted_now_after_inl, .sorted_post_log_inl, .rooted_now_after_inl, .rooted_post_log_inl]
private def run0At1 : Claim run0 choices0 valid0 :=
  caseAt 1 [.terms_now_after_inl, .active_now_after_inl, .led_cur_now_after_inl, .led_cur_led_after_inl,
    .led_cur_led_cur_inr, .led_cur_lt_or_eq_of_le_inr, .leader_led_now_after_inl, .leader_led_leader_inl,
    .persist_now_after_inl, .persist_seen_after_inr, .messages_mem_network_inr, .message_terms_mem_network_inr,
    .message_terms_h_appendEntriesRequest, .mem_network_mem_append_inr, .new_message_h_appendEntriesRequest]
private def run0At2 : Claim run0 choices0 valid0 := caseAt 2 [.persist_seen_after_inl, .persist_persist_inl]
private def run0At3 : Claim run0 choices0 valid0 :=
  caseAt 3 [.new_message_h_proposeRequestVoteRequest, .summary_event_internal, .summary_input_nominateSuccessor,
    .quiet_summary_either_inl, .nominate_sends_successor_some]
private def run0At8 : Claim run0 choices0 valid0 := caseAt 8 [.new_message_h_appendEntriesResponse]
private def run0At9 : Claim run0 choices0 valid0 := caseAt 9 [.terms_post_log_inl]
private def run0At14 : Claim run0 choices0 valid0 :=
  caseAt 14 [.commitChains_step_committed_inr, .commitChains_step_backing_inl]
private def run0At15 : Claim run0 choices0 valid0 :=
  caseAt 15 [.message_terms_h_requestVoteRequest, .new_message_h_requestVoteRequest]
private def run0At16 : Claim run0 choices0 valid0 :=
  caseAt 16 [.led_cur_lt_or_eq_of_le_inl, .message_terms_h_requestVoteResponse, .new_message_h_requestVoteResponse]
private def run0At17 : Claim run0 choices0 valid0 := caseAt 17 [.terms_now_after_inr, .leader_led_leader_inr]
private def run0At19 : Claim run0 choices0 valid0 := caseAt 19 [.led_cur_led_cur_inl]
private def cert0 : Certificate := certify run0 choices0 valid0
  [run0At0, run0At1, run0At2, run0At3, run0At8, run0At9,
    run0At14, run0At15, run0At16, run0At17, run0At19]

private def run1 : Run :=
  ⟨{0, 1}, [0, 1], [
    .input 0 (.append [{content := .transaction 1 {configuration := some {0}}},
      {content := .signature, flushes := [(1, 3)]}, {content := .signature}]),
    .deliver 0 1,
    .input 0 .nominateSuccessor,
    .input 0 .nominateSuccessor,
    .input 0 (.sendEntries 1 3),
    .deliver 0 1,
    .input 1 (.timeout .election),
    .input 1 (.timeout .election),
    .input 0 .nominateSuccessor,
    .input 0 .nominateSuccessor,
    .deliver 1 0,
    .deliver 0 1,
    .input 1 (.timeout .election),
    .deliver 1 0]⟩
private def choices1 : List (Nat × Nat) := [(11, 1), (13, 2)]
private theorem valid1 : run1.valid := by decide
private def run1At2 : Claim run1 choices1 valid1 := caseAt 2 [.commitChains_step_backing_inr]
private def run1At6 : Claim run1 choices1 valid1 :=
  caseAt 6 [.message_terms_h_requestPreVoteRequest, .new_message_h_requestPreVoteRequest]
private def run1At10 : Claim run1 choices1 valid1 := caseAt 10 [.advance_backed_advance_inr]
private def run1At13 : Claim run1 choices1 valid1 :=
  caseAt 13 [.message_terms_h_requestPreVoteResponse, .new_message_h_requestPreVoteResponse]
private def cert1 : Certificate := certify run1 choices1 valid1 [run1At2, run1At6, run1At10, run1At13]

-- BEGIN BOUNDED CENSUS
private def bounded0 : Run :=
  ⟨{0, 1, 2}, [0, 1, 2], [     .input 0 (.append [{content := .transaction 1 {}}])]⟩
private theorem bounded0Valid : bounded0.valid := by decide
private def bounded0Cert : Certificate := certify bounded0 [] bounded0Valid
  [caseAt 0 [.act_input_append,
    .anchor_lt_or_ge_inl,
    .anchor_lt_or_ge_inr,
    .anchor_now_after_inl,
    .anchor_post_log_inr_inl,
    .canon_mono_canon_after_inl,
    .canon_mono_canon_after_inr,
    .canon_mono_now_after_inl,
    .commitFrontier_invariant_event_internal,
    .commit_backed_kind_append,
    .commit_backed_now_after_inl,
    .copyLogs_step_canon_inr,
    .election_safety_led_after_inl,
    .foldlM__items_nil,
    .inv_step_frontier_now_inl,
    .inv_step_term_mono_now_inl,
    .inv_step_term_mono_seen_inl,
    .inv_step_term_mono_seen_inr,
    .keep_log_kind_append,
    .leader_logs_leader_inl,
    .leader_logs_now_after_inl,
    .post_log_kind_append,
    .post_log_role_inl,
    .post_two_active_inl,
    .post_two_active_inr_inl,
    .rooted_now_after_inr,
    .rooted_post_log_inr_inl,
    .sorted_now_after_inr,
    .sorted_post_log_inr_inl,
    .terms_mem_append_inl,
    .terms_mem_append_inr,
    .terms_post_log_inr_inl]]

private def bounded1 : Run :=
  ⟨{0, 1, 2}, [0, 1, 2], [     .input 0 (.sendEntries 1 0)]⟩
private theorem bounded1Valid : bounded1.valid := by decide
private def bounded1Cert : Certificate := certify bounded1 [] bounded1Valid
  [caseAt 0 [.commit_backed_kind_same,
    .keep_backed_led_after_inl,
    .post_led_origin_inl]]

private def bounded2 : Run :=
  ⟨{0, 1, 2}, [0, 1, 2], [     .input 0 (.sendEntries 1 1)]⟩
private theorem bounded2Valid : bounded2.valid := by decide
private def bounded2Cert : Certificate := certify bounded2 [] bounded2Valid
  [caseAt 0 [.act_input_sendEntries,
    .anchor_post_log_inl,
    .anchor_post_log_inr_inr,
    .keep_log_kind_same,
    .post_log_kind_same,
    .prefix_small_inl,
    .rooted_post_log_inr_inr,
    .sorted_post_log_inr_inr,
    .terms_post_log_inr_inr]]

private def bounded3 : Run :=
  ⟨{0, 1, 2}, [0, 1, 2], [     .input 0 (.timeout .checkQuorum)]⟩
private theorem bounded3Valid : bounded3.valid := by decide
private def bounded3Cert : Certificate := certify bounded3 [] bounded3Valid
  [caseAt 0 [.act_input_timeout,
    .act_kind_checkQuorum]]

private def bounded4 : Run :=
  ⟨{0, 1}, [0, 1, 2], [     .input 2 (.initAsBackup [])]⟩
private theorem bounded4Valid : bounded4.valid := by decide
private def bounded4Cert : Certificate := certify bounded4 [] bounded4Valid
  [caseAt 0 [.act_input_initAsBackup]]

private def bounded5 : Run :=
  ⟨{0, 1, 2}, [0, 1, 2], [     .input 0 (.append [{content := .signature}]),     .input 0 (.sendEntries 1 1)]⟩
private theorem bounded5Valid : bounded5.valid := by decide
private def bounded5Cert : Certificate := certify bounded5 [] bounded5Valid
  [caseAt 1 [.persist_pre_kind_append,
    .persist_pre_kind_same]]

private def bounded6 : Run :=
  ⟨{0, 1, 2}, [0, 1, 2], [     .input 0 (.sendEntries 1 0),     .deliver 0 1]⟩
private theorem bounded6Valid : bounded6.valid := by decide
private def bounded6Cert : Certificate := certify bounded6 [] bounded6Valid
  [caseAt 1 [.accept_backed_max_eq_or_inl,
    .accept_backed_max_eq_or_inr,
    .accept_backed_shape_inl,
    .accept_shape_eq_zero_or_pos_inl,
    .accept_shape_shape_pos,
    .commitFrontier_invariant_event_receive,
    .commit_backed_kind_accept,
    .post_log_accept_shape_inl,
    .post_log_kind_accept,
    .post_two_active_inr_inr_inl,
    .receive_message_appendEntriesRequest]]

private def bounded7 : Run :=
  ⟨{0, 1, 2}, [0, 1, 2], [     .input 0 (.sendEntries 1 1),     .deliver 0 1]⟩
private theorem bounded7Valid : bounded7.valid := by decide
private def bounded7Cert : Certificate := certify bounded7 [] bounded7Valid
  [caseAt 1 [.accept_backed_shape_inr,
    .accept_shape_shape_neg,
    .post_log_accept_shape_inr]]

private def bounded8 : Run :=
  ⟨{0, 1, 2}, [0, 1, 2], [     .input 0 (.append [{content := .signature, flushes := [(1, 2)]}]),     .deliver 0 1,     .deliver 1 0]⟩
private theorem bounded8Valid : bounded8.valid := by decide
private def bounded8Cert : Certificate := certify bounded8 [] bounded8Valid
  [caseAt 2 [.persist_pre_kind_ack]]

private def bounded9 : Run :=
  ⟨{0, 1, 2}, [0, 1, 2], [     .input 0 (.sendEntries 1 1),     .deliver 0 1,     .deliver 1 0]⟩
private theorem bounded9Valid : bounded9.valid := by decide
private def bounded9Cert : Certificate := certify bounded9 [] bounded9Valid
  [caseAt 2 [.commit_backed_fromSource_pos,
    .commit_backed_kind_ack,
    .commit_backed_max_eq_or_inr,
    .keep_log_kind_ack,
    .match_ack_matchIndex_inr,
    .post_log_kind_ack,
    .receive_message_appendEntriesResponse]]

private def bounded10 : Run :=
  ⟨{0, 1, 2}, [0, 1, 2], [     .input 0 (.sendEntries 1 1),     .deliver 0 1,     .input 0 (.append [{content := .transaction 1 {}}])]⟩
private theorem bounded10Valid : bounded10.valid := by decide
private def bounded10Cert : Certificate := certify bounded10 [] bounded10Valid
  [caseAt 2 [.anchor_now_after_inr]]

private def bounded11 : Run :=
  ⟨{0, 1}, [0, 1, 2], [     .input 0 (.append [{content := .signature}]),     .input 0 (.timeout .checkQuorum),     .input 0 (.timeout .election)]⟩
private theorem bounded11Valid : bounded11.valid := by decide
private def bounded11Cert : Certificate := certify bounded11 [] bounded11Valid
  [caseAt 2 [.act_kind_election]]

private def bounded12 : Run :=
  ⟨{0, 1}, [0, 1, 2], [     .input 0 (.append [{content := .signature, flushes := [(1, 2)]}]),     .deliver 0 1,     .deliver 1 0,     .input 2 (.initAsBackup [{term := 2, content := .transaction 0 {configuration := some {0, 1}}}, {term := 2, content := .signature}])]⟩
private theorem bounded12Valid : bounded12.valid := by decide
private def bounded12Cert : Certificate := certify bounded12 [] bounded12Valid
  [caseAt 3 [.commit_backed_kind_install,
    .leader_floor_led_inl,
    .post_log_kind_install,
    .post_two_active_inr_inr_inr]]

private def bounded13 : Run :=
  ⟨{0, 1}, [0, 1], [     .input 0 (.append [{content := .signature, flushes := [(1, 2)]}]),     .deliver 0 1,     .input 0 (.nominateSuccessor),     .deliver 0 1]⟩
private theorem bounded13Valid : bounded13.valid := by decide
private def bounded13Cert : Certificate := certify bounded13 [] bounded13Valid
  [caseAt 3 [.campaign_backed_pre_split_inl,
    .candidate_kind_inl,
    .candidate_now_after_inl,
    .receive_message_proposeRequestVoteRequest]]

private def bounded14 : Run :=
  ⟨{0, 1}, [0, 1], [     .input 0 (.sendEntries 1 1),     .deliver 0 1,     .input 0 (.append [{content := .signature, flushes := [(1, 2)]}]),     .deliver 0 1]⟩
private theorem bounded14Valid : bounded14.valid := by decide
private def bounded14Cert : Certificate := certify bounded14 [] bounded14Valid
  [caseAt 3 [.accept_shape_eq_zero_or_pos_inr]]

private def bounded15 : Run :=
  ⟨{0, 1, 2}, [0, 1, 2], [     .input 0 (.append [{content := .signature, flushes := [(1, 2)]}]),     .deliver 0 1,     .deliver 1 0,     .input 0 (.sendEntries 1 2),     .deliver 0 1]⟩
private theorem bounded15Valid : bounded15.valid := by decide
private def bounded15Cert : Certificate := certify bounded15 [] bounded15Valid
  [caseAt 4 [.accept_persist_shape_inl,
    .persist_pre_kind_accept]]

private def bounded16 : Run :=
  ⟨{0, 1}, [0, 1], [     .input 0 (.append [{content := .signature, flushes := [(1, 2)]}]),     .deliver 0 1,     .input 0 (.nominateSuccessor),     .deliver 0 1,     .deliver 1 0]⟩
private theorem bounded16Valid : bounded16.valid := by decide
private def bounded16Cert : Certificate := certify bounded16 [(4, 1)] bounded16Valid
  [caseAt 4 [.receive_message_requestVoteRequest,
    .receive_vote_pos,
    .rv_stable_now_after_inr]]

private def bounded17 : Run :=
  ⟨{0, 1}, [0, 1], [     .input 0 (.append [{content := .signature}]),     .input 0 (.timeout .checkQuorum),     .input 0 (.timeout .election),     .deliver 0 1,     .deliver 1 0]⟩
private theorem bounded17Valid : bounded17.valid := by decide
private def bounded17Cert : Certificate := certify bounded17 [] bounded17Valid
  [caseAt 4 [.receive_message_requestPreVoteResponse]]

private def bounded18 : Run :=
  ⟨{0, 1}, [0, 1], [     .input 0 (.append [{content := .signature, flushes := [(1, 2)]}]),     .deliver 0 1,     .input 0 (.nominateSuccessor),     .deliver 0 1,     .deliver 1 0,     .deliver 0 1]⟩
private theorem bounded18Valid : bounded18.valid := by decide
private def bounded18Cert : Certificate := certify bounded18 [(4, 1)] bounded18Valid
  [caseAt 5 [.canon_mono_elected_after_inr,
    .commit_backed_kind_elect,
    .completeness_committed_inl,
    .election_safety_led_after_inr,
    .freshCampaign_term_inr,
    .freshCert_backing_inl,
    .freshCert_backing_inr,
    .grantFactsBefore_grant_inl,
    .keep_backed_led_after_inr,
    .leader_logs_leader_inr,
    .led_cur_led_after_inr,
    .led_cur_role_inl,
    .old_complete_elected_after_inr,
    .persist_pre_kind_elect,
    .post_led_origin_inr,
    .post_log_kind_elect,
    .previousBacking_elected_inr,
    .rankedElections_elected_inr,
    .receive_message_requestVoteResponse]]

private def bounded19 : Run :=
  ⟨{0, 1}, [0, 1], [     .input 0 (.append [{content := .signature, flushes := [(1, 2)]}]),     .deliver 0 1,     .input 0 (.nominateSuccessor),     .deliver 0 1,     .deliver 1 0,     .deliver 0 1,     .input 1 (.timeout .checkQuorum)]⟩
private theorem bounded19Valid : bounded19.valid := by decide
private def bounded19Cert : Certificate := certify bounded19 [(4, 1)] bounded19Valid
  [caseAt 6 [.canon_mono_elected_after_inl]]

private def bounded20 : Run :=
  ⟨{0, 1}, [0, 1], [     .input 0 (.append [{content := .signature}]),     .input 0 (.timeout .checkQuorum),     .input 0 (.timeout .election),     .deliver 0 1,     .deliver 1 0,     .input 0 (.timeout .election),     .deliver 0 1]⟩
private theorem bounded20Valid : bounded20.valid := by decide
private def bounded20Cert : Certificate := certify bounded20 [(6, 1)] bounded20Valid
  [caseAt 6 [.receive_message_requestPreVoteRequest]]

private def certificates : List Certificate := [cert0, cert1, bounded0Cert, bounded1Cert, bounded2Cert, bounded3Cert, bounded4Cert, bounded5Cert, bounded6Cert, bounded7Cert, bounded8Cert, bounded9Cert, bounded10Cert, bounded11Cert, bounded12Cert, bounded13Cert, bounded14Cert, bounded15Cert, bounded16Cert, bounded17Cert, bounded18Cert, bounded19Cert, bounded20Cert]
-- END GENERATED CERTIFICATES

/-- The positive cases computed by running the sound reader on the cover. -/
public def witnessed : List Classes.StepBranch :=
  (certificates.flatMap (·.questions)).eraseDups

public theorem count : witnessed.Nodup ∧ witnessed.length = 153 := by decide +kernel

public theorem occurs {b : Classes.StepBranch} (mem : b ∈ witnessed) :
    ∃ s : Step, label s (.step b) = true := by
  obtain ⟨c, _, yes⟩ := List.mem_flatMap.mp (List.mem_eraseDups.mp mem)
  exact c.checked b yes

end ConsensusCoverage.CaseWitnesses
