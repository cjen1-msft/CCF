module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.JointWitnesses
import all ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.JointWitnesses
import all ConsensusCoverage.ReplayAnswers

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
  let r := JointWitnesses.caseReader
  let e := r.prepare s.cfg s.before s.act s.after s.past
  questions.all fun b => decide (r.answer e b = some true)

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
    exact ⟨s, JointWitnesses.caseReader.sound s b (of_decide_eq_true (List.all_eq_true.mp checked b mem))⟩

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

private def certificates : List Certificate := [cert0, cert1]
-- END GENERATED CERTIFICATES

/-- The positive cases computed by running the sound reader on the cover. -/
public def witnessed : List Classes.StepBranch :=
  (certificates.flatMap (·.questions)).eraseDups

public theorem count : witnessed.Nodup ∧ witnessed.length = 44 := by decide +kernel

public theorem occurs {b : Classes.StepBranch} (mem : b ∈ witnessed) :
    ∃ s : Step, label s (.step b) = true := by
  obtain ⟨c, _, yes⟩ := List.mem_flatMap.mp (List.mem_eraseDups.mp mem)
  exact c.checked b yes

end ConsensusCoverage.CaseWitnesses
