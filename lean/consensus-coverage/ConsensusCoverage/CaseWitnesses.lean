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

private def accepts (s : Step) (indices : List Nat) : Bool :=
  let r := JointWitnesses.caseReader
  let e := r.prepare s.cfg s.before s.act s.after s.past
  indices.all fun i => FullProfile.stepBranches[i]?.any fun b => decide (r.answer e b = some true)

private def selected (r : Run) (choices : List (Nat × Nat)) (valid : r.valid)
    (offset : Nat) : Option Step := do
  let steps ← JointWitnesses.recordedAt {r with schedule := r.schedule.take (offset + 1)} valid choices
  return (← steps[offset]?).val

private structure Claim (r : Run) (choices : List (Nat × Nat)) (valid : r.valid) where
  offset : Nat
  indices : List Nat
  checked : (selected r choices valid offset).any (accepts · indices) = true

-- The explorer exports numeric offsets and indices. The kernel replays the
-- selected prefixes, checks the positive answers, and computes the branch list.
private def certify (r : Run) (choices : List (Nat × Nat)) (valid : r.valid)
    (claims : List (Claim r choices valid)) : Certificate := by
  refine ⟨claims.flatMap (fun c => c.indices.filterMap (FullProfile.stepBranches[·]?)), ?_⟩
  intro b hb
  obtain ⟨c, _, yes⟩ := List.mem_flatMap.mp hb
  obtain ⟨i, hi, branch⟩ := List.mem_filterMap.mp yes
  have checked := c.checked
  cases step : selected r choices valid c.offset with
  | none => simp [step] at checked
  | some s =>
    simp only [step, Option.any_some, accepts] at checked
    have answer := List.all_eq_true.mp checked i hi
    rw [branch] at answer
    exact ⟨s, JointWitnesses.caseReader.sound s b (of_decide_eq_true answer)⟩

local macro "caseAt " offset:term:arg indices:term:arg : term =>
  `(⟨$offset, $indices, by decide +kernel⟩)

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
private def run0At0 : Claim run0 choices0 valid0 := caseAt 0 [7, 8, 78, 79]
private def run0At1 : Claim run0 choices0 valid0 :=
  caseAt 1 [0, 12, 13, 14, 16, 18, 21, 22, 62, 66, 71, 72, 73, 186, 187]
private def run0At2 : Claim run0 choices0 valid0 := caseAt 2 [63, 64]
private def run0At3 : Claim run0 choices0 valid0 := caseAt 3 [193, 272, 278, 362, 377]
private def run0At8 : Claim run0 choices0 valid0 := caseAt 8 [188]
private def run0At9 : Claim run0 choices0 valid0 := caseAt 9 [1]
private def run0At14 : Claim run0 choices0 valid0 := caseAt 14 [88, 89]
private def run0At15 : Claim run0 choices0 valid0 := caseAt 15 [74, 189]
private def run0At16 : Claim run0 choices0 valid0 := caseAt 16 [17, 75, 190]
private def run0At17 : Claim run0 choices0 valid0 := caseAt 17 [6, 23]
private def run0At19 : Claim run0 choices0 valid0 := caseAt 19 [15]
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
private def run1At2 : Claim run1 choices1 valid1 := caseAt 2 [90]
private def run1At6 : Claim run1 choices1 valid1 := caseAt 6 [76, 191]
private def run1At10 : Claim run1 choices1 valid1 := caseAt 10 [151]
private def run1At13 : Claim run1 choices1 valid1 := caseAt 13 [77, 192]
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
