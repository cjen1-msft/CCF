module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.Readers
public import ConsensusCoverage.ReadersCorpus
import ConsensusCoverage.ReplayAnswers

namespace ConsensusCoverage.ReadersWitnessProof

open ActionProfile

private def accepts (s : Step) (questions : List Classes.StepBranch) : Bool :=
  let e := Readers.read s.cfg s.before s.act s.after s.past
  let baseline := Thunk.mk fun _ => ReplayAnswers.read s.cfg s.before s.act s.after s.past
  questions.all fun b =>
    (Readers.covered.contains b && ReplayAnswers.answer baseline.get (.step b) == some true) ||
      Readers.read? e b == some true

public def checked (schedule offset : Nat) (questions : List Classes.StepBranch) : Bool :=
  (ReadersCorpus.stepAt schedule offset).any (accepts · questions)

public structure Claim where
  schedule : Nat
  offset : Nat
  questions : List Classes.StepBranch
  accepted : checked schedule offset questions = true

private theorem Claim.reads (c : Claim) {b : Classes.StepBranch} (mem : b ∈ c.questions) :
    ∃ s : Step, Readers.read? (Readers.read s.cfg s.before s.act s.after s.past) b = some true := by
  have ran := c.accepted
  unfold checked at ran
  cases found : ReadersCorpus.stepAt c.schedule c.offset with
  | none => simp [found] at ran
  | some s =>
    simp only [found, Option.any_some, accepts] at ran
    refine ⟨s, ?_⟩
    have accepted := List.all_eq_true.mp ran b mem
    rw [Bool.or_eq_true] at accepted
    rcases accepted with prior | test
    · rw [Bool.and_eq_true] at prior
      exact (Readers.read?_at s (List.contains_iff_mem.mp prior.1)).trans
        (congrArg some (ReplayAnswers.sound s (.step b) (beq_iff_eq.mp prior.2)))
    · exact beq_iff_eq.mp test

public theorem Claim.occurs (c : Claim) {b : Classes.StepBranch} (mem : b ∈ c.questions) :
    ∃ s : Step, label s (.step b) = true := by
  obtain ⟨s, yes⟩ := c.reads mem
  exact ⟨s, Readers.read?_correct s b yes⟩

end ConsensusCoverage.ReadersWitnessProof
