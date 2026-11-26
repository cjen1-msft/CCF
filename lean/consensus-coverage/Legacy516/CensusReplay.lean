module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.Readers
public import ConsensusCoverage.ReplayAnswers
import all ConsensusCoverage.ReplayAnswers

namespace ConsensusCoverage.CensusReplay

open ActionProfile

/-- Retain all one-sided answers from either reader. -/
@[noinline] public def answer (old : ReplayAnswers.Evidence) (generated : Readers.Evidence)
    (b : Classes.StepBranch) : Option Bool :=
  (ReplayAnswers.answer old (.step b)).orElse fun _ => Readers.read? generated b

public theorem correct (s : Step) (b : Classes.StepBranch) {v : Bool}
    (h : answer (ReplayAnswers.read s.cfg s.before s.act s.after s.past)
      (Readers.read s.cfg s.before s.act s.after s.past) b = some v) :
    label s (.step b) = v := by
  unfold answer at h
  cases eq : ReplayAnswers.answer (ReplayAnswers.read s.cfg s.before s.act s.after s.past)
      (.step b) with
  | none =>
    rw [eq] at h
    exact Readers.read?_correct s b h
  | some a =>
    rw [eq] at h
    cases h
    exact ReplayAnswers.sound s (.step b) eq

end ConsensusCoverage.CensusReplay
