module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.HandReadersA
public import ConsensusCoverage.HandReadersB
public import ConsensusCoverage.ActionProfile

namespace ConsensusCoverage.ReadersHand

open Consensus ActionProfile

public def covered : List Classes.StepBranch :=
  HandReadersA.covered ++ HandReadersB.covered

public def read? (cfg : FullProfile.Configuration) (before : Model.State) (act : Model.Action)
    (after : Model.State) (past : List Model.State) (b : Classes.StepBranch) : Option Bool :=
  (HandReadersA.read cfg before act after past b).orElse fun _ =>
    HandReadersB.read cfg before act after past b

public theorem read?_correct (s : Step) {b : Classes.StepBranch} {v : Bool}
    (h : read? s.cfg s.before s.act s.after s.past b = some v) :
    label s (.step b) = v := by
  unfold read? at h
  cases a : HandReadersA.read s.cfg s.before s.act s.after s.past b with
  | some yes =>
    simp only [a, Option.orElse_some] at h
    exact HandReadersA.read_correct s (a.trans h)
  | none =>
    simp only [a, Option.orElse_none] at h
    exact HandReadersB.read_correct s h

public theorem read?_at (s : Step) {b : Classes.StepBranch} (mem : b ∈ covered) :
    read? s.cfg s.before s.act s.after s.past b = some (label s (.step b)) := by
  unfold read?
  cases a : HandReadersA.read s.cfg s.before s.act s.after s.past b with
  | some v => simp only [Option.orElse_some, HandReadersA.read_correct s a]
  | none =>
    rw [Option.orElse_none]
    rcases List.mem_append.mp mem with left | right
    · have h := HandReadersA.read_total s left
      simp [a] at h
    · obtain ⟨v, h⟩ := Option.isSome_iff_exists.mp (HandReadersB.read_total s right)
      exact h.trans (congrArg some (HandReadersB.read_correct s h).symm)

end ConsensusCoverage.ReadersHand
