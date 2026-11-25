module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.HandReadersA
public import ConsensusCoverage.HandReadersB
public import ConsensusCoverage.HandReadersTrunkA
public import ConsensusCoverage.HandReadersTrunkB
public import ConsensusCoverage.HandReadersElection
public import ConsensusCoverage.HandReadersOther
public import ConsensusCoverage.HandReadersTrunkC
public import ConsensusCoverage.ActionProfile

namespace ConsensusCoverage.ReadersHand

open Consensus ActionProfile

private abbrev Reader :=
  FullProfile.Configuration → Model.State → Model.Action → Model.State →
    List Model.State → Classes.StepBranch → Option Bool

private def orElseReader (r1 r2 : Reader) : Reader :=
  fun cfg before act after past b =>
    (r1 cfg before act after past b).orElse fun _ =>
      r2 cfg before act after past b

private theorem orElse_correct {r1 r2 : Reader}
    (c1 : ∀ (s : Step) {b v}, r1 s.cfg s.before s.act s.after s.past b = some v → label s (.step b) = v)
    (c2 : ∀ (s : Step) {b v}, r2 s.cfg s.before s.act s.after s.past b = some v → label s (.step b) = v)
    (s : Step) {b : Classes.StepBranch} {v : Bool}
    (h : orElseReader r1 r2 s.cfg s.before s.act s.after s.past b = some v) :
    label s (.step b) = v := by
  unfold orElseReader at h
  cases a : r1 s.cfg s.before s.act s.after s.past b with
  | some yes =>
    simp only [a, Option.orElse_some] at h
    exact c1 s (a.trans h)
  | none =>
    simp only [a, Option.orElse_none] at h
    exact c2 s h

private theorem orElse_total {r1 r2 : Reader} {l1 l2 : List Classes.StepBranch}
    (t1 : ∀ (s : Step) {b}, b ∈ l1 → (r1 s.cfg s.before s.act s.after s.past b).isSome = true)
    (t2 : ∀ (s : Step) {b}, b ∈ l2 → (r2 s.cfg s.before s.act s.after s.past b).isSome = true)
    (s : Step) {b : Classes.StepBranch} (mem : b ∈ l1 ++ l2) :
    (orElseReader r1 r2 s.cfg s.before s.act s.after s.past b).isSome = true := by
  unfold orElseReader
  cases a : r1 s.cfg s.before s.act s.after s.past b with
  | some _ => simp only [Option.orElse_some, Option.isSome_some]
  | none =>
    rw [Option.orElse_none]
    rcases List.mem_append.mp mem with left | right
    · have h := t1 s left
      simp [a] at h
    · exact t2 s right

public def covered : List Classes.StepBranch :=
  HandReadersA.covered ++ HandReadersB.covered ++
    HandReadersTrunkA.covered ++ HandReadersTrunkB.covered ++
    HandReadersElection.covered ++ HandReadersOther.covered ++
    HandReadersTrunkC.covered

public def read? (cfg : FullProfile.Configuration) (before : Model.State) (act : Model.Action)
    (after : Model.State) (past : List Model.State) (b : Classes.StepBranch) : Option Bool :=
  orElseReader
    (orElseReader
      (orElseReader
        (orElseReader
          (orElseReader
            (orElseReader HandReadersA.read HandReadersB.read)
            HandReadersTrunkA.read)
          HandReadersTrunkB.read)
        HandReadersElection.read)
      HandReadersOther.read)
    HandReadersTrunkC.read
    cfg before act after past b

public theorem read?_correct (s : Step) {b : Classes.StepBranch} {v : Bool}
    (h : read? s.cfg s.before s.act s.after s.past b = some v) :
    label s (.step b) = v :=
  orElse_correct
    (orElse_correct
      (orElse_correct
        (orElse_correct
          (orElse_correct
            (orElse_correct HandReadersA.read_correct HandReadersB.read_correct)
            HandReadersTrunkA.read_correct)
          HandReadersTrunkB.read_correct)
        HandReadersElection.read_correct)
      HandReadersOther.read_correct)
    HandReadersTrunkC.read_correct s h

private theorem read?_total (s : Step) {b : Classes.StepBranch} (mem : b ∈ covered) :
    (read? s.cfg s.before s.act s.after s.past b).isSome = true :=
  orElse_total
    (orElse_total
      (orElse_total
        (orElse_total
          (orElse_total
            (orElse_total HandReadersA.read_total HandReadersB.read_total)
            HandReadersTrunkA.read_total)
          HandReadersTrunkB.read_total)
        HandReadersElection.read_total)
      HandReadersOther.read_total)
    HandReadersTrunkC.read_total s mem

public theorem read?_at (s : Step) {b : Classes.StepBranch} (mem : b ∈ covered) :
    read? s.cfg s.before s.act s.after s.past b = some (label s (.step b)) := by
  obtain ⟨v, h⟩ := Option.isSome_iff_exists.mp (read?_total s mem)
  exact h.trans (congrArg some (read?_correct s h).symm)

end ConsensusCoverage.ReadersHand
