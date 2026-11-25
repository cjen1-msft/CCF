module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.Readers
public import ConsensusCoverage.ReadersEquiv
public import ConsensusCoverage.ReadersRefuted
public import ConsensusCoverage.ReplayAnswers
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.CaseUnreachable
import all ConsensusCoverage.CaseUnreachableB
import all ConsensusCoverage.Readers
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReadersEquiv
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersRefuted
import all ConsensusCoverage.ReplayAnswers

namespace ConsensusCoverage.ReadersTotal

open Consensus Consensus.Proofs ActionProfile ReadersAtoms

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxHeartbeats 0
set_option maxRecDepth 8192

/-- Exact readers for initialized steps. This leaves the compiled and
one-sided `Readers` API unchanged, including its raw-view callers. -/
public structure Evidence where
  compiled : Readers.Evidence
  baseline : Thunk ReplayAnswers.Evidence

public def read (cfg : FullProfile.Configuration) (before : Model.State) (act : Model.Action)
    (after : Model.State) (past : List Model.State) : Evidence :=
  ⟨Readers.read cfg before act after past, Thunk.mk fun _ =>
    ReplayAnswers.read cfg before act after past⟩

private def compiled? (e : Readers.Evidence) (b : Classes.StepBranch) : Option Bool :=
  e.view.bind fun x => @ReadersCompiler.readView ⟨e.cfg⟩ x b

private theorem compiled?_correct (s : Step) {b : Classes.StepBranch} {v : Bool}
    (h : compiled? (Readers.read s.cfg s.before s.act s.after s.past) b = some v) :
    label s (.step b) = v := by
  obtain ⟨x, made, _⟩ := ofXAction_matches s
  simp only [compiled?, Readers.read, made, Option.bind_some] at h
  apply Readers.read?_correct s b
  simp only [Readers.read?, Readers.read, made, Option.bind_some, h, Option.orElse_some]

private theorem compiled?_at (s : Step) {b : Classes.StepBranch} (mem : b ∈ Readers.covered) :
    compiled? (Readers.read s.cfg s.before s.act s.after s.past) b = some (label s (.step b)) := by
  obtain ⟨x, made, _⟩ := ofXAction_matches s
  have generated : (@ReadersCompiler.readView ⟨s.cfg⟩ x b).isSome :=
    (@ReadersCompiler.readView_supported ⟨s.cfg⟩ x b).trans (decide_eq_true mem)
  obtain ⟨v, eq⟩ := Option.isSome_iff_exists.mp generated
  have read : compiled? (Readers.read s.cfg s.before s.act s.after s.past) b = some v := by
    change (ofXAction s.cfg s.before s.after s.past s.act).bind
      (fun x => @ReadersCompiler.readView ⟨s.cfg⟩ x b) = some v
    rw [made]
    exact eq
  exact read.trans (congrArg some (compiled?_correct s read).symm)

private def baseColumns : List Classes.StepBranch :=
  Readers.covered ++ ReplayAnswers.unconditional ++ ReadersRefuted.covered

private def readBase? (e : Evidence) (b : Classes.StepBranch) : Option Bool :=
  (compiled? e.compiled b).orElse fun _ =>
    (ReadersRefuted.read? b).orElse fun _ =>
    if b ∈ ReplayAnswers.unconditional then ReplayAnswers.answer e.baseline.get (.step b)
    else none

private theorem readBase?_correct (s : Step) (b : Classes.StepBranch) {v : Bool}
    (h : readBase? (read s.cfg s.before s.act s.after s.past) b = some v) :
    label s (.step b) = v := by
  unfold readBase? read at h
  cases compiled : compiled? (Readers.read s.cfg s.before s.act s.after s.past) b with
  | some val =>
    simp only [compiled, Option.orElse_some] at h
    exact compiled?_correct s (compiled.trans h)
  | none =>
    simp only [compiled, Option.orElse_none] at h
    cases negative : ReadersRefuted.read? b with
    | some val =>
      simp only [negative, Option.orElse_some] at h
      exact ReadersRefuted.read?_correct s (negative.trans h)
    | none =>
      simp only [negative, Option.orElse_none] at h
      split at h
      · exact ReplayAnswers.sound s (.step b) h
      · cases h

private theorem readBase?_at (s : Step) {b : Classes.StepBranch} (mem : b ∈ baseColumns) :
    readBase? (read s.cfg s.before s.act s.after s.past) b = some (label s (.step b)) := by
  simp only [baseColumns, List.mem_append] at mem
  rcases mem with (compiled | baseline) | negative
  · simp only [readBase?, read, compiled?_at s compiled, Option.orElse_some]
  · have legacy := ReplayAnswers.read_unconditional s baseline
    unfold readBase? read
    cases h : compiled? (Readers.read s.cfg s.before s.act s.after s.past) b with
    | some v => simp only [Option.orElse_some, compiled?_correct s h]
    | none =>
      simp only [Option.orElse_none]
      cases r : ReadersRefuted.read? b with
      | some v => simp only [Option.orElse_some, ReadersRefuted.read?_correct s r]
      | none =>
        rw [Option.orElse_none, ite_eq_left baseline]
        exact legacy
  · unfold readBase? read
    cases h : compiled? (Readers.read s.cfg s.before s.act s.after s.past) b with
    | some v => simp only [Option.orElse_some, compiled?_correct s h]
    | none => simp only [Option.orElse_none, ReadersRefuted.read?_at s negative, Option.orElse_some]

public def covered : List Classes.StepBranch := (baseColumns ++ ReadersEquiv.covered).eraseDups

public def read? (e : Evidence) (b : Classes.StepBranch) : Option Bool :=
  (readBase? e b).orElse fun _ =>
    e.compiled.view.bind (fun x => ReadersEquiv.read? x (compiled? e.compiled) b)

public theorem read?_correct (s : Step) (b : Classes.StepBranch) {v : Bool}
    (h : read? (read s.cfg s.before s.act s.after s.past) b = some v) :
    label s (.step b) = v := by
  unfold read? at h
  cases base : readBase? (read s.cfg s.before s.act s.after s.past) b with
  | some yes =>
    simp only [base, Option.orElse_some] at h
    exact readBase?_correct s b (base.trans h)
  | none =>
    obtain ⟨x, made, ok⟩ := ofXAction_matches s
    have view : (read s.cfg s.before s.act s.after s.past).compiled.view = some x := made
    rw [base, Option.orElse_none, view, Option.bind_some] at h
    exact ReadersEquiv.read?_correct s x ok (compiled?_correct s) h

public theorem read?_at (s : Step) {b : Classes.StepBranch} (mem : b ∈ covered) :
    read? (read s.cfg s.before s.act s.after s.past) b = some (label s (.step b)) := by
  simp only [covered, List.mem_eraseDups, List.mem_append] at mem
  rcases mem with base | equiv
  · simp only [read?, readBase?_at s base, Option.orElse_some]
  · unfold read?
    cases base : readBase? (read s.cfg s.before s.act s.after s.past) b with
    | some yes => simp only [Option.orElse_some, readBase?_correct s b base]
    | none =>
      obtain ⟨x, made, ok⟩ := ofXAction_matches s
      have view : (read s.cfg s.before s.act s.after s.past).compiled.view = some x := made
      rw [Option.orElse_none, view, Option.bind_some]
      exact ReadersEquiv.read?_at s x ok (compiled?_at s) equiv

public theorem covered_nodup : covered.Nodup := by decide +kernel

/-- Compiled, baseline-only, all refuted, new false/equivalent, and combined counts. -/
public theorem covered_count :
    Readers.covered.length = 186 ∧
      (ReplayAnswers.unconditional.filter (· ∉ Readers.covered)).length = 2 ∧
      ReadersRefuted.covered.length = 29 ∧
      (ReadersRefuted.covered.filter fun b =>
        b ∉ Readers.covered && b ∉ ReplayAnswers.unconditional).length = 17 ∧
      (ReadersEquiv.covered.filter (· ∉ baseColumns)).length = 2 ∧
      covered.length = 207 := by decide +kernel

end ConsensusCoverage.ReadersTotal
