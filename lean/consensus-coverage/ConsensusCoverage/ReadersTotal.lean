module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.Readers
public import ConsensusCoverage.ReadersEquiv
public import ConsensusCoverage.ReadersExtra
public import ConsensusCoverage.ReadersHand
public import ConsensusCoverage.ReadersRefuted
public import ConsensusCoverage.ReplayAnswers
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.CaseUnreachable
import all ConsensusCoverage.CaseUnreachableB
import all ConsensusCoverage.CensusPartition
import all ConsensusCoverage.FullProfile
import all ConsensusCoverage.HandReadersA
import all ConsensusCoverage.HandReadersB
import all ConsensusCoverage.HandReadersTrunkA
import all ConsensusCoverage.HandReadersTrunkB
import all ConsensusCoverage.HandReadersElection
import all ConsensusCoverage.HandReadersOther
import all ConsensusCoverage.HandReadersTrunkC
import all ConsensusCoverage.Readers
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReadersEquiv
import all ConsensusCoverage.ReadersExtra
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersHand
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
private structure Evidence where
  compiled : Readers.Evidence
  baseline : Thunk ReplayAnswers.Evidence
  hand : Classes.StepBranch → Option Bool

private def prepare (cfg : FullProfile.Configuration) (before : Model.State) (act : Model.Action)
    (after : Model.State) (past : List Model.State) : Evidence :=
  ⟨Readers.read cfg before act after past, Thunk.mk (fun _ =>
    ReplayAnswers.read cfg before act after past), ReadersHand.read? cfg before act after past⟩

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
  (ReadersRefuted.read? b).orElse fun _ =>
    (compiled? e.compiled b).orElse fun _ =>
    if b ∈ ReplayAnswers.unconditional then ReplayAnswers.answer e.baseline.get (.step b)
    else none

private theorem readBase?_correct (s : Step) (b : Classes.StepBranch) {v : Bool}
    (h : readBase? (prepare s.cfg s.before s.act s.after s.past) b = some v) :
    label s (.step b) = v := by
  unfold readBase? prepare at h
  cases negative : ReadersRefuted.read? b with
  | some val =>
    simp only [negative, Option.orElse_some] at h
    exact ReadersRefuted.read?_correct s (negative.trans h)
  | none =>
    simp only [negative, Option.orElse_none] at h
    cases compiled : compiled? (Readers.read s.cfg s.before s.act s.after s.past) b with
    | some val =>
      simp only [compiled, Option.orElse_some] at h
      exact compiled?_correct s (compiled.trans h)
    | none =>
      simp only [compiled, Option.orElse_none] at h
      split at h
      · exact ReplayAnswers.sound s (.step b) h
      · cases h

private theorem readBase?_at (s : Step) {b : Classes.StepBranch} (mem : b ∈ baseColumns) :
    readBase? (prepare s.cfg s.before s.act s.after s.past) b = some (label s (.step b)) := by
  simp only [baseColumns, List.mem_append] at mem
  unfold readBase? prepare
  cases r : ReadersRefuted.read? b with
  | some v => simp only [Option.orElse_some, ReadersRefuted.read?_correct s r]
  | none =>
    simp only [Option.orElse_none]
    rcases mem with (compiled | baseline) | negative
    · simp only [compiled?_at s compiled, Option.orElse_some]
    · cases h : compiled? (Readers.read s.cfg s.before s.act s.after s.past) b with
      | some v => simp only [Option.orElse_some, compiled?_correct s h]
      | none =>
        rw [Option.orElse_none, ite_eq_left baseline]
        exact ReplayAnswers.read_unconditional s baseline
    · rw [ReadersRefuted.read?_at s negative] at r
      contradiction

private def oldColumns : List Classes.StepBranch := baseColumns ++ ReadersEquiv.covered

private def readOld? (e : Evidence) (b : Classes.StepBranch) : Option Bool :=
  (readBase? e b).orElse fun _ =>
    e.compiled.view.bind (fun x => ReadersEquiv.read? x (compiled? e.compiled) b)

private theorem readOld?_correct (s : Step) (b : Classes.StepBranch) {v : Bool}
    (h : readOld? (prepare s.cfg s.before s.act s.after s.past) b = some v) :
    label s (.step b) = v := by
  unfold readOld? at h
  cases base : readBase? (prepare s.cfg s.before s.act s.after s.past) b with
  | some yes =>
    simp only [base, Option.orElse_some] at h
    exact readBase?_correct s b (base.trans h)
  | none =>
    obtain ⟨x, made, ok⟩ := ofXAction_matches s
    have view : (prepare s.cfg s.before s.act s.after s.past).compiled.view = some x := made
    rw [base, Option.orElse_none, view, Option.bind_some] at h
    exact ReadersEquiv.read?_correct s x ok (compiled?_correct s) h

private theorem readOld?_at (s : Step) {b : Classes.StepBranch} (mem : b ∈ oldColumns) :
    readOld? (prepare s.cfg s.before s.act s.after s.past) b = some (label s (.step b)) := by
  simp only [oldColumns, List.mem_append] at mem
  rcases mem with base | equiv
  · simp only [readOld?, readBase?_at s base, Option.orElse_some]
  · unfold readOld?
    cases base : readBase? (prepare s.cfg s.before s.act s.after s.past) b with
    | some yes => simp only [Option.orElse_some, readBase?_correct s b base]
    | none =>
      obtain ⟨x, made, ok⟩ := ofXAction_matches s
      have view : (prepare s.cfg s.before s.act s.after s.past).compiled.view = some x := made
      rw [Option.orElse_none, view, Option.bind_some]
      exact ReadersEquiv.read?_at s x ok (compiled?_at s) equiv

private def coreColumns : List Classes.StepBranch := oldColumns ++ ReadersExtra.covered

private def readCore? (e : Evidence) (b : Classes.StepBranch) : Option Bool :=
  (readOld? e b).orElse fun _ => ReadersExtra.read? e.compiled.cfg e.compiled.view b

private theorem readCore?_correct (s : Step) (b : Classes.StepBranch) {v : Bool}
    (h : readCore? (prepare s.cfg s.before s.act s.after s.past) b = some v) :
    label s (.step b) = v := by
  unfold readCore? at h
  cases old : readOld? (prepare s.cfg s.before s.act s.after s.past) b with
  | some yes =>
    simp only [old, Option.orElse_some] at h
    exact readOld?_correct s b (old.trans h)
  | none =>
    simp only [old, Option.orElse_none] at h
    exact ReadersExtra.read?_correct s h

private theorem readCore?_at (s : Step) {b : Classes.StepBranch} (mem : b ∈ coreColumns) :
    readCore? (prepare s.cfg s.before s.act s.after s.past) b = some (label s (.step b)) := by
  rcases List.mem_append.mp mem with old | extra
  · simp only [readCore?, readOld?_at s old, Option.orElse_some]
  · unfold readCore?
    cases old : readOld? (prepare s.cfg s.before s.act s.after s.past) b with
    | some yes => simp only [Option.orElse_some, readOld?_correct s b old]
    | none => exact ReadersExtra.read?_at s extra

public def covered : List Classes.StepBranch := (coreColumns ++ ReadersHand.covered).eraseDups

private def readPrepared (e : Evidence) (b : Classes.StepBranch) : Option Bool :=
  (readCore? e b).orElse fun _ => e.hand b

/-- Partially apply `read` to share prepared evidence across a step's questions. -/
public def read (cfg : FullProfile.Configuration) (before : Model.State) (act : Model.Action)
    (after : Model.State) (past : List Model.State) : Classes.StepBranch → Option Bool :=
  readPrepared (prepare cfg before act after past)

public theorem read_correct (s : Step) {b : Classes.StepBranch} {v : Bool}
    (h : read s.cfg s.before s.act s.after s.past b = some v) :
    label s (.step b) = v := by
  unfold read readPrepared at h
  cases core : readCore? (prepare s.cfg s.before s.act s.after s.past) b with
  | some yes =>
    simp only [core, Option.orElse_some] at h
    exact readCore?_correct s b (core.trans h)
  | none =>
    simp only [core, Option.orElse_none] at h
    exact ReadersHand.read?_correct s h

public theorem read_total (s : Step) {b : Classes.StepBranch} (mem : b ∈ covered) :
    read s.cfg s.before s.act s.after s.past b = some (label s (.step b)) := by
  simp only [covered, List.mem_eraseDups, List.mem_append] at mem
  rcases mem with core | hand
  · simp only [read, readPrepared, readCore?_at s core, Option.orElse_some]
  · unfold read readPrepared
    cases core : readCore? (prepare s.cfg s.before s.act s.after s.past) b with
    | some yes => simp only [Option.orElse_some, readCore?_correct s b core]
    | none => exact ReadersHand.read?_at s hand

public theorem refuted_covered {b : Classes.StepBranch} (mem : b ∈ CensusPartition.refuted) :
    b ∈ covered :=
  List.mem_eraseDups.mpr (List.mem_append_left _ (List.mem_append_left _
    (List.mem_append_left _ (List.mem_append_right _ mem))))

public theorem covered_nodup : covered.Nodup := by decide +kernel

public def unread : List Classes.StepBranch :=
  FullProfile.stepBranches.toList.filter (· ∉ covered)

/-- Each source's distinct contributions and the deduplicated total. -/
public theorem covered_count :
    Readers.covered.length = 186 ∧
      (ReplayAnswers.unconditional.filter (· ∉ Readers.covered)).length = 2 ∧
      ReadersRefuted.covered.length = 29 ∧
      (ReadersRefuted.covered.filter fun b =>
        b ∉ Readers.covered && b ∉ ReplayAnswers.unconditional).length = 17 ∧
      (ReadersEquiv.covered.filter (· ∉ baseColumns)).length = 2 ∧
      (ReadersExtra.covered.filter (· ∉ oldColumns)).length = 12 ∧
      (HandReadersA.covered.filter (· ∉ coreColumns)).length = 73 ∧
      (HandReadersB.covered.filter (· ∉ coreColumns ++ HandReadersA.covered)).length = 39 ∧
      (HandReadersTrunkA.covered.filter (· ∉ coreColumns ++ HandReadersA.covered ++ HandReadersB.covered)).length = 35 ∧
      (HandReadersTrunkB.covered.filter (· ∉ coreColumns ++ HandReadersA.covered ++ HandReadersB.covered ++ HandReadersTrunkA.covered)).length = 31 ∧
      (HandReadersElection.covered.filter (· ∉ coreColumns ++ HandReadersA.covered ++ HandReadersB.covered ++ HandReadersTrunkA.covered ++ HandReadersTrunkB.covered)).length = 38 ∧
      (HandReadersOther.covered.filter (· ∉ coreColumns ++ HandReadersA.covered ++ HandReadersB.covered ++ HandReadersTrunkA.covered ++ HandReadersTrunkB.covered ++ HandReadersElection.covered)).length = 30 ∧
      (HandReadersTrunkC.covered.filter (· ∉ coreColumns ++ HandReadersA.covered ++ HandReadersB.covered ++ HandReadersTrunkA.covered ++ HandReadersTrunkB.covered ++ HandReadersElection.covered ++ HandReadersOther.covered)).length = 15 ∧
      covered.length = 480 ∧ unread.length = 36 := by decide +kernel

end ConsensusCoverage.ReadersTotal
