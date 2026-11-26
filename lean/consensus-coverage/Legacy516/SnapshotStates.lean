module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.HistoryCollision
import ConsensusCoverage.NoBackingWitness
import all ConsensusCoverage.FrontierRows
import all ConsensusCoverage.StateCoverage
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.SnapshotStates

open Consensus Consensus.Model Consensus.Model.Node
open StateCoverage (Row Run read Holds)

/-- Compatibility hides the complete past and the bootstrap configuration. -/
public def Supports (s : Model.State) (r : Row) : Prop :=
  ∃ cfg ns past, Run cfg ns s past ∧ read cfg s past = r

private noncomputable def possible (s : Model.State) (r : Row) : Bool :=
  open Classical in decide (Supports s r)

@[simp] private theorem possible_iff (s : Model.State) (r : Row) :
    possible s r = true ↔ Supports s r := by classical simp [possible]

/-- Canonically ordered set, not a choice of one compatible history. -/
public noncomputable def observe (s : Model.State) : List Row :=
  StateCoverage.table.filter (possible s)

public theorem mem_observe (s : Model.State) (r : Row) : r ∈ observe s ↔ Supports s r := by
  have listed : r ∈ StateCoverage.table := by
    rcases r with ⟨a, b⟩; cases a <;> cases b <;> decide
  simp [observe, listed]

/-- A single initialized run has to supply the answers to *all* questions. -/
public def Admits (s : Model.State) (answers : Classes.StateBranch → Prop) : Prop :=
  ∃ cfg ns past, Run cfg ns s past ∧ ∀ b, Holds cfg s past b ↔ answers b

public theorem same_answers (s t : Model.State) :
    observe s = observe t ↔ ∀ answers, Admits s answers ↔ Admits t answers := by
  have transfer {s t : Model.State} (h : observe s = observe t) {answers} :
      Admits s answers → Admits t answers := by
    rintro ⟨cfg, ns, past, run, hAns⟩
    have mem := (mem_observe s _).mpr ⟨cfg, ns, past, run, rfl⟩
    rw [h, mem_observe] at mem
    obtain ⟨c, n, p, run', eq⟩ := mem
    exact ⟨c, n, p, run', fun b => ((StateCoverage.same_answers run' run).mp eq b).trans (hAns b)⟩
  have recover {s t : Model.State} (h : ∀ ans, Admits s ans → Admits t ans) {r} :
      Supports s r → Supports t r := by
    rintro ⟨cfg, ns, past, run, rfl⟩
    obtain ⟨c, n, p, run', ans⟩ := h (Holds cfg s past) ⟨cfg, ns, past, run, fun _ => Iff.rfl⟩
    exact ⟨c, n, p, run', (StateCoverage.same_answers run' run).mpr ans⟩
  constructor
  · intro eq answers; exact ⟨transfer eq, transfer eq.symm⟩
  · intro h
    apply List.filter_congr
    intro r _
    exact Bool.eq_iff_iff.mpr ((possible_iff s r).trans
      ((Iff.intro (recover fun a => (h a).mp) (recover fun a => (h a).mpr)).trans (possible_iff t r).symm))

private abbrev emptyRow : Row := (false, false)
private abbrev unbacked : Row := (true, false)
private abbrev backed : Row := (true, true)
private abbrev noZero : Row := (false, true)

public def activeTable : List (List Row) := [[unbacked], [backed], [noZero], [unbacked, backed]]
public def table : List (List Row) := [emptyRow] :: activeTable

public theorem counts :
    activeTable.Nodup ∧ activeTable.length = 4 ∧ table.Nodup ∧ table.length = 5 := by decide

private theorem empty_observe {cfg ns s past} (run : Run cfg ns s past) (empty : s.nodes = []) :
    observe s = [emptyRow] := by
  have spec (r : Row) : Supports s r ↔ emptyRow = r := by
    constructor
    · rintro ⟨c, n, p, _, eq⟩; simpa [StateCoverage.read, empty] using eq
    · rintro rfl; exact ⟨cfg, ns, past, run, by simp [StateCoverage.read, empty]⟩
  have eq (r : Row) : possible s r = decide (emptyRow = r) :=
    Bool.eq_iff_iff.mpr (by simp [spec])
  simp [observe, StateCoverage.table, eq]

private theorem same_zero {s : Model.State} {r q : Row} (a : Supports s r) (b : Supports s q) :
    r.1 = q.1 := by
  obtain ⟨_, _, _, _, rfl⟩ := a
  obtain ⟨_, _, _, _, rfl⟩ := b
  rfl

/-- The zero bit is visible in the snapshot. Only the backing bit can vary
between compatible histories. On a nonempty cluster at least one bit is set. -/
public theorem complete {cfg ns s past} (run : Run cfg ns s past) (ne : s.nodes ≠ []) :
    observe s ∈ activeTable := by
  have noEmpty : possible s emptyRow = false := by
    apply Bool.eq_false_iff.mpr
    intro yes
    obtain ⟨c, n, p, h, eq⟩ := (possible_iff ..).mp yes
    have mem := (StateCoverage.exact emptyRow).2.mpr ⟨c, n, s, p, h, eq, fun _ => ne⟩
    exact (by decide : emptyRow ∉ StateCoverage.activeTable) mem
  let actual := read cfg s past
  have seen : possible s actual = true := (possible_iff ..).mpr ⟨cfg, ns, past, run, rfl⟩
  have fixed (r q : Row) (hr : possible s r = true) (hq : possible s q = true) : r.1 = q.1 :=
    same_zero ((possible_iff ..).mp hr) ((possible_iff ..).mp hq)
  have notBoth₀ := fixed unbacked noZero
  have notBoth₁ := fixed backed noZero
  have someBit : possible s unbacked = true ∨ possible s backed = true ∨ possible s noZero = true := by
    rcases actual with ⟨a, b⟩; cases a <;> cases b <;> simp_all
  change [emptyRow, unbacked, backed, noZero].filter (possible s) ∈ activeTable
  cases h₀ : possible s unbacked <;> cases h₁ : possible s backed <;>
    cases h₂ : possible s noZero <;>
      simp_all [activeTable, -possible_iff]

public def Occurs (rows : List Row) (nonempty : Bool) : Prop :=
  ∃ cfg ns s past, Run cfg ns s past ∧ observe s = rows ∧ (nonempty = true → s.nodes ≠ [])

private theorem alone {s : Model.State} {r : Row} (yes : Supports s r)
    (only : ∀ q, Supports s q → q = r) : observe s = [r] := by
  have eq (q : Row) : possible s q = decide (q = r) := Bool.eq_iff_iff.mpr (by
    rw [possible_iff, decide_eq_true_eq]
    exact ⟨only q, fun h => h ▸ yes⟩)
  rcases r with ⟨z, b⟩
  cases z <;> cases b <;> simp [observe, StateCoverage.table, eq]

private theorem noZero_witness : Occurs [noZero] true := by
  obtain ⟨cfg, ns, s, past, run, key, nonempty⟩ :=
    (StateCoverage.exact noZero).2.mp (by decide)
  have yes : Supports s noZero := ⟨cfg, ns, past, run, key⟩
  refine ⟨cfg, ns, s, past, run, alone yes ?_, nonempty⟩
  intro q hq
  have z := same_zero hq yes
  obtain ⟨c, n, p, run', key'⟩ := hq
  have mem := (StateCoverage.exact q).2.mpr ⟨c, n, s, p, run', key', nonempty⟩
  rcases q with ⟨a, b⟩; cases a <;> cases b <;> simp_all [StateCoverage.activeTable]

private theorem backed_of_positive {cfg ns s past} (run : Run cfg ns s past)
    (pos : s.nodes.any (fun n => n.2.commitIndex != 0) = true) : (read cfg s past).2 = true := by
  open Consensus.Proofs.Safety in
    letI : Proofs.Config.InitialConfiguration := ⟨cfg⟩
    let f := StateCoverage.frame s past
    have inv := @StateCoverage.run_inv ‹_› _ _ _ run
    obtain ⟨⟨n, st⟩, mem, test⟩ := List.any_eq_true.mp pos
    have now : Now f n st := by simpa [Now, f, StateCoverage.frame_current] using mem
    obtain ⟨_, zero | ⟨k, part, committed, _, pref⟩⟩ := (inv.commit_backed n st now).1
    · simp [zero] at test
    · exact (@StateCoverage.read_iff ‹_› s past inv).2.mpr
        ⟨n, st, k, part, by simpa only [StateCoverage.frame_current] using mem, committed, pref⟩

private theorem backed_witness : Occurs [backed] true := by
  open StateCoverage in
    let ns := [0, 1]
    let s := appended ns (by decide +kernel)
    have run : StateCoverage.Run single ns s [initial ns] :=
      .step (.initial (init _ (by decide))) (Option.some_get _).symm
    have yes : Supports s backed := ⟨_, _, _, run, by decide +kernel⟩
    have pos : s.nodes.any (fun n => n.2.commitIndex != 0) = true := by decide +kernel
    refine ⟨_, _, _, _, run, alone yes ?_, fun _ => List.cons_ne_nil _ _⟩
    intro q hq
    have z := same_zero hq yes
    obtain ⟨_, _, _, run', rfl⟩ := hq
    exact Prod.ext z (backed_of_positive run' pos)

private theorem ambiguous_witness : Occurs [unbacked, backed] true := by
  obtain ⟨cfg, ns, s, t, p, q, act, runP, runQ, step, hp, hq⟩ := HistoryCollision.replay_collision
  have bits {past row} (h : FrontierRows.historyLabel cfg s t past = row) :
      read cfg s past = (row.zeroBefore, row.backedBefore) :=
    congrArg (fun r : FrontierRows.Row => (r.zeroBefore, r.backedBefore)) h
  have yes := (mem_observe s backed).mpr ⟨cfg, ns, p, runP, bits hp⟩
  have no := (mem_observe s unbacked).mpr ⟨cfg, ns, q, runQ, bits hq⟩
  have ne := FrontierRows.no_step_without_nodes step
  refine ⟨cfg, ns, s, p, runP, ?_, fun _ => ne⟩
  have mem := complete runP ne
  simp only [activeTable, List.mem_cons, List.not_mem_nil, or_false] at mem
  rcases mem with eq | eq | eq | eq <;> simp_all

private theorem unbacked_witness : Occurs [unbacked] true := by
  obtain ⟨s, ne, ⟨cfg, ns, past, run⟩, only⟩ := NoBackingWitness.exists_unbacked
  exact ⟨cfg, ns, s, past, run, alone ⟨cfg, ns, past, run, only run⟩
    (fun _ ⟨_, _, _, run', eq⟩ => eq.symm.trans (only run')), fun _ => ne⟩

private theorem active_exact (rows : List Row) : rows ∈ activeTable ↔ Occurs rows true := by
  constructor
  · intro mem
    simp only [activeTable, List.mem_cons, List.not_mem_nil, or_false] at mem
    rcases mem with rfl | rfl | rfl | rfl
    · exact unbacked_witness
    · exact backed_witness
    · exact noZero_witness
    · exact ambiguous_witness
  · rintro ⟨_, _, _, _, run, rfl, nonempty⟩
    exact complete run (nonempty rfl)

/-- Every snapshot label listed has a witness; no other set of whole state
answers occurs. The first table includes the isolated empty cluster. -/
public theorem exact (rows : List Row) :
    (rows ∈ table ↔ Occurs rows false) ∧ (rows ∈ activeTable ↔ Occurs rows true) := by
  refine ⟨?_, active_exact rows⟩
  constructor
  · intro h
    rcases List.mem_cons.mp h with rfl | mem
    · open StateCoverage in
        have run : StateCoverage.Run single [] (initial []) [] := .initial (init _ (by decide))
        exact ⟨_, _, _, _, run, empty_observe run rfl, by simp⟩
    · obtain ⟨c, n, s, h, run, eq, _⟩ := (active_exact _).mp mem
      exact ⟨c, n, s, h, run, eq, by simp⟩
  · rintro ⟨_, _, s, _, run, rfl, _⟩
    by_cases empty : s.nodes = []
    · rw [empty_observe run empty]; exact List.mem_cons_self
    · exact List.mem_cons_of_mem _ (complete run empty)

end ConsensusCoverage.SnapshotStates
