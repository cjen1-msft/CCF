module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.StateCoverage
import all ConsensusCoverage.StateCoverage
import all Consensus.Proofs.SafetyInvariant

/-!
# Complete state-answer vectors and their endpoint transitions
-/

namespace ConsensusCoverage.ProofContexts

open Consensus Consensus.Model Consensus.Model.Node
open StateCoverage (Row Run Holds)

public abbrev Answers := Classes.StateBranch → Bool

/-- In the order of the generated questions, not a subset of chosen probes. -/
@[expose] public def answers (r : Row) : Answers := fun _ => r

public theorem faithful {cfg ns s past} (run : Run cfg ns s past) (b : Classes.StateBranch) :
    answers (StateCoverage.read cfg s past) b = true ↔ Holds cfg s past b :=
  StateCoverage.read_iff run b

private theorem answers_injective : Function.Injective answers :=
  fun _ _ h => congrFun h .committed_logs_comparable_committed_comparable_inl

/-- All state vectors, including the isolated empty cluster. -/
public def allTable : List Answers := StateCoverage.table.map answers
/-- State vectors of nonempty clusters. -/
public def table : List Answers := StateCoverage.activeTable.map answers

public theorem count : allTable.Nodup ∧ allTable.length = 2 ∧ table.Nodup ∧ table.length = 1 :=
  ⟨StateCoverage.counts.1.map answers (fun _ _ h e => h (answers_injective e)), rfl,
    StateCoverage.counts.2.2.1.map answers (fun _ _ h e => h (answers_injective e)), rfl⟩

public def Realized (nonempty : Bool) (p : Answers) : Prop :=
  ∃ cfg ns s past, Run cfg ns s past ∧ (nonempty = true → s.nodes ≠ []) ∧
    ∀ b, p b = true ↔ Holds cfg s past b

private theorem realized_iff (nonempty : Bool) (p : Answers) :
    Realized nonempty p ↔ ∃ r, StateCoverage.Occurs r nonempty ∧ answers r = p := by
  constructor
  · rintro ⟨cfg, ns, s, past, run, non, holds⟩
    exact ⟨_, ⟨cfg, ns, s, past, run, rfl, non⟩,
      funext fun b => Bool.eq_iff_iff.mpr ((faithful run b).trans (holds b).symm)⟩
  · rintro ⟨_, ⟨cfg, ns, s, past, run, rfl, non⟩, rfl⟩
    exact ⟨cfg, ns, s, past, run, non, faithful run⟩

/-- The exact set of reachable complete state-answer vectors. -/
public theorem exact (p : Answers) :
    (p ∈ allTable ↔ Realized false p) ∧ (p ∈ table ↔ Realized true p) := by
  simp only [realized_iff, allTable, table, List.mem_map, ← StateCoverage.exact]
  exact ⟨trivial, trivial⟩

/-- Complete state-answer vectors at the two endpoints of one successful step. -/
public def Transition (pre post : Answers) : Prop :=
  ∃ cfg ns s t past a, Run cfg ns s past ∧ (transitionSystem cfg ns).step s a = some t ∧
    (∀ b, pre b = true ↔ Holds cfg s past b) ∧ (∀ b, post b = true ↔ Holds cfg t (s :: past) b)

public def transitions : List (Answers × Answers) :=
  StateCoverage.transitions.map fun r => (answers r.1, answers r.2)

public theorem transitions_count : transitions.length = 1 := by
  simp [transitions, StateCoverage.transitions]

/-- The exact endpoint table: every step starts and ends with both questions true. -/
public theorem transitions_exact (pre post : Answers) :
    (pre, post) ∈ transitions ↔ Transition pre post := by
  constructor
  · intro mem
    obtain ⟨⟨a, b⟩, inner, eq⟩ := List.mem_map.mp mem
    obtain ⟨rfl, rfl⟩ := Prod.mk.inj eq
    obtain ⟨cfg, ns, s, t, past, act, run, ran, rfl, rfl⟩ :=
      (StateCoverage.transitions_exact a b).mp inner
    exact ⟨cfg, ns, s, t, past, act, run, ran, faithful run, faithful (.step run ran)⟩
  · rintro ⟨cfg, ns, s, t, past, act, run, ran, hpre, hpost⟩
    refine List.mem_map.mpr ⟨(StateCoverage.read cfg s past, StateCoverage.read cfg t (s :: past)),
      (StateCoverage.transitions_exact _ _).mpr ⟨cfg, ns, s, t, past, act, run, ran, rfl, rfl⟩, ?_⟩
    exact Prod.ext
      (funext fun b => Bool.eq_iff_iff.mpr ((faithful run b).trans (hpre b).symm))
      (funext fun b => Bool.eq_iff_iff.mpr ((faithful (.step run ran) b).trans (hpost b).symm))

end ConsensusCoverage.ProofContexts
