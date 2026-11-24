module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.CensusLed
import all ConsensusCoverage.CensusObserved
import all ConsensusCoverage.ExplorerGhost
import all ConsensusCoverage.GuardedDomain

namespace ConsensusCoverage.CensusCanonical

open Consensus Consensus.Model Consensus.Model.Node ExplorerGhost CensusObserved

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private theorem fold_project {α β γ : Type} (xs : List α) (a : β) (step : α → β → Id (ForInStep β))
    (project : β → γ) (f : γ → α → γ)
    (keeps : ∀ x b, ∃ c, step x b = .yield c ∧ project c = f (project b) x) :
    project (forIn xs a step) = xs.foldl f (project a) := by
  induction xs generalizing a with
  | nil => rfl
  | cons x xs ih =>
    obtain ⟨c, eq, val⟩ := keeps x a
    rw [List.forIn_cons, eq, List.foldl_cons, ← val]
    exact ih c

private abbrev Keys := List (Nat × List Entry)

private noncomputable def update (g : Ghost) (b : NodeID) (ks : Keys) (p : NodeID × NodeState) : Keys :=
  if p.2.role != .candidate && g.led b p.1 p.2.currentTerm then union ks [(p.2.currentTerm, p.2.log)] else ks

private theorem log_canonical (g : Ghost) (b : NodeID) (s : Model.State) :
    (logDelta g b s).1.canonical = s.nodes.foldl (update g b) g.canonical := by
  unfold logDelta
  change Prod.fst (forIn s.nodes (g.canonical, g.committed, false, false) _ : Id (Keys × Keys × Bool × Bool)) = _
  apply fold_project
  rintro ⟨n, st⟩ ⟨ks, rest⟩
  by_cases led : (st.role != .candidate && g.led b n st.currentTerm) = true
  <;> simp only [led, ite_eq_left, update]
  <;> exact ⟨_, rfl, rfl⟩

private theorem mem_fold (g : Ghost) (b k : Nat) (l : List Entry) (ps : List (NodeID × NodeState))
    (ks : Keys) :
    (k, l) ∈ ps.foldl (update g b) ks ↔ (k, l) ∈ ks ∨
      ∃ n st, (n, st) ∈ ps ∧ st.role ≠ .candidate ∧ st.currentTerm = k ∧ st.log = l ∧ g.led b n k = true := by
  induction ps generalizing ks with
  | nil => simp
  | cons p ps ih =>
    rcases p with ⟨n, st⟩
    rw [List.foldl_cons, ih]
    unfold update
    by_cases yes : (st.role != .candidate && g.led b n st.currentTerm) = true
    <;> simp only [yes, ite_eq_left, mem_union, Prod.mk.injEq, List.mem_cons]
    <;> grind

public def CanonicalHistory (b : NodeID) (g : Ghost) (h : List Model.State) : Prop :=
  ∀ k l, (k, l) ∈ g.canonical ↔ GuardedDomain.canonAt b k l h = true

private theorem add_state (b : NodeID) (g : Ghost) (s : Model.State) (h : List Model.State)
    (old : CanonicalHistory b g h) (elect : ElectionHistory g (s :: h)) :
    CanonicalHistory b (logDelta g b s).1 (s :: h) := by
  intro k l
  rw [log_canonical, mem_fold, old, GuardedDomain.canonAt]
  simp only [Bool.or_eq_true, List.any_eq_true, Prod.exists, Bool.and_eq_true, decide_eq_true_eq,
    CensusLed.led_eq elect]
  grind

public theorem canonical_start (b : NodeID) (s : Model.State) : CanonicalHistory b (start b s) [s] := by
  apply add_state
  · intro k l; simp [GuardedDomain.canonAt]
  · intro n k l i
    change _ ∈ ([] : List (NodeID × Nat × List Entry × Nat)) ↔ false = true
    simp

/-- Canonical pairs, unlike mere log/term marginals, remember that a
non-candidate owned the log at a time when it had already led. -/
public theorem canonical_read {cfg : FullProfile.Configuration} {g : Ghost} {s t : Model.State}
    {act : Model.Action} {edge : Edge} {h : List Model.State}
    (run : ExplorerGhost.read cfg g s t act = some edge)
    (old : CanonicalHistory (cfg.min?.getD 0) g (s :: h))
    (elect : ElectionHistory edge.ghost (t :: s :: h)) :
    CanonicalHistory (cfg.min?.getD 0) edge.ghost (t :: s :: h) := by
  unfold ExplorerGhost.read at run
  simp only [Option.bind_eq_bind, Option.bind_eq_some_iff] at run
  obtain ⟨view, hv, _, _, _, _, _, _, eq⟩ := run
  cases eq
  have boot : view.bootstrap = cfg.min?.getD 0 := by
    unfold GuardedDomain.ofAction at hv
    simp only [Option.bind_eq_bind, Option.bind_eq_some_iff] at hv
    obtain ⟨_, _, _, _, heq⟩ := hv
    cases heq
    rfl
  simp only [boot] at elect ⊢
  exact add_state _ _ _ _ old elect

end ConsensusCoverage.CensusCanonical
