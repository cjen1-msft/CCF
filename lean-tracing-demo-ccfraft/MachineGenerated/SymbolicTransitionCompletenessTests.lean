-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionCompleteness

set_option autoImplicit false

namespace CCFRaft.SymbolicTransitionCompletenessTests

open Symbolic SymbolicModel SymbolicTransition BoundedSymbolicTrace

local instance : NeZero NODE_COUNT := ⟨by decide⟩

def externalTransaction : Expr .nat := .named 0 3 (.add (.unknown 8) (.nat 1))

example : inputsAtOrAfter 8 externalTransaction = true := by decide
example : inputsAtOrAfter 9 externalTransaction = false := by decide
example : inputsAtOrAfter 8 (Expr.named 0 0 (.unknown 7)) = false := by decide
example : inputsAtOrAfter 8 (Expr.ite (.bool false) (.unknown 0) (.unknown 8)) = false := by decide

def mixedTrace : List Instruction :=
  [ .observation (.allocated 14 false),
    .action (.receive 0 14),
    .action (.clientRequest 0 externalTransaction),
    .observation (.submitted (.unknown 9) true),
    .action (.changeConfiguration 0 {0, 7, 14}),
    .observation (.currentTerm 7 2) ]

example : traceInputsAtOrAfter 8 mixedTrace = true := by decide
example : traceInputsAtOrAfter 9 mixedTrace = false := by decide
example : traceInputsAtOrAfter 8 [.observation (.submitted (.unknown 7) false)] = false := by decide

def composite : Expr .nat :=
  .length (.set (.take (.nat 2) (.cons (.unknown 8) (.cons (.unknown 9) .nil)))
    (.nat 0) (.unknown 10))

example : inputsAtOrAfter 8 composite = true := by decide
example : inputsAtOrAfter 9 composite = false := by decide

example (ρ σ : Assignment) (same : ∀ index, 8 ≤ index → ρ index = σ index) :
    composite.eval ρ = composite.eval σ :=
  eval_inputsAtOrAfter 8 composite ρ σ same (by decide)

example (bounds : BoundedState.Bounds) (state : State Node Nat)
    (ρ σ : Assignment) (same : ∀ index, 8 ≤ index → ρ index = σ index) :
    Follows bounds ρ state mixedTrace ↔ Follows bounds σ state mixedTrace :=
  follows_inputsAtOrAfter bounds 8 mixedTrace state ρ σ same (by decide)

example (bounds : BoundedState.Bounds) (start : Nat) (positive : 0 < start)
    (state : State Node Nat) (within : BoundedState.WithinBounds bounds state) (base : Assignment) :
    ∃ ρ : Assignment,
      evalEntry bounds ρ (freshEntry bounds start) = state ∧
      ρ (start - 1) = base (start - 1) ∧
      ρ (start + entryWidth bounds) = base (start + entryWidth bounds) := by
  obtain ⟨ρ, decoded, outside⟩ := freshEntry_complete_preserving bounds start state within base
  exact ⟨ρ, decoded, outside _ (Or.inl (by omega)), outside _ (Or.inr (by omega))⟩

example (bounds : BoundedState.Bounds) (receive : ReceiveAdapter bounds)
    (state : State Node Nat) (within : BoundedState.WithinBounds bounds state) (base : Assignment) :
    ∃ ρ : Assignment, evalEntry bounds ρ (freshEntry bounds) = state ∧
      Trace.Holds ρ (SymbolicTraceEncoding.encode bounds (adapter bounds receive) 0 (freshEntry bounds) []) := by
  obtain ⟨ρ, _, decoded, accepted⟩ := encode_complete_model bounds receive 0 [] base state
    (by rfl) (by intro index below; omega) within
  exact ⟨ρ, decoded, accepted⟩

example (bounds : BoundedState.Bounds) (receive : ReceiveAdapter bounds)
    (base : Assignment) (unknownCount : Nat)
    (invalid : ¬TransactionDomains bounds unknownCount base) :
    ¬∃ ρ : Assignment,
      (∀ index, entryWidth bounds ≤ index → ρ index = base index) ∧
      Trace.Holds ρ (SymbolicTraceEncoding.encode bounds (adapter bounds receive)
        unknownCount (freshEntry bounds) []) := by
  rw [encode_satisfiable_iff bounds receive unknownCount [] base (by rfl)]
  exact fun accepted => invalid accepted.1

run_cmd do
  for name in [
      ``eval_inputsAtOrAfter, ``evaluateAction_inputsAtOrAfter, ``observation_inputsAtOrAfter,
      ``follows_inputsAtOrAfter, ``freshEntry_complete_preserving,
      ``encode_complete_model, ``encode_satisfiable_iff] do
    for axiomName in ← Lean.collectAxioms name do
      unless axiomName == ``propext || axiomName == ``Classical.choice ||
          axiomName == ``Quot.sound do
        throwError "{name} depends on unapproved axiom {axiomName}"

end CCFRaft.SymbolicTransitionCompletenessTests
