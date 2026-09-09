-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import BoundedSymbolicTrace
import MachineGenerated.SymbolicBounds
import MachineGenerated.SymbolicTraceObservation

set_option autoImplicit false

namespace CCFRaft.SymbolicTraceEncoding

open Symbolic SymbolicModel BoundedSymbolicTrace

/-- Reject unbounded successors before representing them in the finite codec. -/
structure Adapter (bounds : BoundedState.Bounds) where
  step : Expr (stateCodec bounds.transactionCount).ty -> SymbolicAction ->
    Trace.Step (stateCodec bounds.transactionCount).ty
  accepted_correct : ∀ assignment entry action,
    BoundedState.WithinBounds bounds (evalEntry bounds assignment entry) ->
      ((step entry action).enabled.eval assignment = true ↔
        Enabled (evalEntry bounds assignment entry) (evaluateAction assignment action) ∧
          BoundedState.WithinBounds bounds
            (next (evalEntry bounds assignment entry) (evaluateAction assignment action)))
  next_correct : ∀ assignment entry action,
    BoundedState.WithinBounds bounds (evalEntry bounds assignment entry) ->
    Enabled (evalEntry bounds assignment entry) (evaluateAction assignment action) ->
    BoundedState.WithinBounds bounds
      (next (evalEntry bounds assignment entry) (evaluateAction assignment action)) ->
      evalEntry bounds assignment (step entry action).successor =
        next (evalEntry bounds assignment entry) (evaluateAction assignment action)

def semantics (bounds : BoundedState.Bounds) (adapter : Adapter bounds) :
    Trace.Semantics (stateCodec bounds.transactionCount).ty
      (State Node Nat) SymbolicAction SymbolicTraceObservation.Observation where
  decode := evalEntry bounds
  within := BoundedState.WithinBounds bounds
  enabled := fun assignment state action =>
    Enabled state (evaluateAction assignment action) ∧
      BoundedState.WithinBounds bounds (next state (evaluateAction assignment action))
  next := fun assignment state action => next state (evaluateAction assignment action)
  observes := fun assignment state observation => observation.Holds bounds assignment state
  bounds := stateWithin bounds
  step := adapter.step
  observe := SymbolicTraceObservation.expression bounds
  bounds_correct := stateWithin_correct bounds
  enabled_correct := adapter.accepted_correct
  next_correct := fun assignment entry action within accepted =>
    adapter.next_correct assignment entry action within accepted.1 accepted.2
  observe_correct := SymbolicTraceObservation.expression_correct bounds

def encode (bounds : BoundedState.Bounds) (adapter : Adapter bounds)
    (unknownCount : Nat) (entry : Expr (stateCodec bounds.transactionCount).ty)
    (instructions : List Instruction) : List (Expr .bool) :=
  transactionDomains bounds unknownCount ::
    Trace.encode (semantics bounds adapter) entry instructions

theorem follows_within (bounds : BoundedState.Bounds) (assignment : Assignment)
    (state : State Node Nat) (instructions : List Instruction)
    (follows : Follows bounds assignment state instructions) :
    BoundedState.WithinBounds bounds state := by
  cases instructions with
  | nil => exact follows
  | cons instruction rest => cases instruction <;> exact follows.1

theorem follows_correct (bounds : BoundedState.Bounds) (adapter : Adapter bounds)
    (assignment : Assignment) (state : State Node Nat) (instructions : List Instruction) :
    Trace.Follows (semantics bounds adapter) assignment state instructions ↔
      Follows bounds assignment state instructions := by
  induction instructions generalizing state with
  | nil => rfl
  | cons instruction rest inductionHypothesis =>
      cases instruction with
      | action action =>
          simp only [Trace.Follows, Follows, inductionHypothesis]
          change
            (BoundedState.WithinBounds bounds state ∧
              (Enabled state (evaluateAction assignment action) ∧
                BoundedState.WithinBounds bounds (next state (evaluateAction assignment action))) ∧
              Follows bounds assignment (next state (evaluateAction assignment action)) rest) ↔ _
          constructor
          · rintro ⟨within, ⟨enabled, _⟩, follows⟩
            exact ⟨within, enabled, follows⟩
          · rintro ⟨within, enabled, follows⟩
            exact ⟨within, ⟨enabled, follows_within bounds assignment _ rest follows⟩, follows⟩
      | observation observation =>
          simp only [Trace.Follows, Follows, inductionHypothesis]
          rfl

theorem encode_holds_correct (bounds : BoundedState.Bounds) (adapter : Adapter bounds)
    (unknownCount : Nat) (entry : Expr (stateCodec bounds.transactionCount).ty)
    (instructions : List Instruction) (assignment : Assignment) :
    Trace.Holds assignment (encode bounds adapter unknownCount entry instructions) ↔
      TransactionDomains bounds unknownCount assignment ∧
        Follows bounds assignment (evalEntry bounds assignment entry) instructions := by
  rw [encode, Trace.holds_cons, transactionDomains_correct, Trace.encode_correct,
    follows_correct]
  rfl

theorem verifiedEncoder (adapters : ∀ bounds, Adapter bounds) :
    VerifiedEncoder (fun bounds => encode bounds (adapters bounds)) :=
  fun bounds unknownCount entry instructions assignment =>
    encode_holds_correct bounds (adapters bounds) unknownCount entry instructions assignment

theorem group_count (bounds : BoundedState.Bounds) (adapter : Adapter bounds)
    (unknownCount : Nat) (entry : Expr (stateCodec bounds.transactionCount).ty)
    (instructions : List Instruction) :
    (encode bounds adapter unknownCount entry instructions).length = instructions.length + 2 := by
  simp [encode, Trace.encode_group_count, Nat.add_assoc]

end CCFRaft.SymbolicTraceEncoding
