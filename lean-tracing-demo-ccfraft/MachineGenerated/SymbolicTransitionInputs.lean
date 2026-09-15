-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import BoundedSymbolicTrace

set_option autoImplicit false

namespace CCFRaft.SymbolicTransition

open Symbolic SymbolicModel BoundedSymbolicTrace

def inputsAtOrAfter (lower : Nat) : {s : Ty} → Expr s → Bool
  | _, .nat _ | _, .bool _ | _, .unit | _, .nil => true
  | _, .unknown index => decide (lower ≤ index)
  | _, .named _ _ value => inputsAtOrAfter lower value
  | _, .add a b | _, .sub a b | _, .lt a b | _, .eq a b | _, .and a b
  | _, .pair a b | _, .leftD a b | _, .rightD a b | _, .cons a b
  | _, .append a b | _, .take a b | _, .drop a b | _, .get? a b
  | _, .contains a b => inputsAtOrAfter lower a && inputsAtOrAfter lower b
  | _, .not value | _, .fst value | _, .snd value | _, .inl value
  | _, .inr value | _, .isLeft value | _, .length value => inputsAtOrAfter lower value
  | _, .ite a b c | _, .set a b c =>
      inputsAtOrAfter lower a && inputsAtOrAfter lower b && inputsAtOrAfter lower c

theorem eval_inputsAtOrAfter {s : Ty} (lower : Nat) (expression : Expr s)
    (ρ σ : Assignment) (same : ∀ index, lower ≤ index → ρ index = σ index)
    (inScope : inputsAtOrAfter lower expression = true) :
    expression.eval ρ = expression.eval σ := by
  induction expression <;> simp_all [inputsAtOrAfter, Expr.eval]

def actionInputsAtOrAfter (lower : Nat) : SymbolicAction → Bool
  | .clientRequest _ transaction => inputsAtOrAfter lower transaction
  | _ => true

theorem evaluateAction_inputsAtOrAfter (lower : Nat) (action : SymbolicAction)
    (ρ σ : Assignment) (same : ∀ index, lower ≤ index → ρ index = σ index)
    (inScope : actionInputsAtOrAfter lower action = true) :
    evaluateAction ρ action = evaluateAction σ action := by
  cases action <;> simp_all [actionInputsAtOrAfter, evaluateAction, eval_inputsAtOrAfter lower _ ρ σ same]

def observationInputsAtOrAfter (lower : Nat) : SymbolicTraceObservation.Observation → Bool
  | .submitted transaction _ => inputsAtOrAfter lower transaction
  | _ => true

theorem observation_inputsAtOrAfter (bounds : BoundedState.Bounds) (lower : Nat)
    (observation : SymbolicTraceObservation.Observation) (state : State Node Nat)
    (ρ σ : Assignment) (same : ∀ index, lower ≤ index → ρ index = σ index)
    (inScope : observationInputsAtOrAfter lower observation = true) :
    observation.Holds bounds ρ state ↔ observation.Holds bounds σ state := by
  cases observation <;>
    simp_all [observationInputsAtOrAfter, SymbolicTraceObservation.Observation.Holds,
      eval_inputsAtOrAfter lower _ ρ σ same]

def instructionInputsAtOrAfter (lower : Nat) : Instruction → Bool
  | .action action => actionInputsAtOrAfter lower action
  | .observation observation => observationInputsAtOrAfter lower observation

def traceInputsAtOrAfter (lower : Nat) (instructions : List Instruction) : Bool :=
  instructions.all (instructionInputsAtOrAfter lower)

theorem follows_inputsAtOrAfter (bounds : BoundedState.Bounds) (lower : Nat)
    (instructions : List Instruction) (state : State Node Nat)
    (ρ σ : Assignment) (same : ∀ index, lower ≤ index → ρ index = σ index)
    (inScope : traceInputsAtOrAfter lower instructions = true) :
    Follows bounds ρ state instructions ↔ Follows bounds σ state instructions := by
  induction instructions generalizing state with
  | nil => rfl
  | cons instruction rest ih =>
      have parts : instructionInputsAtOrAfter lower instruction = true ∧
          traceInputsAtOrAfter lower rest = true := by
        simpa [traceInputsAtOrAfter] using inScope
      cases instruction with
      | action action =>
          have equal := evaluateAction_inputsAtOrAfter lower action ρ σ same parts.1
          simp only [Follows, equal, ih _ parts.2]
      | observation observation =>
          have equal := observation_inputsAtOrAfter bounds lower observation state ρ σ same parts.1
          simp only [Follows, equal, ih _ parts.2]

end CCFRaft.SymbolicTransition
