-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.Symbolic

set_option autoImplicit false

namespace Symbolic.Trace

variable {stateTy : Ty} {State Action Observation : Type}

inductive Instruction (Action Observation : Type) where
  | action (value : Action)
  | observation (value : Observation)

structure Step (stateTy : Ty) where
  enabled : Expr .bool
  successor : Expr stateTy

/-- Each adapter must describe the actual transition, not a projection. -/
structure Semantics (stateTy : Ty) (State Action Observation : Type) where
  decode : Assignment -> Expr stateTy -> State
  within : State -> Prop
  enabled : Assignment -> State -> Action -> Prop
  next : Assignment -> State -> Action -> State
  observes : Assignment -> State -> Observation -> Prop
  bounds : Expr stateTy -> Expr .bool
  step : Expr stateTy -> Action -> Step stateTy
  observe : Expr stateTy -> Observation -> Expr .bool
  bounds_correct : ∀ ρ state, (bounds state).eval ρ = true ↔ within (decode ρ state)
  enabled_correct : ∀ ρ state action,
    within (decode ρ state) ->
    ((step state action).enabled.eval ρ = true ↔ enabled ρ (decode ρ state) action)
  next_correct : ∀ ρ state action,
    within (decode ρ state) -> enabled ρ (decode ρ state) action ->
    decode ρ (step state action).successor = next ρ (decode ρ state) action
  observe_correct : ∀ ρ state observation,
    within (decode ρ state) ->
    ((observe state observation).eval ρ = true ↔ observes ρ (decode ρ state) observation)

def Follows (semantics : Semantics stateTy State Action Observation)
    (ρ : Assignment) (state : State) : List (Instruction Action Observation) -> Prop
  | [] => semantics.within state
  | .action action :: rest =>
      semantics.within state ∧ semantics.enabled ρ state action ∧
        Follows semantics ρ (semantics.next ρ state action) rest
  | .observation observation :: rest =>
      semantics.within state ∧ semantics.observes ρ state observation ∧
        Follows semantics ρ state rest

private def encodeWithBounds (semantics : Semantics stateTy State Action Observation)
    (nameState : Nat -> Expr stateTy -> Expr stateTy -> Expr stateTy)
    (group : Nat) (state : Expr stateTy) (stateBounds : Expr .bool) :
    List (Instruction Action Observation) -> List (Expr .bool)
  | [] => [stateBounds]
  | .action action :: rest =>
      let result := semantics.step state action
      let successor := nameState group state result.successor
      .and stateBounds result.enabled ::
        encodeWithBounds semantics nameState (group + 1)
          successor (semantics.bounds successor) rest
  | .observation observation :: rest =>
      .and stateBounds (semantics.observe state observation) ::
        encodeWithBounds semantics nameState (group + 1) state stateBounds rest

/-- Instruction indices advance through observations as well as actions.
Bounds are constructed once per state and reused through observations. -/
def encodeWithState (semantics : Semantics stateTy State Action Observation)
    (nameState : Nat -> Expr stateTy -> Expr stateTy -> Expr stateTy)
    (group : Nat) (state : Expr stateTy)
    (trace : List (Instruction Action Observation)) : List (Expr .bool) :=
  encodeWithBounds semantics nameState group state (semantics.bounds state) trace

def encodeWith (semantics : Semantics stateTy State Action Observation)
    (nameState : Nat -> Expr stateTy -> Expr stateTy)
    (group : Nat) (state : Expr stateTy)
    (trace : List (Instruction Action Observation)) : List (Expr .bool) :=
  encodeWithState semantics (fun owner _ after => nameState owner after) group state trace

@[simp] theorem encodeWithState_nil
    (semantics : Semantics stateTy State Action Observation)
    (nameState : Nat -> Expr stateTy -> Expr stateTy -> Expr stateTy)
    (group : Nat) (state : Expr stateTy) :
    encodeWithState semantics nameState group state [] = [semantics.bounds state] := rfl

@[simp] theorem encodeWithState_action
    (semantics : Semantics stateTy State Action Observation)
    (nameState : Nat -> Expr stateTy -> Expr stateTy -> Expr stateTy)
    (group : Nat) (state : Expr stateTy) (action : Action)
    (rest : List (Instruction Action Observation)) :
    encodeWithState semantics nameState group state (.action action :: rest) =
      let result := semantics.step state action
      .and (semantics.bounds state) result.enabled ::
        encodeWithState semantics nameState (group + 1)
          (nameState group state result.successor) rest := rfl

@[simp] theorem encodeWithState_observation
    (semantics : Semantics stateTy State Action Observation)
    (nameState : Nat -> Expr stateTy -> Expr stateTy -> Expr stateTy)
    (group : Nat) (state : Expr stateTy) (observation : Observation)
    (rest : List (Instruction Action Observation)) :
    encodeWithState semantics nameState group state (.observation observation :: rest) =
      .and (semantics.bounds state) (semantics.observe state observation) ::
        encodeWithState semantics nameState (group + 1) state rest := rfl

@[simp] theorem encodeWith_nil (semantics : Semantics stateTy State Action Observation)
    (nameState : Nat -> Expr stateTy -> Expr stateTy) (group : Nat) (state : Expr stateTy) :
    encodeWith semantics nameState group state [] = [semantics.bounds state] := rfl

@[simp] theorem encodeWith_action (semantics : Semantics stateTy State Action Observation)
    (nameState : Nat -> Expr stateTy -> Expr stateTy) (group : Nat) (state : Expr stateTy)
    (action : Action) (rest : List (Instruction Action Observation)) :
    encodeWith semantics nameState group state (.action action :: rest) =
      let result := semantics.step state action
      .and (semantics.bounds state) result.enabled ::
        encodeWith semantics nameState (group + 1)
          (nameState group result.successor) rest := rfl

@[simp] theorem encodeWith_observation
    (semantics : Semantics stateTy State Action Observation)
    (nameState : Nat -> Expr stateTy -> Expr stateTy) (group : Nat) (state : Expr stateTy)
    (observation : Observation) (rest : List (Instruction Action Observation)) :
    encodeWith semantics nameState group state (.observation observation :: rest) =
      .and (semantics.bounds state) (semantics.observe state observation) ::
        encodeWith semantics nameState (group + 1) state rest := rfl

/-- The list preserves instruction groups, with a separate final-bounds group. -/
def encode (semantics : Semantics stateTy State Action Observation)
    (state : Expr stateTy) (trace : List (Instruction Action Observation)) :
    List (Expr .bool) :=
  encodeWith semantics (fun _ value => value) 0 state trace

def Holds (ρ : Assignment) (groups : List (Expr .bool)) : Prop :=
  ∀ expression ∈ groups, expression.eval ρ = true

@[simp] theorem holds_nil (ρ : Assignment) : Holds ρ [] := by
  simp [Holds]

@[simp] theorem holds_cons (ρ : Assignment) (head : Expr .bool)
    (tail : List (Expr .bool)) :
    Holds ρ (head :: tail) ↔ head.eval ρ = true ∧ Holds ρ tail := by
  simp [Holds]

theorem encodeWithState_correct (semantics : Semantics stateTy State Action Observation)
    (nameState : Nat -> Expr stateTy -> Expr stateTy -> Expr stateTy)
    (nameState_correct : ∀ ρ group before after,
      semantics.decode ρ (nameState group before after) = semantics.decode ρ after)
    (ρ : Assignment) (group : Nat) (state : Expr stateTy)
    (trace : List (Instruction Action Observation)) :
    Holds ρ (encodeWithState semantics nameState group state trace) ↔
      Follows semantics ρ (semantics.decode ρ state) trace := by
  induction trace generalizing group state with
  | nil => simp [Follows, semantics.bounds_correct]
  | cons instruction rest inductionHypothesis =>
      by_cases bounded : semantics.within (semantics.decode ρ state)
      · cases instruction with
        | action action =>
            by_cases enabled : semantics.enabled ρ (semantics.decode ρ state) action
            · simp [Follows, Expr.eval, semantics.bounds_correct,
                semantics.enabled_correct ρ state action bounded, bounded, enabled,
                inductionHypothesis, nameState_correct,
                semantics.next_correct ρ state action bounded enabled]
            · simp [Follows, Expr.eval, semantics.bounds_correct,
                semantics.enabled_correct ρ state action bounded, bounded, enabled]
        | observation observation =>
            simp [Follows, Expr.eval, semantics.bounds_correct, bounded,
              semantics.observe_correct ρ state observation bounded, inductionHypothesis]
      · cases instruction <;>
          simp [Follows, Expr.eval, semantics.bounds_correct, bounded]

theorem encodeWith_correct (semantics : Semantics stateTy State Action Observation)
    (nameState : Nat -> Expr stateTy -> Expr stateTy)
    (nameState_correct : ∀ ρ group state,
      semantics.decode ρ (nameState group state) = semantics.decode ρ state)
    (ρ : Assignment) (group : Nat) (state : Expr stateTy)
    (trace : List (Instruction Action Observation)) :
    Holds ρ (encodeWith semantics nameState group state trace) ↔
      Follows semantics ρ (semantics.decode ρ state) trace :=
  encodeWithState_correct semantics (fun owner _ after => nameState owner after)
    (fun assignment owner _ after => nameState_correct assignment owner after)
    ρ group state trace

theorem encode_correct (semantics : Semantics stateTy State Action Observation)
    (ρ : Assignment) (state : Expr stateTy)
    (trace : List (Instruction Action Observation)) :
    Holds ρ (encode semantics state trace) ↔
      Follows semantics ρ (semantics.decode ρ state) trace :=
  encodeWith_correct semantics (fun _ value => value) (by intros; rfl) ρ 0 state trace

theorem encodeWithState_group_count (semantics : Semantics stateTy State Action Observation)
    (nameState : Nat -> Expr stateTy -> Expr stateTy -> Expr stateTy)
    (group : Nat) (state : Expr stateTy) (trace : List (Instruction Action Observation)) :
    (encodeWithState semantics nameState group state trace).length = trace.length + 1 := by
  induction trace generalizing group state with
  | nil => rfl
  | cons instruction rest inductionHypothesis =>
      cases instruction <;> simp [inductionHypothesis, Nat.add_assoc]

theorem encodeWith_group_count (semantics : Semantics stateTy State Action Observation)
    (nameState : Nat -> Expr stateTy -> Expr stateTy)
    (group : Nat) (state : Expr stateTy) (trace : List (Instruction Action Observation)) :
    (encodeWith semantics nameState group state trace).length = trace.length + 1 :=
  encodeWithState_group_count semantics (fun owner _ after => nameState owner after)
    group state trace

theorem encode_group_count (semantics : Semantics stateTy State Action Observation)
    (state : Expr stateTy) (trace : List (Instruction Action Observation)) :
    (encode semantics state trace).length = trace.length + 1 :=
  encodeWith_group_count semantics (fun _ value => value) 0 state trace

end Symbolic.Trace
