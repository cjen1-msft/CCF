-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

set_option autoImplicit false

/-!
# Executable transition systems

The proof relation and compiled execution share the same `Enabled` predicate and
`next` function. Nondeterministic choices are explicit values of `Action`.
-/

namespace CCFRaft

/-- A transition system whose guards and state updates can also be executed. -/
structure ExecutableTransitionSystem where
  State : Type
  Action : Type
  initial : State
  Enabled : State -> Action -> Prop
  enabledDecidable : forall state action, Decidable (Enabled state action)
  next : State -> Action -> State

namespace ExecutableTransitionSystem

/-- Use the decision procedure stored in the transition system for its guards. -/
instance (system : ExecutableTransitionSystem) :
    forall state action, Decidable (system.Enabled state action) :=
  system.enabledDecidable

/-- Execute an action when enabled, returning `none` when its guard is false. -/
def applyAction
    (system : ExecutableTransitionSystem)
    (state : system.State)
    (action : system.Action) :
    Option system.State :=
  if system.Enabled state action then
    some (system.next state action)
  else
    none

/-- Two states are related when an enabled action transforms one into the other. -/
def Step
    (system : ExecutableTransitionSystem)
    (before after : system.State) : Prop :=
  Exists fun action =>
    system.Enabled before action /\
      after = system.next before action

/-- States obtainable from the initial state by finitely many enabled actions. -/
inductive Reachable
    (system : ExecutableTransitionSystem) :
    system.State -> Prop where
  | initial : Reachable system system.initial
  | step
      {state : system.State}
      (reachable : Reachable system state)
      {action : system.Action}
      (enabled : system.Enabled state action) :
      Reachable system (system.next state action)

/-- Lift an initial-state and one-step preservation proof to all reachable states. -/
theorem reachableInvariant
    (system : ExecutableTransitionSystem)
    {Invariant : system.State -> Prop}
    (initial : Invariant system.initial)
    (preserved :
      forall state action,
        Invariant state ->
          system.Enabled state action ->
            Invariant (system.next state action))
    {state : system.State}
    (reachable : system.Reachable state) :
    Invariant state := by
  induction reachable with
  | initial => exact initial
  | step reachable enabled invariant =>
      exact preserved _ _ invariant enabled

/-- Connect a finite simulator choice type to a transition system's actions. -/
structure SimulationAdapter
    (system : ExecutableTransitionSystem) where
  Choice : Type
  materialize : system.State -> Choice -> Option system.Action
  complete :
    forall state action,
      system.Enabled state action ->
        Exists fun choice =>
          materialize state choice = some action

namespace SimulationAdapter

/-- Materialize one simulator choice and execute the resulting model action. -/
def simulateStep
    {system : ExecutableTransitionSystem}
    (adapter : SimulationAdapter system)
    (state : system.State)
    (choice : adapter.Choice) :
    Option system.State := do
  let action <- adapter.materialize state choice
  system.applyAction state action

end SimulationAdapter

end ExecutableTransitionSystem

end CCFRaft
