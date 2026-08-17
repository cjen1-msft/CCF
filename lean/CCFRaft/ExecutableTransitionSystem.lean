-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

set_option autoImplicit false

/-!
# Executable transition systems

The proof relation and compiled execution share the same `Enabled` predicate and
`next` function. Nondeterministic choices are explicit values of `Action`.
-/

namespace CCFRaft

structure ExecutableTransitionSystem where
  State : Type
  Action : Type
  initial : State
  Enabled : State -> Action -> Prop
  enabledDecidable : forall state action, Decidable (Enabled state action)
  next : State -> Action -> State

namespace ExecutableTransitionSystem

instance (system : ExecutableTransitionSystem) :
    forall state action, Decidable (system.Enabled state action) :=
  system.enabledDecidable

def applyAction
    (system : ExecutableTransitionSystem)
    (state : system.State)
    (action : system.Action) :
    Option system.State :=
  if system.Enabled state action then
    some (system.next state action)
  else
    none

def Step
    (system : ExecutableTransitionSystem)
    (before after : system.State) : Prop :=
  Exists fun action =>
    system.Enabled before action /\
      after = system.next before action

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
