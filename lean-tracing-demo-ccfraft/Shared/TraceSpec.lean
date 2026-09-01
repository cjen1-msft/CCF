-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

set_option autoImplicit false

namespace TraceValidation

/-- One model action followed by observations at the resulting boundary. -/
structure Step (Action Observation : Type) where
  action : Action
  observationsAfter : List Observation

/-- A reduced trace with observations before and after model actions. -/
structure ReducedTrace (Action Observation : Type) where
  observationsAtEntry : List Observation
  steps : List (Step Action Observation)

def observationsHold
    {State Observation : Type}
    (observes : Observation -> State -> Prop)
    (state : State) :
    List Observation -> Prop
  | [] => True
  | observation :: rest =>
      observes observation state /\
        observationsHold observes state rest

def follows
    {State Action Observation : Type}
    (enabled : State -> Action -> Prop)
    (next : State -> Action -> State)
    (observes : Observation -> State -> Prop)
    (state : State) :
    List (Step Action Observation) -> Prop
  | [] => True
  | step :: rest =>
      enabled state step.action /\
        observationsHold
          observes
          (next state step.action)
          step.observationsAfter /\
        follows enabled next observes (next state step.action) rest

def Satisfiable
    {State Action Observation : Type}
    (validEntryState : State -> Prop)
    (enabled : State -> Action -> Prop)
    (next : State -> Action -> State)
    (observes : Observation -> State -> Prop)
    (trace : ReducedTrace Action Observation) : Prop :=
  Exists fun entry =>
    validEntryState entry /\
      observationsHold observes entry trace.observationsAtEntry /\
      follows enabled next observes entry trace.steps

end TraceValidation
