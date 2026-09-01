-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

set_option autoImplicit false

namespace TraceValidation

/-- One ordered trace instruction. Observations do not advance model state. -/
inductive Instruction (Action Observation : Type) where
  | action (value : Action)
  | observation (value : Observation)

def follows
    {State Action Observation : Type}
    (enabled : State -> Action -> Prop)
    (next : State -> Action -> State)
    (observes : Observation -> State -> Prop)
    (state : State) :
    List (Instruction Action Observation) -> Prop
  | [] => True
  | .observation observation :: rest =>
      observes observation state /\
        follows enabled next observes state rest
  | .action action :: rest =>
      enabled state action /\
        follows enabled next observes (next state action) rest

def Satisfiable
    {State Action Observation : Type}
    (validEntryState : State -> Prop)
    (enabled : State -> Action -> Prop)
    (next : State -> Action -> State)
    (observes : Observation -> State -> Prop)
    (trace : List (Instruction Action Observation)) : Prop :=
  Exists fun entry =>
    validEntryState entry /\
      follows enabled next observes entry trace

end TraceValidation
