-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Model
import Shared.TraceSpec

set_option autoImplicit false

namespace CCFRaft.MachineGenerated

variable {Node TxId Observation : Type}
variable [DecidableEq Node] [DecidableEq TxId]
variable [Bootstrap Node]

/-- Typed symbolic form of every current `CCFRaft.Action` constructor. -/
inductive LoweredAction (Node TxId : Type) where
  | clientRequest (node : Node) (txId : TxId)
  | changeConfiguration (source : Node) (configuration : Finset Node)
  | signCommittableMessages (node : Node)
  | appendEntries (source destination : Node) (batchEnd : Nat)
  | receive (source destination : Node)
  | advanceCommitIndex (node : Node)
  | timeout (node : Node)
  | requestVote (source destination : Node)
  | updateTerm (source destination : Node)
  | becomeLeader (node : Node)

def LoweredAction.toAction :
    LoweredAction Node TxId -> Action Node TxId
  | .clientRequest node txId => .clientRequest node txId
  | .changeConfiguration source configuration =>
      .changeConfiguration source configuration
  | .signCommittableMessages node => .signCommittableMessages node
  | .appendEntries source destination batchEnd =>
      .appendEntries source destination batchEnd
  | .receive source destination => .receive source destination
  | .advanceCommitIndex node => .advanceCommitIndex node
  | .timeout node => .timeout node
  | .requestVote source destination => .requestVote source destination
  | .updateTerm source destination => .updateTerm source destination
  | .becomeLeader node => .becomeLeader node

def lowerAction : Action Node TxId -> LoweredAction Node TxId
  | .clientRequest node txId => .clientRequest node txId
  | .changeConfiguration source configuration =>
      .changeConfiguration source configuration
  | .signCommittableMessages node => .signCommittableMessages node
  | .appendEntries source destination batchEnd =>
      .appendEntries source destination batchEnd
  | .receive source destination => .receive source destination
  | .advanceCommitIndex node => .advanceCommitIndex node
  | .timeout node => .timeout node
  | .requestVote source destination => .requestVote source destination
  | .updateTerm source destination => .updateTerm source destination
  | .becomeLeader node => .becomeLeader node

structure LoweredStep (Node TxId Observation : Type) where
  action : LoweredAction Node TxId
  observationsAfter : List Observation

structure Formula (Node TxId Observation : Type) where
  observationsAtEntry : List Observation
  steps : List (LoweredStep Node TxId Observation)

def lowerStep
    (step : TraceValidation.Step (Action Node TxId) Observation) :
    LoweredStep Node TxId Observation where
  action := lowerAction step.action
  observationsAfter := step.observationsAfter

def lowerTrace
    (trace : TraceValidation.ReducedTrace (Action Node TxId) Observation) :
    Except String (Formula Node TxId Observation) :=
  .ok
    { observationsAtEntry := trace.observationsAtEntry
      steps := trace.steps.map lowerStep }

def ActionConstraint
    (before after : State Node TxId)
    (action : LoweredAction Node TxId) : Prop :=
  Enabled before action.toAction /\
    after = next before action.toAction

def formulaFollows
    (observes : Observation -> State Node TxId -> Prop)
    (state : State Node TxId) :
    List (LoweredStep Node TxId Observation) -> Prop
  | [] => True
  | step :: rest =>
      Exists fun after =>
        ActionConstraint state after step.action /\
          TraceValidation.observationsHold
            observes after step.observationsAfter /\
          formulaFollows observes after rest

def Satisfiable
    (validEntryState : State Node TxId -> Prop)
    (observes : Observation -> State Node TxId -> Prop)
    (formula : Formula Node TxId Observation) : Prop :=
  Exists fun entry =>
    validEntryState entry /\
      TraceValidation.observationsHold
        observes entry formula.observationsAtEntry /\
      formulaFollows observes entry formula.steps

end CCFRaft.MachineGenerated
