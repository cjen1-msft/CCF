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

inductive LoweredInstruction (Node TxId Observation : Type) where
  | action (value : LoweredAction Node TxId)
  | observation (value : Observation)

structure Formula (Node TxId Observation : Type) where
  instructions : List (LoweredInstruction Node TxId Observation)

def lowerInstruction :
    TraceValidation.Instruction (Action Node TxId) Observation ->
      LoweredInstruction Node TxId Observation
  | .action action => .action (lowerAction action)
  | .observation observation => .observation observation

def lowerTrace
    (trace : List (TraceValidation.Instruction (Action Node TxId) Observation)) :
    Except String (Formula Node TxId Observation) :=
  .ok { instructions := trace.map lowerInstruction }

def ActionConstraint
    (before after : State Node TxId)
    (action : LoweredAction Node TxId) : Prop :=
  Enabled before action.toAction /\
    after = next before action.toAction

def formulaFollows
    (observes : Observation -> State Node TxId -> Prop)
    (state : State Node TxId) :
    List (LoweredInstruction Node TxId Observation) -> Prop
  | [] => True
  | .observation observation :: rest =>
      observes observation state /\
        formulaFollows observes state rest
  | .action action :: rest =>
      Exists fun after =>
        ActionConstraint state after action /\
          formulaFollows observes after rest

def Satisfiable
    (validEntryState : State Node TxId -> Prop)
    (observes : Observation -> State Node TxId -> Prop)
    (formula : Formula Node TxId Observation) : Prop :=
  Exists fun entry =>
    validEntryState entry /\
      formulaFollows observes entry formula.instructions

end CCFRaft.MachineGenerated
