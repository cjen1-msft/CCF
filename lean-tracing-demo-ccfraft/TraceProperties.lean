-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.LoweringProofs
import MachineGenerated.Invariant

set_option autoImplicit false

namespace CCFRaft.TraceValidation

variable {Node TxId : Type}
variable [DecidableEq Node] [DecidableEq TxId]
variable [Bootstrap Node]

/-- State facts that the arbitrary trace entry point must satisfy. -/
def ValidEntryState
    (state : State Node TxId) : Prop :=
  RetirementInvariantFacts state /\
    (forall node, state.allocated node <-> node ∈ state.hasJoined) /\
    (forall node,
      state.allocated node ->
        (state.nodes node).commitIndex <= (state.nodes node).log.length) /\
    (forall destination message,
      message ∈ state.network destination ->
        Message.destination message = destination /\
          state.allocated (Message.source message) /\
          state.allocated destination)

/-- State observations emitted by the model-specific reducer. -/
inductive Observation (Node TxId : Type) where
  | allocated (node : Node) (value : Bool)
  | joined (node : Node) (value : Bool)
  | role (node : Node) (value : Role)
  | preVoteStatus (node : Node) (value : PreVoteStatus)
  | membershipState (node : Node) (value : MembershipState)
  | retirementIndex (node : Node) (value : Option Nat)
  | retirementCommittableIndex (node : Node) (value : Option Nat)
  | retiredCommittedIndex (node : Node) (value : Option Nat)
  | retirementCompleted
      (observer retired : Node)
      (value : Bool)
  | currentTerm (node : Node) (value : Nat)
  | commitIndex (node : Node) (value : Nat)
  | logLength (node : Node) (value : Nat)
  | submitted (txId : TxId) (value : Bool)
  | firstMessageFrom
      (source destination : Node)
      (message : Message Node TxId)

def Observation.Holds
    (state : State Node TxId) :
    Observation Node TxId -> Prop
  | .allocated node value => decide (state.allocated node) = value
  | .joined node value => decide (node ∈ state.hasJoined) = value
  | .role node value => (state.nodes node).role = value
  | .preVoteStatus node value => state.preVoteStatus node = value
  | .membershipState node value =>
      (state.nodes node).membershipState = value
  | .retirementIndex node value =>
      (state.nodes node).retirementIndex = value
  | .retirementCommittableIndex node value =>
      (state.nodes node).retirementCommittableIndex = value
  | .retiredCommittedIndex node value =>
      (state.nodes node).retiredCommittedIndex = value
  | .retirementCompleted observer retired value =>
      decide (retired ∈ state.retirementCompleted observer) = value
  | .currentTerm node value => (state.nodes node).currentTerm = value
  | .commitIndex node value => (state.nodes node).commitIndex = value
  | .logLength node value => (state.nodes node).log.length = value
  | .submitted txId value => decide (txId ∈ state.submittedTxIds) = value
  | .firstMessageFrom source destination message =>
      Exists fun remaining =>
        takeFirstFrom source (state.network destination) =
          some (message, remaining)

abbrev ReducedTrace (Node TxId : Type) :=
  List
    (_root_.TraceValidation.Instruction
      (Action Node TxId)
      (Observation Node TxId))

abbrev Formula (Node TxId : Type) :=
  MachineGenerated.Formula Node TxId (Observation Node TxId)

def MidtraceSatisfiable
    (trace : ReducedTrace Node TxId) : Prop :=
  _root_.TraceValidation.Satisfiable
    ValidEntryState
    Enabled
    next
    (fun observation state => observation.Holds state)
    trace

def FormulaSatisfiable
    (formula : Formula Node TxId) : Prop :=
  MachineGenerated.Satisfiable
    ValidEntryState
    (fun observation state => observation.Holds state)
    formula

theorem lowerTrace_correct
    (trace : ReducedTrace Node TxId)
    (formula : Formula Node TxId)
    (lowered : MachineGenerated.lowerTrace trace = .ok formula) :
    FormulaSatisfiable formula <-> MidtraceSatisfiable trace := by
  exact
    MachineGenerated.lowerTraceCorrect
      ValidEntryState
      (fun observation state => observation.Holds state)
      trace
      formula
      lowered

end CCFRaft.TraceValidation
