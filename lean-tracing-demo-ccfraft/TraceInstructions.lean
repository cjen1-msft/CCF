-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Model
import Shared.Smt

set_option autoImplicit false

/-!
# Checked trace instructions and observations

Transaction unknowns are shared by index throughout a trace. The full-entry
execution contract and encoder correctness requirement are defined in
`BoundedTrace.lean`.
-/

namespace CCFRaft.TraceInstructions

structure Bounds where
  transactionCount : Nat
  logCapacity : Nat
  deriving Repr

abbrev Value := TraceSmt.NatTerm

inductive Observation (holes : Nat) where
  | role (node : Node) (value : Role)
  | currentTerm (node : Node) (value : Nat)
  | logLength (node : Node) (value : Nat)
  | queueLength (node : Node) (value : Nat)
  | commitIndex (node : Node) (value : Nat)
  | allocated (node : Node) (value : Bool)
  | joined (node : Node) (value : Bool)
  | submitted (transaction : Value holes) (value : Bool)

inductive Instruction (holes : Nat) where
  | clientRequest (node : Node) (transaction : Value holes)
  | signCommittableMessages (node : Node)
  | changeConfiguration (node : Node) (configuration : Finset Node)
  | appendRetiredCommitted (node : Node)
  | appendEntries (source destination : Node) (batchEnd : Nat)
  | observation (value : Observation holes)

def Instruction.isAction {holes : Nat} : Instruction holes -> Bool
  | .observation _ => false
  | _ => true

def supportedActions : List String :=
  ["clientRequest", "signCommittableMessages", "changeConfiguration",
   "appendRetiredCommitted", "appendEntries"]

def Observation.Holds {holes : Nat}
    (bounds : Bounds)
    (assignment : Fin holes -> Nat)
    (state : State Node Nat) : Observation holes -> Prop
  | .role node value => (state.nodes node).role = value
  | .currentTerm node value => (state.nodes node).currentTerm = value
  | .logLength node value => (state.nodes node).log.length = value
  | .queueLength node value => (state.network node).length = value
  | .commitIndex node value => (state.nodes node).commitIndex = value
  | .allocated node value => decide (state.allocated node) = value
  | .joined node value => decide (node ∈ state.hasJoined) = value
  | .submitted transaction value =>
      transaction.eval assignment < bounds.transactionCount /\
        decide (transaction.eval assignment ∈ state.submittedTxIds) = value

end CCFRaft.TraceInstructions
