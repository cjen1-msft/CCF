-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import TraceStateObservation
import TraceMessageSummary
import BoundedState
import Shared.Symbolic

set_option autoImplicit false

namespace CCFRaft.SymbolicTraceObservation

open Symbolic

inductive Observation where
  | role (node : Node) (value : Role)
  | currentTerm (node : Node) (value : Nat)
  | logLength (node : Node) (value : Nat)
  | queueLength (node : Node) (value : Nat)
  | commitIndex (node : Node) (value : Nat)
  | allocated (node : Node) (value : Bool)
  | joined (node : Node) (value : Bool)
  | submitted (transaction : Expr .nat) (value : Bool)
  | state (observation : TraceStateObservation.Observation Node)
  | message (summary : TraceMessageSummary.Summary Node)

def Observation.Holds (bounds : BoundedState.Bounds) (assignment : Assignment)
    (state : State Node Nat) : Observation -> Prop
  | .role node value => (state.nodes node).role = value
  | .currentTerm node value => (state.nodes node).currentTerm = value
  | .logLength node value => (state.nodes node).log.length = value
  | .queueLength node value => (state.network node).length = value
  | .commitIndex node value => (state.nodes node).commitIndex = value
  | .allocated node value => decide (state.allocated node) = value
  | .joined node value => decide (node ∈ state.hasJoined) = value
  | .submitted transaction value =>
      transaction.eval assignment < bounds.transactionCount ∧
        decide (transaction.eval assignment ∈ state.submittedTxIds) = value
  | .state observation => observation.Holds state
  | .message summary => summary.matchesFirst state = true

instance (bounds : BoundedState.Bounds) (assignment : Assignment)
    (state : State Node Nat) (observation : Observation) :
    Decidable (observation.Holds bounds assignment state) := by
  cases observation <;> unfold Observation.Holds <;> infer_instance

end CCFRaft.SymbolicTraceObservation
