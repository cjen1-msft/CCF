-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import TraceStateObservation
import MachineGenerated.TransactionMappingProofs
import Shared.Smt

set_option autoImplicit false

namespace CCFRaft.TraceStateObservation

open TransactionMapping TraceSmt

theorem holds_map {Node TxId OtherTxId : Type}
    [DecidableEq Node] [DecidableEq OtherTxId]
    (f : TxId -> OtherTxId) (state : State Node TxId) (observation : Observation Node) :
    observation.Holds (mapState f state) ↔ observation.Holds state := by
  cases observation <;> simp [Observation.Holds, mapState, mapNodeState]

/-- Exact template expression; causal writer bindings belong to trace integration. -/
def expression {Node : Type} [DecidableEq Node] {holes : Nat}
    (state : State Node (NatTerm holes)) (observation : Observation Node) : Expr holes :=
  .boolean (decide (observation.Holds state))

theorem expression_correct {Node : Type} [DecidableEq Node] {holes : Nat}
    (assignment : Fin holes -> Nat) (state : State Node (NatTerm holes))
    (observation : Observation Node) :
    (expression state observation).Holds assignment ↔
      observation.Holds (mapState (NatTerm.eval assignment) state) := by
  simp [expression, Expr.Holds, holds_map]

end CCFRaft.TraceStateObservation
