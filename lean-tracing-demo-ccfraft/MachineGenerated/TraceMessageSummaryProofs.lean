-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import TraceMessageSummary
import MachineGenerated.ControlActionMappingProofs

set_option autoImplicit false

namespace CCFRaft.TraceMessageSummary

open TransactionMapping

variable {Node TxId OtherTxId : Type}

@[simp] theorem ofMessage_map (f : TxId -> OtherTxId) (message : Message Node TxId) :
    ofMessage (mapMessage f message) = ofMessage message := by
  cases message <;> simp [ofMessage, mapMessage]

theorem matchesFirst_map [DecidableEq Node] [DecidableEq TxId]
    [DecidableEq OtherTxId] [Bootstrap Node]
    (f : TxId -> OtherTxId) (summary : Summary Node) (state : State Node TxId) :
    summary.matchesFirst (mapState f state) = summary.matchesFirst state := by
  unfold Summary.matchesFirst
  change (match takeFirstFrom summary.source
      ((state.network summary.destination).map (mapMessage f)) with
    | none => false
    | some (message, _) => decide (ofMessage message = summary)) = _
  rw [takeFirstFrom_map]
  cases takeFirstFrom summary.source (state.network summary.destination) with
  | none => rfl
  | some selected => simp [ofMessage_map]

end CCFRaft.TraceMessageSummary
