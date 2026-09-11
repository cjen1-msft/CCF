-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.TransactionMappingProofs

set_option autoImplicit false

namespace CCFRaft.TransactionMapping

variable {Node TxId OtherTxId : Type}
variable [DecidableEq Node] [DecidableEq TxId] [DecidableEq OtherTxId]
variable [Bootstrap Node]

theorem enabled_mapState_appendEntries_iff
    (f : TxId -> OtherTxId) (state : State Node TxId)
    (source destination : Node) (batchEnd : Nat) :
    Enabled (mapState f state) (.appendEntries source destination batchEnd) ↔
      Enabled state (.appendEntries source destination batchEnd) := by
  simp only [Enabled, mapState_allocated, mapState_nodes_get]
  simp [mapNodeState, activeNodeUnion, activeConfigurations, currentConfiguration,
    mapState]

theorem mapMessage_makeAppendEntriesRequest
    (f : TxId -> OtherTxId) (state : State Node TxId)
    (source destination : Node) (batchEnd : Nat) :
    mapMessage f (.appendEntriesRequest
      (makeAppendEntriesRequest state source destination batchEnd)) =
    .appendEntriesRequest
      (makeAppendEntriesRequest (mapState f state) source destination batchEnd) := by
  by_cases zero : (state.nodes source).sentIndex destination = 0
  <;> simp [makeAppendEntriesRequest, mapMessage, mapNodeState, messageEntries,
    termAt, entryAt?, zero, mapEntry, Option.map_map, Function.comp_def]

theorem map_enqueue
    (f : TxId -> OtherTxId)
    (network : Node -> List (Message Node TxId))
    (message : Message Node TxId) :
    (fun node => (enqueue network message node).map (mapMessage f)) =
      enqueue (fun node => (network node).map (mapMessage f))
        (mapMessage f message) := by
  have destination : (mapMessage f message).destination = message.destination := by
    cases message <;> rfl
  funext node
  simp [enqueue, destination, updateQueue]
  by_cases same : node = message.destination
  <;> simp [Function.update_apply, same]

/-- Mapping payloads preserves FIFO sends even when distinct packets become equal. -/
theorem mapState_appendEntries
    (f : TxId -> OtherTxId) (state : State Node TxId)
    (source destination : Node) (batchEnd : Nat) :
    mapState f (next state (.appendEntries source destination batchEnd)) =
      next (mapState f state) (.appendEntries source destination batchEnd) := by
  have request := mapMessage_makeAppendEntriesRequest f state source destination batchEnd
  simp only [mapState] at request
  unfold next
  simp only [mapState, mapNodeStore_get]
  congr 1
  · rw [mapNodeStore_updateNode]
    rfl
  · rw [← request]
    exact map_enqueue f state.network _

end CCFRaft.TransactionMapping
