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

theorem map_enqueueNoDup_of_not_mem
    (f : TxId -> OtherTxId)
    (network : Node -> List (Message Node TxId))
    (message : Message Node TxId)
    (absent : mapMessage f message ∉
      (network message.destination).map (mapMessage f)) :
    (fun node => (enqueueNoDup network message node).map (mapMessage f)) =
      enqueueNoDup (fun node => (network node).map (mapMessage f))
        (mapMessage f message) := by
  have destination : (mapMessage f message).destination = message.destination := by
    cases message <;> rfl
  have syntacticAbsent : message ∉ network message.destination := by
    intro member
    exact absent (List.mem_map.mpr ⟨message, member, rfl⟩)
  funext node
  simp [enqueueNoDup, destination, absent, syntacticAbsent, updateQueue]
  by_cases same : node = message.destination
  <;> simp [Function.update_apply, same]

/--
Mapping may create a duplicate packet, so retain the sender update but undo
the template enqueue in that branch. Only the mapped result is a model step.
-/
theorem mapState_appendEntries_with_dedup
    (f : TxId -> OtherTxId) (state : State Node TxId)
    (source destination : Node) (batchEnd : Nat) :
    let message := Message.appendEntriesRequest
      (makeAppendEntriesRequest state source destination batchEnd)
    let advanced := next state (.appendEntries source destination batchEnd)
    mapState f
      (if mapMessage f message ∈
          (state.network destination).map (mapMessage f)
       then { advanced with network := state.network }
       else advanced) =
      next (mapState f state) (.appendEntries source destination batchEnd) := by
  have request := mapMessage_makeAppendEntriesRequest f state source destination batchEnd
  simp only [mapState] at request
  dsimp only
  split
  · rename_i duplicate
    unfold next
    simp only [mapState, mapNodeStore_get]
    congr 1
    · rw [mapNodeStore_updateNode]
      rfl
    · rw [← request]
      simp only [enqueueNoDup]
      exact (if_pos duplicate).symm
  · rename_i absent
    unfold next
    simp only [mapState, mapNodeStore_get]
    congr 1
    · rw [mapNodeStore_updateNode]
      rfl
    · rw [← request]
      exact map_enqueueNoDup_of_not_mem f state.network _ absent

end CCFRaft.TransactionMapping
