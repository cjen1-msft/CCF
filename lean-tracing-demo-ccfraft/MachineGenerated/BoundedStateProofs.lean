-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import BoundedState
import MachineGenerated.ModelProofs

set_option autoImplicit false

/-!
# Proofs for the finite full-state representation

The named theorem corpus is kept outside the reviewed representation module.
-/

namespace CCFRaft.BoundedState

variable {α : Type}
variable {TxId : Type}

@[simp]
theorem NodeTable.get_ofFunction (value : Node → α) (node : Node) :
    (NodeTable.ofFunction value).get node = value node := by
  simp [NodeTable.ofFunction, NodeTable.get]

@[simp]
theorem decodeLocal_encodeLocal (state : NodeState Node TxId) :
    decodeLocal (encodeLocal state) = state := by
  cases state
  simp only [encodeLocal, decodeLocal]
  congr 1 <;> funext node <;> simp

@[simp]
theorem LocalDataWithin_encodeLocal_iff
    (bounds : Bounds)
    (state : NodeState Node Nat) :
    LocalDataWithin bounds (encodeLocal state) ↔ LocalWithin bounds state := by
  simp [LocalDataWithin, LocalWithin, encodeLocal]

@[simp]
theorem Data.allocatedNodes_encode (state : State Node TxId) (node : Node) :
    node ∈ (encode state).allocatedNodes ↔ (state.node? node).isSome := by
  simp [Data.allocatedNodes, encode]

@[simp]
theorem Data.node?_decodeNodes (data : Data TxId) (node : Node) :
    data.decodeNodes.node? node =
      (data.nodes.get node).map decodeLocal := by
  cases found : data.nodes.get node with
  | none =>
      apply NodeStore.node?_ofFinset_of_not_mem
      simp [Data.allocatedNodes, found]
  | some localState =>
      rw [Data.decodeNodes, NodeStore.node?_ofFinset_of_mem]
      · simp [found]
      · simp [Data.allocatedNodes, found]

@[simp]
theorem Data.node?_decode_encode (state : State Node TxId) (node : Node) :
    (encode state).decodeNodes.node? node = state.node? node := by
  rw [Data.node?_decodeNodes]
  cases found : state.node? node <;> simp [encode, found]

theorem Data.decodeNodes_encode (state : State Node TxId) :
    (encode state).decodeNodes = state.nodes := by
  cases left : (encode state).decodeNodes with
  | mk leftEntries =>
      cases right : state.nodes with
      | mk rightEntries =>
          congr 1
          apply Finmap.ext_lookup
          intro node
          calc
            leftEntries.lookup node =
                state.node? node := by
              simpa [NodeStore.node?, left] using
                Data.node?_decode_encode state node
            _ = rightEntries.lookup node := by
              simp [State.node?, NodeStore.node?, right]

/-- Encoding followed by decoding recovers the exact original model state. -/
@[simp]
theorem decode_encode (state : State Node TxId) :
    decode (encode state) = state := by
  cases state with
  | mk nodes network submittedTxIds hasJoined preVoteStatus
      retirementCompleted =>
      simp only [decode, encode]
      congr 1
      · exact Data.decodeNodes_encode {
          nodes := nodes
          network := network
          submittedTxIds := submittedTxIds
          hasJoined := hasJoined
          preVoteStatus := preVoteStatus
          retirementCompleted := retirementCompleted
        }
      · funext node
        simp
      · funext node
        simp
      · funext node
        simp

@[simp]
theorem LocalWithin_decodeLocal_iff
    (bounds : Bounds)
    (data : LocalStateData) :
    LocalWithin bounds (decodeLocal data) ↔ LocalDataWithin bounds data := by
  simp [LocalWithin, LocalDataWithin, decodeLocal]

/--
The executable data predicate is exactly the reviewed predicate on its decoded
model state, including optional allocation and every queue in order.
-/
theorem decode_withinBounds_iff
    (bounds : Bounds)
    (data : Data) :
    WithinBounds bounds (decode data) ↔ DataWithinBounds bounds data := by
  simp only [WithinBounds, DataWithinBounds, decode, State.node?,
    Data.node?_decodeNodes]
  constructor
  · rintro ⟨locals, queues, submitted⟩
    refine ⟨?_, queues, submitted⟩
    intro node
    specialize locals node
    cases found : data.nodes.get node with
    | none => trivial
    | some localState =>
        simpa [found, OptionalLocalWithin, OptionalLocalDataWithin,
          LocalWithin_decodeLocal_iff] using locals
  · rintro ⟨locals, queues, submitted⟩
    refine ⟨?_, queues, submitted⟩
    intro node
    specialize locals node
    cases found : data.nodes.get node with
    | none => trivial
    | some localState =>
        simpa [found, OptionalLocalWithin, OptionalLocalDataWithin,
          LocalWithin_decodeLocal_iff] using locals

@[simp]
theorem check_eq_true_iff
    (bounds : Bounds)
    (data : Data) :
    check bounds data = true ↔ WithinBounds bounds (decode data) := by
  rw [check, decide_eq_true_iff, decode_withinBounds_iff]

@[simp]
theorem DataWithinBounds_encode_iff
    (bounds : Bounds)
    (state : State Node Nat) :
    DataWithinBounds bounds (encode state) ↔ WithinBounds bounds state := by
  rw [← decode_withinBounds_iff, decode_encode]

end CCFRaft.BoundedState
