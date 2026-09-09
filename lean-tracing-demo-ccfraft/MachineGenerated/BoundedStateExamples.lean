-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.BoundedStateProofs

set_option autoImplicit false

namespace CCFRaft.BoundedStateExamples

open BoundedState

def node0 : Node := ⟨0, by decide⟩
def node1 : Node := ⟨1, by decide⟩

def generousBounds : Bounds where
  transactionCount := 8
  termCount := 5
  indexCount := 8
  logCapacity := 4
  queueCapacity := 3

def emptyData : Data where
  nodes := Vector.replicate NODE_COUNT none
  network := Vector.replicate NODE_COUNT []
  submittedTxIds := ∅
  hasJoined := ∅
  preVoteStatus := Vector.replicate NODE_COUNT .capable
  retirementCompleted := Vector.replicate NODE_COUNT ∅

def freshData : BoundedState.LocalStateData :=
  BoundedState.encodeLocal (freshNodeState : NodeState Node Nat)

/-- The canonical bootstrap is representable and satisfies ordinary bounds. -/
def bootstrapData : Data :=
  BoundedState.encode (initialState : State Node Nat)

#guard BoundedState.check generousBounds bootstrapData

example :
    BoundedState.decode bootstrapData = (initialState : State Node Nat) := by
  exact BoundedState.decode_encode _

/-- The representation and roundtrip are not specific to natural transactions. -/
example (state : State Node (Fin 4)) :
    BoundedState.decode (BoundedState.encode state) = state := by
  exact BoundedState.decode_encode state

/-- An absent node and an allocated fresh node remain distinct after decoding. -/
example :
    (BoundedState.decode emptyData).node? node0 = none ∧
      (BoundedState.decode {
        emptyData with
        nodes := Vector.ofFn fun node =>
          if node = node0 then some freshData else none
      }).node? node0 = some freshNodeState := by
  constructor
  · change emptyData.decodeNodes.node? node0 = none
    rw [BoundedState.Data.node?_decodeNodes]
    change
      Option.map BoundedState.decodeLocal
        (Vector.get (Vector.replicate NODE_COUNT none) node0) = none
    simp
  · change
      ({
        emptyData with
        nodes := Vector.ofFn fun node =>
          if node = node0 then some freshData else none
      } : Data).decodeNodes.node? node0 = some freshNodeState
    rw [BoundedState.Data.node?_decodeNodes]
    simp [freshData, BoundedState.NodeTable.get]

/-- Nonzero terms, indices, logs, and messages fit in the finite representation. -/
def nonzeroData : Data :=
  let entry : Entry Node Nat := {
    term := 2
    content := .transaction 3
  }
  let localState : LocalStateData := {
    freshData with
    role := .leader
    currentTerm := 2
    log := [entry]
    commitIndex := 1
    sentIndex := Vector.ofFn fun node => if node = node1 then 2 else 0
    matchIndex := Vector.ofFn fun node => if node = node1 then 1 else 0
  }
  let request : AppendEntriesRequest Node Nat := {
    term := 2
    prevLogIndex := 1
    prevLogTerm := 2
    entries := [entry]
    leaderCommit := 1
    source := node0
    destination := node1
  }
  {
    emptyData with
    nodes := Vector.ofFn fun node =>
      if node = node0 then some localState else none
    network := Vector.ofFn fun node =>
      if node = node1 then [.appendEntriesRequest request] else []
    submittedTxIds := {3}
    hasJoined := {node0}
  }

#guard BoundedState.check generousBounds nonzeroData

-- Transaction bounds inspect payloads inside queued AppendEntries entries.
#guard !BoundedState.check
  { generousBounds with transactionCount := 3 }
  nonzeroData

end CCFRaft.BoundedStateExamples
