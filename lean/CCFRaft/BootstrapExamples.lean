-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs

set_option autoImplicit false

/-!
# Bootstrap parameter examples

These examples exercise initial-state construction and the generic reachable
safety proof under bootstraps unlike the canonical five-node default.
-/

namespace CCFRaft.BootstrapExamples

abbrev ExampleTxId := Fin 1

def node0 : Node := Fin.mk 0 (by decide)
def node1 : Node := Fin.mk 1 (by decide)
def node2 : Node := Fin.mk 2 (by decide)
def node7 : Node := Fin.mk 7 (by decide)
def node14 : Node := Fin.mk 14 (by decide)

/-- A one-member bootstrap led by its only member. -/
def singletonBootstrap : Bootstrap Node where
  configuration := {node0}
  leader := node0
  leader_mem := by decide

/-- A sparse three-member bootstrap led by node seven. -/
def noncontiguousBootstrap : Bootstrap Node where
  configuration := {node2, node7, node14}
  leader := node7
  leader_mem := by decide

/-- A bootstrap containing the entire fixed 15-node world. -/
def fullBootstrap : Bootstrap Node where
  configuration := Finset.univ
  leader := node14
  leader_mem := Finset.mem_univ node14

/-- Reachable safety is uniform over every valid bootstrap parameter. -/
theorem arbitraryBootstrapReachableSafety
    {Node : Type}
    [DecidableEq Node]
    [Bootstrap Node]
    {state : State Node ExampleTxId}
    (reachable : Reachable state) :
    ConsensusSafety state :=
  reachableConsensusSafety reachable

section Singleton

local instance : Bootstrap Node := singletonBootstrap

/-- Singleton initialization has one term-one leader and no other participant. -/
theorem singletonInitialShape :
    ((initialState (Node := Node) (TxId := ExampleTxId)).nodes node0).role = .leader /\
      ((initialState (Node := Node) (TxId := ExampleTxId)).nodes node0).currentTerm =
        TERM_ONE /\
      ((initialState (Node := Node) (TxId := ExampleTxId)).nodes node1).role = .none /\
      ((initialState (Node := Node) (TxId := ExampleTxId)).nodes node1).currentTerm = 0 /\
      (initialState (Node := Node) (TxId := ExampleTxId)).hasJoined = {node0} /\
      implicitConfiguration =
        { index := 0, nodes := {node0} } /\
      currentConfiguration
          ((initialState (Node := Node) (TxId := ExampleTxId)).nodes node0) =
        implicitConfiguration := by
  decide

theorem singletonInitialReachable :
    Reachable (initialState : State Node ExampleTxId) :=
  Reachable.initial

theorem singletonReachableSafety
    {state : State Node ExampleTxId}
    (reachable : Reachable state) :
    ConsensusSafety state :=
  reachableConsensusSafety reachable

/-- Expanding a singleton allocates the new node before replication reaches it. -/
theorem singletonExpansionAllocatesAndReplicates :
    let start := initialState (Node := Node) (TxId := ExampleTxId)
    let actions : List (Action Node ExampleTxId) := [
      .changeConfiguration node0 {node0, node1},
      .appendEntries node0 node1 1,
      .updateTerm node0 node1,
      .receive node0 node1
    ]
    let expanded :=
      runActions start [.changeConfiguration node0 {node0, node1}]
    start.node? node1 = none /\
      expanded.isSome = true /\
      ((expanded.getD start).node? node1).isSome = true /\
      ((expanded.getD start).nodes node1).role = .none /\
      ((expanded.getD start).nodes node1).currentTerm = 0 /\
      ((expanded.getD start).nodes node1).log = [] /\
      (runActions start actions).isSome = true /\
      let final := (runActions start actions).getD start
      (final.node? node1).isSome = true /\
        (final.nodes node1).role = .follower /\
        (final.nodes node1).currentTerm = TERM_ONE /\
        (final.nodes node1).log.length = 1 := by
  decide

/-- Responses from unallocated senders are consumed without changing local state. -/
theorem singletonDropsUnknownResponse :
    let start := initialState (Node := Node) (TxId := ExampleTxId)
    let response : RequestVoteResponse Node := {
      term := TERM_ONE + 1
      voteGranted := true
      source := node1
      destination := node0
    }
    let queued : State Node ExampleTxId := {
      start with
      network :=
        enqueueNoDup start.network (.requestVoteResponse response)
    }
    newerMessage? queued node1 node0 = none /\
      (match handleReceive? queued node1 node0 with
      | none => false
      | some after =>
          decide (
            after.network node0 = [] /\
              (after.nodes node0).role = (start.nodes node0).role /\
              (after.nodes node0).currentTerm =
                (start.nodes node0).currentTerm /\
              (after.nodes node0).log = (start.nodes node0).log)) = true := by
  decide

/-- Requests from unallocated senders can update term and receive a vote. -/
theorem singletonAcceptsUnknownRequest :
    let start := initialState (Node := Node) (TxId := ExampleTxId)
    let request : RequestVoteRequest Node := {
      term := TERM_ONE + 1
      lastCommittableTerm := 0
      lastCommittableIndex := 0
      source := node1
      destination := node0
    }
    let queued : State Node ExampleTxId := {
      start with
      network :=
        enqueueNoDup start.network (.requestVoteRequest request)
    }
    let actions : List (Action Node ExampleTxId) := [
      .updateTerm node1 node0,
      .receive node1 node0
    ]
    newerMessage? queued node1 node0 = some (.requestVoteRequest request) /\
      (runActions queued actions).isSome = true /\
      let final := (runActions queued actions).getD queued
      (final.nodes node0).currentTerm = TERM_ONE + 1 /\
        (final.nodes node0).votedFor = some node1 := by
  decide

end Singleton

section Noncontiguous

local instance : Bootstrap Node := noncontiguousBootstrap

/-- Sparse initialization respects membership rather than node-number ranges. -/
theorem noncontiguousInitialShape :
    ((initialState (Node := Node) (TxId := ExampleTxId)).nodes node7).role = .leader /\
      ((initialState (Node := Node) (TxId := ExampleTxId)).nodes node7).currentTerm =
        TERM_ONE /\
      ((initialState (Node := Node) (TxId := ExampleTxId)).nodes node2).role = .follower /\
      ((initialState (Node := Node) (TxId := ExampleTxId)).nodes node2).currentTerm =
        TERM_ONE /\
      ((initialState (Node := Node) (TxId := ExampleTxId)).nodes node14).role = .follower /\
      ((initialState (Node := Node) (TxId := ExampleTxId)).nodes node14).currentTerm =
        TERM_ONE /\
      ((initialState (Node := Node) (TxId := ExampleTxId)).nodes node0).role = .none /\
      ((initialState (Node := Node) (TxId := ExampleTxId)).nodes node0).currentTerm = 0 /\
      (initialState (Node := Node) (TxId := ExampleTxId)).hasJoined =
        {node2, node7, node14} /\
      implicitConfiguration =
        { index := 0, nodes := {node2, node7, node14} } /\
      currentConfiguration
          ((initialState (Node := Node) (TxId := ExampleTxId)).nodes node7) =
        implicitConfiguration := by
  decide

theorem noncontiguousInitialReachable :
    Reachable (initialState : State Node ExampleTxId) :=
  Reachable.initial

theorem noncontiguousReachableSafety
    {state : State Node ExampleTxId}
    (reachable : Reachable state) :
    ConsensusSafety state :=
  reachableConsensusSafety reachable

end Noncontiguous

section Full

local instance : Bootstrap Node := fullBootstrap

/-- Full-world initialization makes every node a term-one participant. -/
theorem fullInitialShape :
    ((initialState (Node := Node) (TxId := ExampleTxId)).nodes node14).role = .leader /\
      ((initialState (Node := Node) (TxId := ExampleTxId)).nodes node14).currentTerm =
        TERM_ONE /\
      ((initialState (Node := Node) (TxId := ExampleTxId)).nodes node0).role = .follower /\
      ((initialState (Node := Node) (TxId := ExampleTxId)).nodes node0).currentTerm =
        TERM_ONE /\
      (initialState (Node := Node) (TxId := ExampleTxId)).hasJoined =
        Finset.univ /\
      (implicitConfiguration (Node := Node)) =
        { index := 0, nodes := Finset.univ } /\
      currentConfiguration
          ((initialState (Node := Node) (TxId := ExampleTxId)).nodes node14) =
        (implicitConfiguration (Node := Node)) := by
  decide

theorem fullInitialReachable :
    Reachable (initialState : State Node ExampleTxId) :=
  Reachable.initial

theorem fullReachableSafety
    {state : State Node ExampleTxId}
    (reachable : Reachable state) :
    ConsensusSafety state :=
  reachableConsensusSafety reachable

end Full

end CCFRaft.BootstrapExamples
