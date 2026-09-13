-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayFixtureJson

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeArrayAdvanceCommitFixtures

open Lean NativeArrayFixtures

private instance : Bootstrap (Fin 3) :=
  { configuration := {0, 1}, leader := 0, leader_mem := by simp }

inductive Mutation where
  | unchanged
  | sourceCommit
  | sourceRole
  | sourceTerm
  | sourceMembership
  | retirementIndex
  | retirementCommittableIndex
  | retiredCommittedIndex
  | peerTerm
  | peerMatch
  | completed
  | hasJoined
  | queue
  | submitted
  | preVote
  deriving DecidableEq, Repr

structure Scenario where
  name : String
  source : Fin 3
  present : Finset (Fin 3)
  role : Role
  currentTerm : Nat
  log : List (Entry (Fin 3) Nat)
  commit : Nat
  matchIndex : Fin 3 -> Nat
  membershipState : MembershipState := .active

private def different (value : Option Nat) : Option Nat :=
  if value.isSome then none else some 0

private def mutate (source : Fin 3) (state : State (Fin 3) Nat)
    (mutation : Mutation) : State (Fin 3) Nat :=
  let sourceRow := state.nodes source
  let peer : Fin 3 := if source = 2 then 0 else 2
  let peerRow := state.nodes peer
  match mutation with
  | .unchanged => state
  | .sourceCommit =>
    let changed := { sourceRow with commitIndex := sourceRow.commitIndex + 1 }
    { state with nodes := updateNode state.nodes source changed }
  | .sourceRole =>
    let changed := { sourceRow with
      role := if sourceRow.role = .leader then .follower else .leader }
    { state with nodes := updateNode state.nodes source changed }
  | .sourceTerm =>
    let changed := { sourceRow with currentTerm := sourceRow.currentTerm + 1 }
    { state with nodes := updateNode state.nodes source changed }
  | .sourceMembership =>
    let changed := { sourceRow with membershipState :=
      if sourceRow.membershipState = .active then .retirementCompleted else .active }
    { state with nodes := updateNode state.nodes source changed }
  | .retirementIndex =>
    let changed := { sourceRow with retirementIndex := different sourceRow.retirementIndex }
    { state with nodes := updateNode state.nodes source changed }
  | .retirementCommittableIndex =>
    let changed := { sourceRow with
      retirementCommittableIndex := different sourceRow.retirementCommittableIndex }
    { state with nodes := updateNode state.nodes source changed }
  | .retiredCommittedIndex =>
    let changed := { sourceRow with
      retiredCommittedIndex := different sourceRow.retiredCommittedIndex }
    { state with nodes := updateNode state.nodes source changed }
  | .peerTerm =>
    let changed := { peerRow with currentTerm := peerRow.currentTerm + 1 }
    { state with nodes := updateNode state.nodes peer changed }
  | .peerMatch =>
    let nextMatch :=
      updateIndex peerRow.matchIndex source (peerRow.matchIndex source + 1)
    let changed := { peerRow with matchIndex := nextMatch }
    { state with nodes := updateNode state.nodes peer changed }
  | .completed =>
    let completed :=
      if peer ∈ state.retirementCompleted source then
        (state.retirementCompleted source).erase peer
      else insert peer (state.retirementCompleted source)
    let updated := Function.update state.retirementCompleted source completed
    { state with retirementCompleted := updated }
  | .hasJoined =>
    let joined :=
      if peer ∈ state.hasJoined then state.hasJoined.erase peer
      else insert peer state.hasJoined
    { state with hasJoined := joined }
  | .queue =>
    let packet : Message (Fin 3) Nat :=
      .proposeVoteRequest { term := 99, source := peer, destination := source }
    { state with network := enqueue state.network packet }
  | .submitted =>
    let submitted :=
      if 99 ∈ state.submittedTxIds then state.submittedTxIds.erase 99
      else insert 99 state.submittedTxIds
    { state with submittedTxIds := submitted }
  | .preVote =>
    let status :=
      if state.preVoteStatus peer = .enabled then .capable else .enabled
    let updated := Function.update state.preVoteStatus peer status
    { state with preVoteStatus := updated }

private def fixture (scenario : Scenario) (mutation : Mutation) : Json :=
  let sourceRow : NodeState (Fin 3) Nat :=
    { (freshNodeState : NodeState (Fin 3) Nat) with
      role := scenario.role
      currentTerm := scenario.currentTerm
      log := scenario.log
      commitIndex := scenario.commit
      matchIndex := scenario.matchIndex
      membershipState := scenario.membershipState
      isNewFollower := false
      votedFor := some scenario.source
      votesGranted := {scenario.source}
      preVotesGranted := {2}
      sentIndex := fun peer => peer.val + 3 }
  let peerRow := fun node : Fin 3 =>
    { (freshNodeState : NodeState (Fin 3) Nat) with
      role := .candidate
      currentTerm := 40 + node.val
      log := [{ term := node.val, content := .transaction 0 }]
      commitIndex := node.val
      matchIndex := fun peer => node.val + peer.val
      isNewFollower := false
      votedFor := some node
      votesGranted := {node}
      retirementIndex := some 0 }
  let packet : Message (Fin 3) Nat :=
    .requestVoteRequest
      { term := 7, source := 2, destination := 1,
        lastCommittableTerm := 0, lastCommittableIndex := 0 }
  let state : State (Fin 3) Nat :=
    { nodes := NodeStore.ofFinset scenario.present fun node =>
        if node = scenario.source then sourceRow else peerRow node
      network := fun node => if node = 1 then [packet, packet] else []
      submittedTxIds := {0, 7}
      hasJoined := {0, 1, 2}
      preVoteStatus := fun node => if node = 2 then .enabled else .capable
      retirementCompleted := fun node => if node = scenario.source then {2} else {0} }
  let action := Action.advanceCommitIndex scenario.source
  let allowed := decide (Enabled state action)
  let actual := CCFRaft.next state action
  let observed := mutate scenario.source actual mutation
  let beforeRow := state.nodes scenario.source
  let afterRow := actual.nodes scenario.source
  let best := highestCommittableIndex state scenario.source
  let event := Json.mkObj [
    ("kind", toJson "advanceCommitIndex"),
    ("node", toJson (nodeName scenario.source))]
  Json.mkObj [
    ("scenario", toJson scenario.name),
    ("mutation", toJson (reprStr mutation)),
    ("modelEnabled", toJson allowed),
    ("allocated", toJson (decide (state.allocated scenario.source))),
    ("leader", toJson (beforeRow.role == .leader)),
    ("oldCommit", toJson beforeRow.commitIndex),
    ("highestCommit", toJson best),
    ("advances", toJson (decide (beforeRow.commitIndex < best))),
    ("terminalRetirement", toJson (decide (terminalRetirementCommit state scenario.source))),
    ("currentConfiguration", toJson
      (currentConfigurationAt beforeRow.log beforeRow.commitIndex).index),
    ("beforeMembership", toJson (membershipName beforeRow.membershipState)),
    ("afterMembership", toJson (membershipName afterRow.membershipState)),
    ("completedBefore", toJson (nodeNames (state.retirementCompleted scenario.source))),
    ("completedAfter", toJson (nodeNames (actual.retirementCompleted scenario.source))),
    ("expected", toJson
      (if allowed && decide (mutation = .unchanged) then "sat" else "unsat")),
    ("trace", Json.mkObj [
      ("nodes", toJson (["a", "b", "c"] : List String)),
      ("bootstrap", toJson (["a", "b"] : List String)),
      ("instructions", toJson
        (frameObservations state [0, 7, 99] ++ [event] ++
          if allowed then frameObservations observed [0, 7, 99] else []))])]

private def scenarios : List Scenario :=
  let signature (term : Nat) : Entry (Fin 3) Nat := { term, content := .signature }
  let transaction (term tx : Nat) : Entry (Fin 3) Nat :=
    { term, content := .transaction tx }
  let configuration (term : Nat) (nodes : Finset (Fin 3)) : Entry (Fin 3) Nat :=
    { term, content := .reconfiguration nodes }
  let retired (term : Nat) (nodes : Finset (Fin 3)) : Entry (Fin 3) Nat :=
    { term, content := .retiredCommitted nodes }
  let allAt (value : Nat) : Fin 3 -> Nat := fun _ => value
  [
    { name := "bootstrap-success", source := 0, present := {0, 1, 2},
      role := .leader, currentTerm := 1, log := [signature 1], commit := 0,
      matchIndex := fun peer => if peer = 1 then 1 else 0 },
    { name := "majority-rejection", source := 0, present := {0, 1, 2},
      role := .leader, currentTerm := 1, log := [signature 1], commit := 0,
      matchIndex := allAt 0 },
    { name := "stale-retired-metadata-success", source := 0, present := {0, 1, 2},
      role := .leader, currentTerm := 1, log := [signature 1], commit := 0,
      matchIndex := fun peer => if peer = 1 then 1 else 0,
      membershipState := .retiredCommitted },
    { name := "wrong-role", source := 0, present := {0, 1, 2},
      role := .follower, currentTerm := 1, log := [signature 1], commit := 0,
      matchIndex := allAt 1 },
    { name := "unallocated-source", source := 0, present := {1, 2},
      role := .leader, currentTerm := 1, log := [signature 1], commit := 0,
      matchIndex := allAt 1 },
    { name := "no-new-current-term-signature", source := 0, present := {0, 1, 2},
      role := .leader, currentTerm := 2,
      log := [transaction 2 0, signature 1], commit := 0,
      matchIndex := allAt 2 },
    { name := "retirement-refresh-success", source := 0, present := {0, 1, 2},
      role := .leader, currentTerm := 1,
      log := [configuration 1 {1}, signature 1], commit := 0,
      matchIndex := fun peer => if peer = 1 then 2 else 0 },
    { name := "terminal-retirement-rejection", source := 0, present := {0, 1, 2},
      role := .leader, currentTerm := 1,
      log := [configuration 1 {1}, signature 1, retired 1 {0}, signature 1],
      commit := 0, matchIndex := fun peer => if peer = 1 then 4 else 0 },
    { name := "configuration-commit-success", source := 0, present := {0, 1, 2},
      role := .leader, currentTerm := 1,
      log := [configuration 1 {0, 1, 2}, signature 1], commit := 0,
      matchIndex := allAt 2 },
    { name := "transaction-zero-success", source := 0, present := {0, 1, 2},
      role := .leader, currentTerm := 1,
      log := [transaction 1 0, signature 1], commit := 0,
      matchIndex := allAt 2 },
    { name := "nonzero-source-success", source := 1, present := {0, 1, 2},
      role := .leader, currentTerm := 1, log := [signature 1], commit := 0,
      matchIndex := fun peer => if peer = 0 then 1 else 0 },
    { name := "source-outside-bootstrap-success", source := 2, present := {0, 1, 2},
      role := .leader, currentTerm := 1, log := [signature 1], commit := 0,
      matchIndex := fun peer => if peer = 2 then 0 else 1 }
  ]

private def broadMutations : List Mutation :=
  [.unchanged, .sourceCommit, .sourceRole, .sourceTerm, .sourceMembership,
    .retirementIndex, .retirementCommittableIndex, .retiredCommittedIndex,
    .peerTerm, .peerMatch, .completed, .hasJoined, .queue, .submitted, .preVote]

def cases : List Json :=
  scenarios.flatMap fun scenario =>
    let mutations :=
      if scenario.name = "bootstrap-success" ||
          scenario.name = "retirement-refresh-success" then
        broadMutations
      else if scenario.name = "configuration-commit-success" then
        [.unchanged, .completed]
      else if scenario.name = "nonzero-source-success" ||
          scenario.name = "source-outside-bootstrap-success" then
        [.unchanged, .sourceCommit]
      else
        [.unchanged]
    mutations.map (fixture scenario)

end CCFRaft.NativeArrayAdvanceCommitFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeArrayAdvanceCommitFixtures.cases).compress
