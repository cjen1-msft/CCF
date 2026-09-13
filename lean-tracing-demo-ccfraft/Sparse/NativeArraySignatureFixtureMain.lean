-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayFixtureJson

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeArraySignatureFixtures

open Lean NativeArrayFixtures

private instance : Bootstrap (Fin 3) :=
  { configuration := {0, 1}, leader := 0, leader_mem := by simp }

inductive Mutation where
  | unchanged
  | sourceCommit
  | sourceRole
  | sourceTerm
  | sourceMembership
  | sourceVotedFor
  | sourceLog
  | signatureTerm
  | signatureContent
  | sourceNewFollower
  | sourceVotes
  | sourcePreVotes
  | sourceSentIndex
  | sourceMatchIndex
  | retirementIndex
  | retirementCommittableIndex
  | retiredCommittedIndex
  | peerRow
  | completed
  | queue
  | submitted
  | joined
  | preVoteStatus
  deriving DecidableEq, Repr

structure Scenario where
  name : String
  source : Fin 3
  present : Finset (Fin 3)
  role : Role
  currentTerm : Nat
  log : List (Entry (Fin 3) Nat)
  commit : Nat
  membershipState : MembershipState := .active
  retirementIndex : Option Nat := none
  retirementCommittableIndex : Option Nat := none
  retiredCommittedIndex : Option Nat := none
  votedFor : Option (Fin 3) := some 0

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
      if sourceRow.membershipState = .active then .retirementSigned else .active }
    { state with nodes := updateNode state.nodes source changed }
  | .sourceVotedFor =>
    let changed := { sourceRow with
      votedFor := if sourceRow.votedFor.isSome then none else some 0 }
    { state with nodes := updateNode state.nodes source changed }
  | .sourceLog =>
    let changed := { sourceRow with log := sourceRow.log ++
      [{ term := 99, content := .transaction 0 }] }
    { state with nodes := updateNode state.nodes source changed }
  | .signatureTerm =>
    let changed := { sourceRow with log := sourceRow.log.dropLast ++
      [{ term := sourceRow.currentTerm + 1, content := .signature }] }
    { state with nodes := updateNode state.nodes source changed }
  | .signatureContent =>
    let changed := { sourceRow with log := sourceRow.log.dropLast ++
      [{ term := sourceRow.currentTerm, content := .transaction 0 }] }
    { state with nodes := updateNode state.nodes source changed }
  | .sourceNewFollower =>
    let changed := { sourceRow with isNewFollower := !sourceRow.isNewFollower }
    { state with nodes := updateNode state.nodes source changed }
  | .sourceVotes =>
    let changed := { sourceRow with votesGranted := insert peer sourceRow.votesGranted }
    { state with nodes := updateNode state.nodes source changed }
  | .sourcePreVotes =>
    let changed := { sourceRow with preVotesGranted := {} }
    { state with nodes := updateNode state.nodes source changed }
  | .sourceSentIndex =>
    let changed := { sourceRow with
      sentIndex := Function.update sourceRow.sentIndex peer (sourceRow.sentIndex peer + 1) }
    { state with nodes := updateNode state.nodes source changed }
  | .sourceMatchIndex =>
    let changed := { sourceRow with
      matchIndex := Function.update sourceRow.matchIndex peer (sourceRow.matchIndex peer + 1) }
    { state with nodes := updateNode state.nodes source changed }
  | .retirementIndex =>
    let changed :=
      { sourceRow with retirementIndex := different sourceRow.retirementIndex }
    { state with nodes := updateNode state.nodes source changed }
  | .retirementCommittableIndex =>
    let changed :=
      { sourceRow with
        retirementCommittableIndex := different sourceRow.retirementCommittableIndex }
    { state with nodes := updateNode state.nodes source changed }
  | .retiredCommittedIndex =>
    let changed :=
      { sourceRow with
        retiredCommittedIndex := different sourceRow.retiredCommittedIndex }
    { state with nodes := updateNode state.nodes source changed }
  | .peerRow =>
    let changed := { peerRow with currentTerm := peerRow.currentTerm + 1 }
    { state with nodes := updateNode state.nodes peer changed }
  | .completed =>
    let completed :=
      if peer ∈ state.retirementCompleted source then
        (state.retirementCompleted source).erase peer
      else
        insert peer (state.retirementCompleted source)
    { state with retirementCompleted :=
        Function.update state.retirementCompleted source completed }
  | .queue =>
    let packet : Message (Fin 3) Nat :=
      .proposeVoteRequest { term := 99, source := peer, destination := source }
    { state with network := enqueue state.network packet }
  | .submitted =>
    let submitted :=
      if 0 ∈ state.submittedTxIds then
        state.submittedTxIds.erase 0
      else
        insert 0 state.submittedTxIds
    { state with submittedTxIds := submitted }
  | .joined => { state with hasJoined := state.hasJoined.erase peer }
  | .preVoteStatus =>
    { state with preVoteStatus := Function.update state.preVoteStatus source .enabled }

private def fixture (scenario : Scenario) (mutation : Mutation) : Json :=
  let sourceRow : NodeState (Fin 3) Nat :=
    { (freshNodeState : NodeState (Fin 3) Nat) with
      role := scenario.role
      currentTerm := scenario.currentTerm
      log := scenario.log
      commitIndex := scenario.commit
      matchIndex := fun peer => peer.val + 2
      sentIndex := fun peer => peer.val + 5
      membershipState := scenario.membershipState
      retirementIndex := scenario.retirementIndex
      retirementCommittableIndex := scenario.retirementCommittableIndex
      retiredCommittedIndex := scenario.retiredCommittedIndex
      isNewFollower := false
      votedFor := scenario.votedFor
      votesGranted := {scenario.source}
      preVotesGranted := {2} }
  let peerRow := fun node : Fin 3 =>
    { (freshNodeState : NodeState (Fin 3) Nat) with
      role := .candidate
      currentTerm := 40 + node.val
      log := [{ term := node.val, content := .transaction 0 }]
      commitIndex := node.val
      matchIndex := fun peer => node.val + peer.val
      sentIndex := fun peer => 10 + node.val + peer.val
      isNewFollower := false
      votedFor := if node = 2 then none else some 0
      votesGranted := {node}
      preVotesGranted := {0, 2}
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
      retirementCompleted := fun node =>
        if node = scenario.source then {2} else {0, 1} }
  let action := Action.signCommittableMessages scenario.source
  let allowed := decide (Enabled state action)
  let actual := CCFRaft.next state action
  let observed := mutate scenario.source actual mutation
  let beforeRow := state.nodes scenario.source
  let appended :=
    { beforeRow with log := beforeRow.log ++
        [{ term := beforeRow.currentTerm, content := .signature }] }
  let refreshed := refreshRetirementState scenario.source appended
  let afterRow := actual.nodes scenario.source
  let event := Json.mkObj [
    ("kind", toJson "signCommittableMessages"),
    ("node", toJson (nodeName scenario.source))]
  Json.mkObj [
    ("scenario", toJson scenario.name),
    ("mutation", toJson (reprStr mutation)),
    ("modelEnabled", toJson allowed),
    ("actionSource", toJson (nodeName scenario.source)),
    ("sourceInBootstrap", toJson
      (decide (scenario.source ∈ INITIAL_CONFIGURATION))),
    ("sourceAllocated", toJson (decide (state.allocated scenario.source))),
    ("sourceRole", toJson (roleName beforeRow.role)),
    ("currentTerm", toJson beforeRow.currentTerm),
    ("oldLength", toJson beforeRow.log.length),
    ("oldCommit", toJson beforeRow.commitIndex),
    ("oldVotedFor", toJson (beforeRow.votedFor.map nodeName)),
    ("outputVotedFor", toJson (afterRow.votedFor.map nodeName)),
    ("oldMembership", toJson (membershipName beforeRow.membershipState)),
    ("oldTerminal", toJson
      (decide (beforeRow.membershipState = .retiredCommitted))),
    ("refreshedMembership", toJson (membershipName refreshed.membershipState)),
    ("refreshedTerminal", toJson
      (decide (refreshed.membershipState = .retiredCommitted))),
    ("outputLength", toJson afterRow.log.length),
    ("outputMembership", toJson (membershipName afterRow.membershipState)),
    ("oldRetirementIndex", toJson beforeRow.retirementIndex),
    ("refreshedRetirementIndex", toJson refreshed.retirementIndex),
    ("oldRetirementCommittableIndex", toJson beforeRow.retirementCommittableIndex),
    ("refreshedRetirementCommittableIndex",
      toJson refreshed.retirementCommittableIndex),
    ("oldRetiredCommittedIndex", toJson beforeRow.retiredCommittedIndex),
    ("refreshedRetiredCommittedIndex", toJson refreshed.retiredCommittedIndex),
    ("expected", toJson
      (if allowed && decide (mutation = .unchanged) then "sat" else "unsat")),
    ("trace", Json.mkObj [
      ("nodes", toJson (["a", "b", "c"] : List String)),
      ("bootstrap", toJson (["a", "b"] : List String)),
      ("instructions", toJson
        (frameObservations state [0, 7, 99] ++ [event] ++
          if allowed then frameObservations observed [0, 7, 99] else []))])]

private def scenarios : List Scenario :=
  let signature (term : Nat) : Entry (Fin 3) Nat :=
    { term, content := .signature }
  let transaction (term tx : Nat) : Entry (Fin 3) Nat :=
    { term, content := .transaction tx }
  let configuration (term : Nat) (nodes : Finset (Fin 3)) :
      Entry (Fin 3) Nat :=
    { term, content := .reconfiguration nodes }
  let retired (term : Nat) (nodes : Finset (Fin 3)) : Entry (Fin 3) Nat :=
    { term, content := .retiredCommitted nodes }
  [
    { name := "signature-nonempty", source := 0, present := {0, 1, 2},
      role := .leader, currentTerm := 2, log := [signature 1], commit := 0 },
    { name := "transaction-zero-unsorted-current-zero", source := 0,
      present := {0, 1, 2}, role := .leader, currentTerm := 0,
      log := [transaction 5 0, signature 1, transaction 3 0], commit := 0 },
    { name := "physical-configuration-retains-source", source := 0,
      present := {0, 1, 2}, role := .leader, currentTerm := 4,
      log := [configuration 3 {0, 2}], commit := 1 },
    { name := "refresh-retirement-signed", source := 0, present := {0, 1, 2},
      role := .leader, currentTerm := 4,
      log := [configuration 3 {1, 2}], commit := 0 },
    { name := "refresh-retirement-completed", source := 0,
      present := {0, 1, 2}, role := .leader, currentTerm := 4,
      log := [configuration 3 {1, 2}], commit := 1 },
    { name := "stale-retirement-metadata-refreshes-active", source := 0,
      present := {0, 1, 2}, role := .leader, currentTerm := 0,
      log := [transaction 8 0], commit := 9,
      membershipState := .retirementCompleted, retirementIndex := some 7,
      retirementCommittableIndex := some 8, retiredCommittedIndex := some 0 },
    { name := "nonzero-source", source := 1, present := {0, 1, 2},
      role := .leader, currentTerm := 6, log := [transaction 2 0], commit := 0,
      votedFor := none },
    { name := "source-outside-bootstrap", source := 2, present := {0, 1, 2},
      role := .leader, currentTerm := 6, log := [signature 2], commit := 0,
      votedFor := none },
    { name := "unallocated-source", source := 0, present := {1, 2},
      role := .leader, currentTerm := 2, log := [signature 1], commit := 0 },
    { name := "nonleader", source := 0, present := {0, 1, 2},
      role := .follower, currentTerm := 2, log := [signature 1], commit := 0 },
    { name := "empty-log", source := 0, present := {0, 1, 2},
      role := .leader, currentTerm := 2, log := [], commit := 0 },
    { name := "old-retired-committed", source := 0, present := {0, 1, 2},
      role := .leader, currentTerm := 2, log := [signature 1], commit := 0,
      membershipState := .retiredCommitted },
    { name := "newly-refreshed-retired-committed", source := 0,
      present := {0, 1, 2}, role := .leader, currentTerm := 2,
      log := [configuration 1 {1, 2}, retired 1 {0}], commit := 2 }
  ]

private def broadMutations : List Mutation :=
  [.unchanged, .sourceCommit, .sourceRole, .sourceTerm, .sourceMembership,
    .sourceVotedFor, .sourceLog, .signatureTerm, .signatureContent,
    .sourceNewFollower, .sourceVotes, .sourcePreVotes, .sourceSentIndex,
    .sourceMatchIndex, .retirementIndex,
    .retirementCommittableIndex, .retiredCommittedIndex, .peerRow, .completed,
    .queue, .submitted, .joined, .preVoteStatus]

def cases : List Json :=
  scenarios.flatMap fun scenario =>
    let mutations :=
      if scenario.name = "signature-nonempty" then
        broadMutations
      else if scenario.name = "refresh-retirement-signed" ||
          scenario.name = "refresh-retirement-completed" ||
          scenario.name = "stale-retirement-metadata-refreshes-active" then
        [.unchanged, .sourceMembership, .completed, .retirementIndex]
      else if scenario.name = "transaction-zero-unsorted-current-zero" ||
          scenario.name = "physical-configuration-retains-source" then
        [.unchanged, .sourceLog]
      else if scenario.name = "nonzero-source" ||
          scenario.name = "source-outside-bootstrap" then
        [.unchanged, .sourceVotedFor, .peerRow]
      else
        [.unchanged]
    mutations.map (fixture scenario)

end CCFRaft.NativeArraySignatureFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeArraySignatureFixtures.cases).compress
