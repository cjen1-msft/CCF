-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayFixtureJson

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeArrayClientRequestFixtures

open Lean NativeArrayFixtures

private instance : Bootstrap (Fin 3) :=
  { configuration := {0, 1}, leader := 0, leader_mem := by simp }

structure Scenario where
  name : String
  source : Fin 3 := 0
  present : Finset (Fin 3) := {0, 1, 2}
  role : Role := .leader
  currentTerm : Nat := 0
  transaction : Nat := 5
  submitted : Finset Nat := {0, 7}
  log : List (Entry (Fin 3) Nat) := []
  commit : Nat := 9
  membership : MembershipState := .active
  retirement : Option Nat := none
  retirementSignature : Option Nat := none
  retired : Option Nat := none

private def fixture (scenario : Scenario) : Json :=
  let sourceRow : NodeState (Fin 3) Nat :=
    { (freshNodeState : NodeState (Fin 3) Nat) with
      role := scenario.role
      currentTerm := scenario.currentTerm
      log := scenario.log
      commitIndex := scenario.commit
      membershipState := scenario.membership
      retirementIndex := scenario.retirement
      retirementCommittableIndex := scenario.retirementSignature
      retiredCommittedIndex := scenario.retired
      isNewFollower := true
      votedFor := some 2
      votesGranted := {1}
      preVotesGranted := {0, 2}
      sentIndex := fun peer => peer.val + 5
      matchIndex := fun peer => peer.val + 12 }
  let peerRow := fun node : Fin 3 =>
    { (freshNodeState : NodeState (Fin 3) Nat) with
      role := .candidate
      currentTerm := node.val + 30
      log := [{ term := node.val, content := .transaction 7 }]
      commitIndex := node.val
      isNewFollower := false
      retirementIndex := some 0 }
  let packet : Message (Fin 3) Nat :=
    .requestVoteRequest
      { term := 7, source := 2, destination := 1,
        lastCommittableTerm := 0, lastCommittableIndex := 0 }
  let state : State (Fin 3) Nat :=
    { nodes := NodeStore.ofFinset scenario.present fun node =>
        if node = scenario.source then sourceRow else peerRow node
      network := fun node => if node = 1 then [packet, packet] else []
      submittedTxIds := scenario.submitted
      hasJoined := {0, 2}
      preVoteStatus := fun node => if node = 1 then .enabled else .capable
      retirementCompleted := fun node => if node = scenario.source then {2} else {0, 1} }
  let action := Action.clientRequest scenario.source scenario.transaction
  let allowed := decide (Enabled state action)
  let actual := CCFRaft.next state action
  let transactions := [0, 5, 7, 99, 10^30]
  let before := frameObservations state transactions
  let event := Json.mkObj [
    ("kind", toJson "clientRequest"),
    ("node", toJson (nodeName scenario.source)),
    ("transaction", toJson scenario.transaction)]
  Json.mkObj [
    ("name", toJson scenario.name),
    ("stepIndex", toJson before.length),
    ("modelEnabled", toJson allowed),
    ("outputLength", toJson (actual.nodes scenario.source).log.length),
    ("outputMembership", toJson (membershipName (actual.nodes scenario.source).membershipState)),
    ("expected", toJson (if allowed then "sat" else "unsat")),
    ("trace", Json.mkObj [
      ("nodes", toJson (["a", "b", "c"] : List String)),
      ("bootstrap", toJson (["a", "b"] : List String)),
      ("instructions", toJson
        (before ++ [event] ++ if allowed then frameObservations actual transactions else []))])]

private def scenarios : List Scenario :=
  let signature (term : Nat) : Entry (Fin 3) Nat := { term, content := .signature }
  let transaction (term tx : Nat) : Entry (Fin 3) Nat :=
    { term, content := .transaction tx }
  let excluding : Entry (Fin 3) Nat := { term := 1, content := .reconfiguration {1, 2} }
  let terminal : Entry (Fin 3) Nat := { term := 1, content := .retiredCommitted {0} }
  [
    { name := "empty-log" },
    { name := "unsorted-log", log := [transaction 9 7, signature 1, transaction 3 0] },
    { name := "present-in-log-not-submitted", log := [transaction 9 5] },
    { name := "submitted-but-not-in-log", submitted := {5} },
    { name := "retirement-ordered", log := [excluding], commit := 0 },
    { name := "retirement-signed", log := [excluding, signature 1], commit := 0 },
    { name := "retirement-completed", log := [excluding, signature 1], commit := 2 },
    { name := "refreshed-terminal", log := [excluding, signature 1, terminal], commit := 3 },
    { name := "stale-metadata", membership := .retirementCompleted,
      retirement := some 7, retirementSignature := some 8, retired := some 0 },
    { name := "unallocated-source", present := {1, 2} },
    { name := "zero-transaction", transaction := 0, submitted := {7} },
    { name := "large-naturals", transaction := 10^30, currentTerm := 10^30, commit := 10^30 }
  ] ++
  ([Role.none, .follower, .preVoteCandidate, .candidate, .leader].map fun role =>
    { name := s!"role-{roleName role}", role }) ++
  ([MembershipState.active, .retirementOrdered, .retirementSigned,
      .retirementCompleted, .retiredCommitted].map fun membership =>
    { name := s!"membership-{membershipName membership}", membership }) ++
  ([1, 2].map fun source =>
    { name := s!"source-{source.val}", source }) ++
  ([0, 5, 10^30].flatMap fun tx =>
    ([({0, 7} : Finset Nat), {5, 7}, {}, {10^30}].zipIdx.map fun (submitted, index) =>
      { name := s!"submitted-{tx}-{index}", transaction := tx, submitted }))

def cases : List Json := scenarios.map fixture

end CCFRaft.NativeArrayClientRequestFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeArrayClientRequestFixtures.cases).compress
