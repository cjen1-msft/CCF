-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayFixtureJson

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeArrayAppendReceiveFixtures

open Lean NativeArrayFixtures

private instance : Bootstrap (Fin 3) :=
  { configuration := {0, 1}, leader := 0, leader_mem := by simp }

structure Scenario where
  name : String
  log : List (Entry (Fin 3) Nat) := []
  entries : List (Entry (Fin 3) Nat) := []
  previous : Nat := 0
  previousTerm : Nat := 0
  commit : Nat := 0
  leaderCommit : Nat := 10 ^ 30

def branch (state : State (Fin 3) Nat) (source destination : Fin 3) : String :=
  if !decide (state.allocated destination) then "unallocated"
  else match takeFirstFrom source (state.network destination) with
  | none => "empty"
  | some (.appendEntriesRequest request, _) =>
    let row := state.nodes destination
    if request.destination != destination then "wrongDestination"
    else if (returnToFollowerState? row request).isSome then "stepdown"
    else if !(handleAppendEntriesRequest? row request).isSome then "blocked"
    else if (rejectAppendEntriesRequest? row request).isSome then "reject"
    else if (appendEntriesAlreadyDone? row request).isSome then "alreadyDone"
    else if (noConflictAppendEntriesRequest? row request).isSome then "extension"
    else "conflict"
  | some _ => "wrongKind"

def fixture (scenario : Scenario) (role : Role) (isNewFollower : Bool) (term : Nat)
    (source destination : Fin 3) (sourcePresent destinationPresent : Bool)
    (mode : Nat) (conflict : Bool) : Json :=
  let row : NodeState (Fin 3) Nat :=
    { (freshNodeState : NodeState (Fin 3) Nat) with
      role, isNewFollower, currentTerm := 5, log := scenario.log, commitIndex := scenario.commit,
      votedFor := some 2, votesGranted := {0, 2}, preVotesGranted := {1},
      retirementIndex := some 99, retirementCommittableIndex := some 88,
      retiredCommittedIndex := some 77, sentIndex := fun _ => 9, matchIndex := fun _ => 8 }
  let request : AppendEntriesRequest (Fin 3) Nat :=
    { term, source, destination := if mode = 2 then 2 else destination,
      prevLogIndex := scenario.previous, prevLogTerm := scenario.previousTerm,
      leaderCommit := scenario.leaderCommit, entries := scenario.entries }
  let selected : List (Message (Fin 3) Nat) :=
    if mode = 1 then []
    else if mode = 3 then
      [.requestVoteRequest { term, source, destination, lastCommittableTerm := 0, lastCommittableIndex := 0 }]
    else [.appendEntriesRequest request, .appendEntriesRequest request]
  let response : Message (Fin 3) Nat :=
    .appendEntriesResponse
      { term := 2, source := destination, destination := source, success := false, lastLogIndex := 42 }
  let present : Finset (Fin 3) :=
    (if sourcePresent then {source} else {}) ∪ (if destinationPresent then {destination} else {})
  let state : State (Fin 3) Nat :=
    { nodes := NodeStore.ofFinset present fun _ => row
      network := fun node =>
        (if node = destination then
          [.proposeVoteRequest { term := 2, source := 2, destination }] ++ selected else []) ++
        (if node = source && !(mode == 1 && source == destination) then [response, response] else [])
      hasJoined := {0, 2}, submittedTxIds := {7}, preVoteStatus := fun _ => .enabled,
      retirementCompleted := fun _ => {0, 2} }
  let action := Action.receive source destination
  let allowed := decide (Enabled state action)
  let selectedAppend := match takeFirstFrom source (state.network destination) with
    | some (.appendEntriesRequest _, _) => true
    | _ => false
  let actual := CCFRaft.next state action
  let observed := if conflict then
      { actual with
        nodes := updateNode actual.nodes destination
          { (actual.nodes destination) with currentTerm := (actual.nodes destination).currentTerm + 1 } }
    else actual
  let event := Json.mkObj [("kind", toJson "receiveAppendEntries"), ("source", toJson (nodeName source)),
    ("destination", toJson (nodeName destination))]
  Json.mkObj [
    ("scenario", toJson scenario.name), ("branch", toJson (branch state source destination)),
    ("modelEnabled", toJson allowed), ("selectedAppendRequest", toJson selectedAppend),
    ("expected", toJson (if allowed && selectedAppend && !conflict then "sat" else "unsat")),
    ("trace", Json.mkObj [("nodes", toJson (["a", "b", "c"] : List String)),
      ("bootstrap", toJson (["a", "b"] : List String)),
      ("instructions", toJson (frameObservations state [0, 7] ++ [event] ++ frameObservations observed [0, 7]))])]

def scenarios : List Scenario :=
  let signature : Entry (Fin 3) Nat := { term := 3, content := .signature }
  let transaction : Entry (Fin 3) Nat := { term := 2, content := .transaction 7 }
  let earlierSignature : Entry (Fin 3) Nat := { term := 1, content := .signature }
  let replacement : Entry (Fin 3) Nat := { term := 3, content := .transaction 8 }
  let configuration : Entry (Fin 3) Nat := { term := 4, content := .reconfiguration {0} }
  [
    { name := "empty" },
    { name := "matching", log := [signature], entries := [signature] },
    { name := "same-term-different-content", log := [signature], entries := [replacement] },
    { name := "extension", log := [signature], entries := [signature, transaction, configuration] },
    { name := "term-conflict", log := [signature, transaction], entries := [signature, earlierSignature] },
    { name := "shifted-conflict", log := [signature, transaction],
      previous := 1, previousTerm := 3, entries := [signature, configuration] },
    { name := "same-term-content-conflict-extension", log := [signature], entries := [replacement, transaction] },
    { name := "retained-tail", log := [signature, transaction], previous := 1, previousTerm := 3 },
    { name := "commit-signature", log := [signature, transaction, earlierSignature],
      previous := 1, previousTerm := 3, entries := [transaction, earlierSignature] },
    { name := "missing-previous", log := [signature, transaction], previous := 10 ^ 30, previousTerm := 3 },
    { name := "committed-prefix", log := [signature], entries := [signature, transaction], commit := 1 },
    { name := "retirement-refresh", log :=
        [configuration, signature, { term := 2, content := .retiredCommitted {1} }, earlierSignature],
      previous := 3, previousTerm := 2, entries := [earlierSignature], commit := 3 }
  ]

def cases : List Json :=
  let normal := scenarios.flatMap fun scenario =>
    [.follower, .candidate, .preVoteCandidate, .leader].flatMap fun role =>
      [false, true].flatMap fun isNewFollower =>
        [4, 5, 6].flatMap fun term =>
          ([(0, 1), (1, 1)] : List (Fin 3 × Fin 3)).flatMap fun (source, destination) =>
            [false, true].map (fixture scenario role isNewFollower term source destination true true 0)
  let malformed := [0, 1, 2, 3].flatMap fun mode =>
    [4, 5, 6].flatMap fun term =>
      ([(0, 1), (1, 1)] : List (Fin 3 × Fin 3)).flatMap fun (source, destination) =>
        [false, true].flatMap fun sourcePresent =>
          [false, true].flatMap fun destinationPresent =>
            [false, true].map (fixture { name := "queue-and-allocation" } .candidate false term
              source destination sourcePresent destinationPresent mode)
  normal ++ malformed

end CCFRaft.NativeArrayAppendReceiveFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeArrayAppendReceiveFixtures.cases).compress
