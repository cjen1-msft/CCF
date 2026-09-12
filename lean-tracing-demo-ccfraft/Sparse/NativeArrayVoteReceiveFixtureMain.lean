-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayFixtureJson

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeArrayVoteReceiveFixtures

open Lean NativeArrayFixtures

private instance : Bootstrap (Fin 3) :=
  { configuration := {0, 1}, leader := 0, leader_mem := by simp }

def fixture (log : List (Entry (Fin 3) Nat)) (term : Nat) (chosen : Option (Fin 3))
    (source destination : Fin 3) (sourcePresent destinationPresent : Bool)
    (mode : Nat) (conflict : Bool) : Json :=
  let row : NodeState (Fin 3) Nat :=
    { (freshNodeState : NodeState (Fin 3) Nat) with
      role := .candidate, currentTerm := 5, log, commitIndex := 10 ^ 30, votedFor := chosen,
      votesGranted := {0, 2}, preVotesGranted := {1} }
  let request : RequestVoteRequest (Fin 3) :=
    { term, source, destination := if mode = 2 then 2 else destination,
      lastCommittableTerm := 4, lastCommittableIndex := 10 ^ 30 }
  let selected : List (Message (Fin 3) Nat) :=
    if mode = 1 then []
    else if mode = 3 then [.requestVoteResponse { term, source, destination, voteGranted := true }]
    else [.requestVoteRequest request, .requestVoteRequest request]
  let response : Message (Fin 3) Nat :=
    .requestVoteResponse { term := 5, source := destination, destination := source, voteGranted := false }
  let present : Finset (Fin 3) :=
    (if sourcePresent then {source} else {}) ∪ (if destinationPresent then {destination} else {})
  let state : State (Fin 3) Nat :=
    { nodes := NodeStore.ofFinset present fun _ => row
      network := fun node =>
        (if node = destination then selected ++ [.proposeVoteRequest { term := 2, source := 2, destination }]
          else []) ++
        (if node = source && !(mode == 1 && source == destination) then [response, response] else [])
      hasJoined := {0, 2}, submittedTxIds := {7}, preVoteStatus := fun _ => .enabled,
      retirementCompleted := fun _ => {1, 2} }
  let action := Action.receive source destination
  let allowed := decide (Enabled state action)
  let selectedVote := match takeFirstFrom source (state.network destination) with
    | some (.requestVoteRequest _, _) => true
    | _ => false
  let actual := CCFRaft.next state action
  let observed := if conflict then
      { actual with
        nodes := updateNode actual.nodes destination
          { (actual.nodes destination) with
            votedFor := if (actual.nodes destination).votedFor.isSome then none else some 2 } }
    else actual
  let event := Json.mkObj [("kind", toJson "receiveRequestVote"), ("source", toJson (nodeName source)),
    ("destination", toJson (nodeName destination))]
  Json.mkObj [
    ("modelEnabled", toJson allowed), ("selectedVoteRequest", toJson selectedVote),
    ("expected", toJson (if allowed && selectedVote && !conflict then "sat" else "unsat")),
    ("trace", Json.mkObj [("nodes", toJson (["a", "b", "c"] : List String)),
      ("bootstrap", toJson (["a", "b"] : List String)),
      ("instructions", toJson (frameObservations state [0, 7] ++ [event] ++ frameObservations observed [0, 7]))])]

def cases : List Json :=
  let logs : List (List (Entry (Fin 3) Nat)) := [
    [], [{ term := 3, content := .signature }], [{ term := 7, content := .transaction 99 }],
    [{ term := 3, content := .signature }, { term := 1, content := .signature }]]
  let normal := logs.flatMap fun log =>
    [4, 5, 6].flatMap fun term =>
      [none, some (0 : Fin 3), some 2].flatMap fun chosen =>
        ([(0, 1), (1, 1)] : List (Fin 3 × Fin 3)).flatMap fun (source, destination) =>
          [false, true].flatMap fun sourcePresent =>
            [false, true].map (fixture log term chosen source destination sourcePresent true 0)
  let malformed := [0, 1, 2, 3].flatMap fun mode =>
    [4, 5, 6].flatMap fun term =>
      ([(0, 1), (1, 1)] : List (Fin 3 × Fin 3)).flatMap fun (source, destination) =>
        [false, true].flatMap fun sourcePresent =>
          [false, true].flatMap fun destinationPresent =>
            [false, true].map (fixture [] term none source destination sourcePresent destinationPresent mode)
  normal ++ malformed

end CCFRaft.NativeArrayVoteReceiveFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeArrayVoteReceiveFixtures.cases).compress
