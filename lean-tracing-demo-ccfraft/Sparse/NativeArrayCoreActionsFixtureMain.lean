-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayFixtureJson
import Sparse.NativeNodeRowFixtureTerms

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeArrayCoreActionFixtures

open Lean NativeArrayFixtures

private instance : Bootstrap (Fin 3) :=
  { configuration := {0, 1}, leader := 0, leader_mem := by simp }

inductive Command where
  | membership (configuration : Finset (Fin 3))
  | append
  | appendReceive
  | vote
  | voteReceive
  | update (source destination : Fin 3)

def event (state : State (Fin 3) Nat) (command : Command) : Action (Fin 3) Nat × Json :=
  let directed (kind : String) (source destination : Fin 3) : List (String × Json) :=
    [("kind", toJson kind), ("source", toJson (nodeName source)),
      ("destination", toJson (nodeName destination))]
  match command with
  | .membership configuration =>
    (.changeConfiguration 0 configuration,
      Json.mkObj [("kind", toJson "changeConfiguration"), ("source", toJson "a"),
        ("configuration", toJson (nodeNames configuration))])
  | .append =>
    let batchEnd := min ((state.nodes 0).sentIndex 2 + 1) (state.nodes 0).log.length
    (.appendEntries 0 2 batchEnd,
      Json.mkObj (directed "appendEntries" 0 2 ++ [("batchEnd", toJson batchEnd)]))
  | .appendReceive => (.receive 0 2, Json.mkObj (directed "receiveAppendEntries" 0 2))
  | .vote => (.requestVote 1 0, Json.mkObj (directed "requestVote" 1 0))
  | .voteReceive => (.receive 1 0, Json.mkObj (directed "receiveRequestVote" 1 0))
  | .update source destination =>
    (.updateTerm source destination, Json.mkObj (directed "updateTerm" source destination))

def fixture (present : Bool) (mode mutation : Nat) : Json := Id.run do
  let row : NodeState (Fin 3) Nat :=
    { (freshNodeState : NodeState (Fin 3) Nat) with
      role := .leader, currentTerm := 3,
      log := [{ term := 3, content := .signature }], commitIndex := 1,
      retirementIndex := some 99, retirementCommittableIndex := some 88,
      retiredCommittedIndex := some 77 }
  let initial : State (Fin 3) Nat :=
    { nodes := NodeStore.ofFinset (if present then {0, 1, 2} else {0, 1}) fun node =>
        if node = 0 then row
        else if node = 1 then { row with role := .candidate, currentTerm := 4 }
        else { row with role := .follower, currentTerm := 0 }
      network := fun _ => []
      hasJoined := if mode = 3 then {} else {0, 1}
      submittedTxIds := {7}, retirementCompleted := fun _ => {1} }
  let commands : List Command :=
    [.membership {0, 1, 2}] ++
    (if mode = 1 then [.membership {0, 1, 2}] else []) ++
    [.append, .update 0 2, .appendReceive,
      .membership {0, 2}, .append, .appendReceive] ++
    (if mode = 2 || mode = 3 then [.membership {0, 1, 2}] else []) ++
    [.vote, .update 1 0, .voteReceive]
  let mut state := initial
  let mut instructions := frameObservations initial [7, 9]
  let mut enabled := true
  let mut disabled := #[]
  for (command, index) in commands.zipIdx do
    let (action, instruction) := event state command
    let allowed := decide (Enabled state action)
    enabled := enabled && allowed
    unless allowed do disabled := disabled.push index
    state := CCFRaft.next state action
    let observed := if index + 1 = commands.length && mutation != 0 then
        if mutation = 22 then
          { state with nodes := NodeStore.ofFinset ({1, 2} : Finset (Fin 3)) state.nodes }
        else NativeNodeRowWriteFixtures.mutate state 0 mutation
      else state
    instructions := instructions ++ [instruction] ++ frameObservations observed [7, 9]
  return Json.mkObj [
    ("present", toJson present), ("mode", toJson mode), ("mutation", toJson mutation),
    ("modelEnabled", toJson enabled), ("disabledSteps", toJson disabled),
    ("expected", toJson (if enabled && mutation = 0 then "sat" else "unsat")),
    ("trace", Json.mkObj [
      ("nodes", toJson (["a", "b", "c"] : List String)),
      ("bootstrap", toJson (["a", "b"] : List String)),
      ("instructions", toJson instructions)])]

def cases : List Json :=
  [false, true].flatMap fun present =>
    (List.range 4).flatMap fun mode =>
      (List.range 23).map fun mutation => fixture present mode mutation

end CCFRaft.NativeArrayCoreActionFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeArrayCoreActionFixtures.cases).compress
