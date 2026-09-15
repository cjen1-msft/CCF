-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayFixtureJson

set_option autoImplicit false

namespace CCFRaft.FiniteBlockOracle

open Lean NativeArrayFixtures

private instance : Bootstrap (Fin 3) :=
  { configuration := {0, 1}, leader := 0, leader_mem := by simp }

def runCase (count initialLength offset mask : Nat) : Except String Json := do
  let transaction := fun value => ({ term := 5, content := .transaction value } : Entry (Fin 3) Nat)
  let oldLog := (List.range initialLength).map fun i => transaction ((i + offset) % 8)
  let fresh : NodeState (Fin 3) Nat := freshNodeState
  let row : NodeState (Fin 3) Nat := {
    fresh with role := .follower, currentTerm := 5, log := oldLog, isNewFollower := false }
  let mut messages : List (Message (Fin 3) Nat) := []
  let mut wantedLength := initialLength
  for index in List.range count do
    let accept := mask.testBit index
    let previous := wantedLength + if accept then 0 else 1
    messages := messages ++ [.appendEntriesRequest {
      term := 5, source := 0, destination := 1, prevLogIndex := previous, prevLogTerm := 5,
      leaderCommit := 0, entries := [transaction ((index + offset) % 8)] }]
    wantedLength := wantedLength + if accept then 1 else 0
  let mut state : State (Fin 3) Nat := {
    nodes := NodeStore.ofFinset {0, 1} fun node => if node == 1 then row else
      { fresh with role := .leader, currentTerm := 5, isNewFollower := false },
    network := fun node => if node == 1 then messages else [],
    submittedTxIds := {},
    hasJoined := {0, 1} }
  for index in List.range count do
    let action := Action.receive (0 : Fin 3) 1
    unless decide (Enabled state action) do throw "oracle action unexpectedly disabled"
    let accept := mask.testBit index
    let log := if accept then (state.nodes 1).log ++ [transaction ((index + offset) % 8)]
      else (state.nodes 1).log
    let response : Message (Fin 3) Nat := .appendEntriesResponse {
      term := 5, source := 1, destination := 0, success := accept, lastLogIndex := log.length }
    let expectedRow := { (state.nodes 1) with log := log }
    let expected : State (Fin 3) Nat := { state with
      nodes := state.nodes.set 1 expectedRow
      network := fun node => if node == 1 then (state.network 1).drop 1
        else if node == 0 then state.network 0 ++ [response] else state.network node }
    let actual := CCFRaft.next state action
    unless frameObservations actual (List.range 8) == frameObservations expected (List.range 8) do
      throw s!"finite receive slice disagrees with Model: {count}/{initialLength}/{offset}/{mask}/{index}"
    state := actual
  let values <- (state.nodes 1).log.mapM fun entry => match entry.content with
    | .transaction value => pure value
    | _ => throw "unexpected non-transaction log entry"
  return Json.mkObj [
    ("receives", toJson count), ("initialLength", toJson initialLength),
    ("offset", toJson offset), ("mask", toJson mask),
    ("initialLog", toJson (oldLog.map entryJson)),
    ("requests", toJson (messages.map messageJson)),
    ("finalLength", toJson (state.nodes 1).log.length), ("finalValues", toJson values),
    ("responses", toJson ((state.network 0).map messageJson))]

end CCFRaft.FiniteBlockOracle

def main : IO UInt32 := do
  let result : Except String Lean.Json := do
    let mut rows := #[]
    for count in [1, 2, 3, 4, 5] do
      for length in [0, 1, 2, 3] do
        for offset in List.range 8 do
          for mask in List.range (2 ^ count) do
            rows := rows.push (← CCFRaft.FiniteBlockOracle.runCase count length offset mask)
    return Lean.toJson rows
  match result with
  | .ok output => IO.println output.compress; return 0
  | .error error => (← IO.getStderr).putStrLn error; return 2
