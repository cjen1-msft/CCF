-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendReceiveTerms
import Sparse.NativeAppendReceiveFixtureInstructions

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeAppendReceiveGuardFixtures

open Lean NativeSmt NativeEncode NativeAppendReceiveFixtures

def modelFixture (index : Nat) (item : Json) : Except String Json := do
  let input <- decodeDocumentWith fixtureInstruction (<- field item "trace")
  let program : EncodeM input.width Unit := do
    initialFrameDomains input.width
    for instruction in input.instructions do
      match instruction with
      | .inr (source, destination) =>
        assertAll (appendReceiveGuards (<- get).toColumns source destination)
        return ()
      | .inl observation => frameInstruction observation
    throw "append receive guard fixture has no receiveAppendEntries instruction"
  let (_, final) <- program.run (initialEncoding input.width input.bootstrap)
  let enabled <- (<- field item "modelEnabled").getBool?
  let selectedAppend <- (<- field item "selectedAppendRequest").getBool?
  return Json.mkObj [("name", toJson s!"append-receive-guard-model-{index}"),
    ("script", toJson (renderScript final.assertions.toList)), ("branch", <- field item "branch"),
    ("expected", toJson (if enabled && selectedAppend then "sat" else "unsat"))]

def request (term : Nat) (source destination : Fin 3) : Message (Fin 3) Nat :=
  .appendEntriesRequest
    { term, source, destination, prevLogIndex := 0, prevLogTerm := 10 ^ 30,
      leaderCommit := 10 ^ 30, entries := [] }

def rawPackets : List (Expr (packetTy 3) × Bool) :=
  [(packetTerm (width := 3) (request 5 0 1), true),
    (packetTerm (width := 3) (request 4 0 1), true),
    (packetTerm (width := 3) (request 6 0 1), false),
    (packetTerm (width := 3) (request 5 2 1), false),
    (packetTerm (width := 3) (request 5 0 2), false),
    (packetTerm (width := 3) (.requestVoteRequest
      { term := 5, source := 0, destination := 1, lastCommittableTerm := 0, lastCommittableIndex := 0 }), false)]

def rawFixture (index : Nat) (packet : Expr (packetTy 3)) (enabled : Bool) (head count : Int) : Json :=
  let cell := fun (position : Expr .int) => .select
    (queueCellsTerm (width := 3) 23 (.integer 1) (.integer 0)) position
  let assertions : List (Expr .bool) := [
    .equal (allocated {} 0) (.boolean false), .equal (allocated {} 1) (.boolean true),
    .equal (read {} 1 1 (.integer 0)) (.integer (roleCode .candidate)),
    .equal (read {} 5 1 (.integer 0)) (.integer 5),
    .equal (length {} 1) (.integer 0), .equal (commit {} 1) (.integer (10 ^ 30)),
    .equal (.select (.select (.free (.array .int (.array .int .int)) 21) (.integer 1)) (.integer 0))
      (.integer count),
    .equal (.select (.select (.free (.array .int (.array .int .int)) 22) (.integer 1)) (.integer 0))
      (.integer head),
    .equal (cell (.integer head.toNat)) packet]
  let trap := if head < 0 then
      [Term.equal (cell (.integer head)) (packetTerm (width := 3) (request 99 0 1))]
    else []
  Json.mkObj [("name", toJson s!"append-receive-guard-raw-{index}-{head}-{count}"),
    ("script", toJson (renderScript (assertions ++ trap ++ appendReceiveGuards (width := 3) {} 0 1))),
    ("expected", toJson (if enabled && 0 < count then "sat" else "unsat"))]

def cases (input : Json) : Except String (List Json) := do
  let models <- ((<- input.getArr?).toList.zipIdx).mapM fun (item, index) => modelFixture index item
  let raw := rawPackets.zipIdx.flatMap fun ((packet, enabled), index) =>
    ([-9, 0, 10 ^ 30] : List Int).flatMap fun head =>
      ([-1, 0, 1, 10 ^ 30] : List Int).map fun count => rawFixture index packet enabled head count
  return models ++ raw

end CCFRaft.NativeAppendReceiveGuardFixtures

def main : IO Unit := do
  let input <- (<- IO.getStdin).readToEnd
  let result := do
    let parsed <- Lean.Json.parse input
    CCFRaft.NativeAppendReceiveGuardFixtures.cases parsed
  match result with
  | .ok fixtures => IO.println (Lean.toJson fixtures).compress
  | .error error => throw (IO.userError error)
