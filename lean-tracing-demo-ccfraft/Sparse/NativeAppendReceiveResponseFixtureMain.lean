-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendReceiveResponse
import Sparse.NativeAppendReceiveResponseScenarios
import Sparse.NativeLogSummaryTerms
import Sparse.NativeNodeRowFixtureTerms

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeAppendReceiveResponseFixtures

open Lean NativeSmt NativeEncode NativeNodeRowWriteFixtures

def fixture (scenario : Scenario) (source destination : Fin 3) (witness mutation : Nat) :
    Except String Json := do
  let row : NodeState (Fin 3) Nat :=
    { (freshNodeState : NodeState (Fin 3) Nat) with
      role := .follower, currentTerm := 5
      log := scenario.terms.map fun term => { term, content := .signature } }
  let request : AppendEntriesRequest (Fin 3) Nat :=
    { term := scenario.term, source, destination
      prevLogIndex := scenario.previous, prevLogTerm := scenario.previousTerm
      leaderCommit := 0, entries := scenario.entries }
  let some (_, response) := handleAppendEntriesRequest? row request
    | throw s!"response fixture has no Model handler: {scenario.name}"
  let usesHint := !response.success && scenario.hint
  let best := findHighestPossibleMatch row.log request.prevLogIndex request.prevLogTerm
  let selected : Int := if usesHint then
      if witness = 0 then best else if witness = 1 then -11 else best + 1
    else if witness = 0 then -11 else if witness = 1 then 0 else 10 ^ 30
  let observed := { response with
    term := response.term + if mutation = 1 then 1 else 0
    lastLogIndex := response.lastLogIndex + if mutation = 2 then 1 else 0 }
  let values := rowTerms row
  let tail := entryTerm (width := 3) { term := 0, content := .signature }
  let values := { values with
    logEntries :=
      .store (.store values.logEntries (.integer (-1)) tail) (.integer row.log.length) tail }
  let program : EncodeM 3 Unit := do
    writeNodeRow destination values
    let columns := (<- get).toColumns
    let packet := packetTerm (width := 3) (.appendEntriesRequest request)
    let hint := appendReceiveNackHint (width := 3) columns destination packet
    assertion (.equal hint (.boolean (if mutation = 3 then !scenario.hint else scenario.hint)))
    assertion (implies (.and (appendReceiveTerms (width := 3) columns destination packet).rejects hint)
      (nackMatchTerm 3 (length columns destination.val)
        (.select (.free (.array .int (.array .int (entryTy 3))) columns.logEntries)
          (.integer destination.val))
        (.integer request.prevLogIndex) (.integer request.prevLogTerm) (.integer selected)))
    assertion (.equal
      (appendReceiveResponseTerm (width := 3) columns source destination packet (.integer selected))
      (packetTerm (width := 3) (.appendEntriesResponse observed)))
  let (_, final) <- program.run (initialEncoding 3 {0, 1})
  return Json.mkObj [
    ("name", toJson s!"append-receive-response-{scenario.name}-{source.val}-{destination.val}-{witness}-{mutation}"),
    ("scenario", toJson scenario.name), ("hinted", toJson usesHint),
    ("ack", toJson response.success), ("self", toJson (source == destination)),
    ("selected", toJson selected), ("responseTerm", toJson response.term),
    ("responseIndex", toJson response.lastLogIndex),
    ("script", toJson (renderScript final.assertions.toList)),
    ("expected", toJson (if mutation = 0 && (!usesHint || witness = 0) then "sat" else "unsat"))]

def cases : Except String (List Json) :=
  scenarios.flatMapM fun scenario =>
    ([(0, 1), (1, 0), (2, 2)] : List (Fin 3 × Fin 3)).flatMapM fun (source, destination) =>
      (List.range 3).flatMapM fun witness =>
        (List.range 4).mapM fun mutation => fixture scenario source destination witness mutation

end CCFRaft.NativeAppendReceiveResponseFixtures

def main : IO Unit :=
  match CCFRaft.NativeAppendReceiveResponseFixtures.cases with
  | .ok result => IO.println (Lean.toJson result).compress
  | .error error => throw (IO.userError error)
