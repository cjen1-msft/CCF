-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeVotePacket
import Sparse.NativeScript
import Lean.Data.Json

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeVotePacketFixtures

open Lean NativeSmt NativeEncode

def entries : List (Entry (Fin 3) Nat) :=
  [{ term := 9, content := .signature },
    { term := 10 ^ 30, content := .transaction 7 },
    { term := 2, content := .reconfiguration {0, 2} },
    { term := 0, content := .retiredCommitted {1} }]

def fixture (name : String) (log : List (Entry (Fin 3) Nat)) (committed : Nat)
    (present preVote agrees : Bool) (source destination : Fin 3) (termColumn : Nat) : Json :=
  let current := if committed = 0 then 0 else 10 ^ 30 + committed
  let columns : Columns := { currentTerm := termColumn }
  let state : State (Fin 3) Nat :=
    { nodes := NodeStore.ofFinset (if present then {source} else {}) fun _ =>
        { (freshNodeState : NodeState (Fin 3) Nat) with currentTerm := current, log, commitIndex := committed }
      network := fun _ => []
      submittedTxIds := {}
      hasJoined := {}
      preVoteStatus := fun _ => .capable }
  let expected : Message (Fin 3) Nat :=
    if preVote then .requestPreVote (makeRequestPreVote state source destination)
    else .requestVoteRequest (makeRequestVoteRequest state source destination)
  let equality : Expr .bool := .equal
    (votePacketTerm (width := 3) columns preVote source destination (.free .int 24)) (packetTerm (width := 3) expected)
  let assertions : List (Expr .bool) := [
    .equal (allocated source.val) (.boolean present),
    .equal (.select (.free (.array .int .int) 3) (.integer source.val)) (.integer log.length),
    .equal (.select (.free (.array .int .int) 4) (.integer source.val)) (.integer committed),
    .equal (.select (.free (.array .int .int) 5) (.integer source.val))
      (.integer (if termColumn = 5 then current else current + 1)),
    .equal (.select (.free (.array .int .int) termColumn) (.integer source.val)) (.integer current),
    .equal (.select (.free (.array .int (.array .int (entryTy 3))) 6) (.integer source.val))
      (.snd (logTerm log)),
    signatureIndexTerm 3 source.val (.free .int 24),
    if agrees then equality else .not equality]
  Json.mkObj [("name", toJson name), ("script", toJson (renderScript assertions)),
    ("expected", toJson (if agrees then "sat" else "unsat"))]

def rawTermFixture (raw index : Int) (agrees : Bool) : Json :=
  let log : List (Entry (Fin 3) Nat) := [{ term := raw.toNat, content := .signature }]
  let equality : Expr .bool := .equal (logTermAt 3 0 (.integer index))
    (.integer (CCFRaft.termAt log index.toNat))
  let assertions : List (Expr .bool) := [
    .equal (allocated 0) (.boolean true),
    .equal (length 0) (.integer 1),
    .equal (entryAt 3 0 (.integer 0)) (.pair (.integer raw) (.inl .unit)),
    if agrees then equality else .not equality]
  Json.mkObj [("name", toJson s!"vote-raw-term-{raw}-{index}-{agrees}"),
    ("script", toJson (renderScript assertions)),
    ("expected", toJson (if agrees then "sat" else "unsat"))]

def cases : List Json :=
  let logs := [[]] ++ entries.map (fun entry => [entry]) ++
    entries.flatMap (fun left => entries.map fun right => [left, right])
  let pairs : List (Fin 3 × Fin 3) := [(0, 1), (2, 0), (1, 1)]
  let packets := logs.zipIdx.flatMap fun (log, index) =>
    [0, 1, 2, 3, 10 ^ 30].flatMap fun committed =>
      [false, true].flatMap fun present =>
        [false, true].flatMap fun preVote =>
          pairs.flatMap fun (source, destination) =>
            [false, true].flatMap fun agrees =>
              [5, 25].map fun termColumn =>
                fixture s!"vote-packet-{index}-{committed}-{present}-{preVote}-{source.val}-{destination.val}-{agrees}-{termColumn}"
                  log committed present preVote agrees source destination termColumn
  let rawTerms := ([-9, 0, 1, 10 ^ 30] : List Int).flatMap fun raw =>
    ([-1, 0, 1, 2, 10 ^ 30] : List Int).flatMap fun index =>
      [false, true].map fun agrees => rawTermFixture raw index agrees
  packets ++ rawTerms

end CCFRaft.NativeVotePacketFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeVotePacketFixtures.cases).compress
