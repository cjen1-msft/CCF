-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendPacket
import Sparse.NativeScript

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeAppendPacketFixtures

open Lean NativeSmt NativeEncode

def fixture (index : Nat) (log : List (Entry (Fin 3) Nat)) (previous : Nat)
    (present moved agrees : Bool) (source destination : Fin 3) : Json :=
  let columns : Columns := if moved then { currentTerm := 25, sentIndex := 26 } else {}
  let row : NodeState (Fin 3) Nat :=
    { (freshNodeState : NodeState (Fin 3) Nat) with
      currentTerm := 10 ^ 30, log, commitIndex := 10 ^ 30 + 1, sentIndex := fun _ => previous }
  let state : State (Fin 3) Nat :=
    { nodes := NodeStore.ofFinset (if present then {source} else {}) (fun _ => row)
      network := fun _ => [], submittedTxIds := {}, hasJoined := {} }
  let expected := makeAppendEntriesRequest state source destination
    (min ((state.nodes source).sentIndex destination + 1) (state.nodes source).log.length)
  let equality : Expr .bool :=
    .equal (appendPacketTerm (width := 3) columns source destination) (packetTerm (width := 3) (.appendEntriesRequest expected))
  let assertions : List (Expr .bool) := [
    .equal (allocated columns source.val) (.boolean present),
    .equal (.select (.free (.array .int .int) 3) (.integer source.val)) (.integer log.length),
    .equal (.select (.free (.array .int .int) 4) (.integer source.val)) (.integer row.commitIndex),
    .equal (.select (.free (.array .int .int) columns.currentTerm) (.integer source.val)) (.integer row.currentTerm),
    .equal (.select (.select (.free (.array .int (.array .int .int)) columns.sentIndex)
      (.integer source.val)) (.integer destination.val)) (.integer previous),
    .equal (.select (.free (.array .int (.array .int (entryTy 3))) 6) (.integer source.val)) (.snd (logTerm log)),
    if agrees then equality else .not equality]
  let poisoned := if moved then [
    Term.equal (.select (.free (.array .int .int) 5) (.integer source.val)) (.integer (row.currentTerm + 1)),
    Term.equal (.select (.select (.free (.array .int (.array .int .int)) 14)
      (.integer source.val)) (.integer destination.val)) (.integer (previous + 1))] else []
  Json.mkObj [("name", toJson s!"append-packet-{index}-{previous}-{present}-{moved}-{agrees}-{source.val}-{destination.val}"),
    ("script", toJson (renderScript (assertions ++ poisoned))), ("expected", toJson (if agrees then "sat" else "unsat"))]

def rawFixture (term txId : Int) (agrees : Bool) : Json :=
  let raw : Expr (entryTy 3) := .pair (.integer term) (.inr (.inl (.integer txId)))
  let expected : Entry (Fin 3) Nat := { term := term.toNat, content := .transaction txId.toNat }
  let equality : Expr .bool := .equal (normalizedEntryTerm raw) (entryTerm expected)
  Json.mkObj [("name", toJson s!"append-normalized-entry-{term}-{txId}-{agrees}"),
    ("script", toJson (renderScript [if agrees then equality else .not equality])),
    ("expected", toJson (if agrees then "sat" else "unsat"))]

def cases : List Json :=
  let entries : List (Entry (Fin 3) Nat) :=
    [{ term := 7, content := .signature }, { term := 1, content := .transaction (10 ^ 30) },
      { term := 2, content := .reconfiguration {0, 2} }, { term := 0, content := .retiredCommitted {1} }]
  let logs := [[]] ++ entries.map (fun entry => [entry]) ++
    entries.flatMap fun left => entries.map fun right => [left, right]
  let packets := logs.zipIdx.flatMap fun (log, index) =>
    [0, 1, 2, 3, 10 ^ 30].flatMap fun previous =>
      [false, true].flatMap fun present =>
        [false, true].flatMap fun moved =>
          [false, true].flatMap fun agrees =>
            ([(0, 1), (2, 0), (1, 1)] : List (Fin 3 × Fin 3)).map fun (source, destination) =>
              fixture index log previous present moved agrees source destination
  let raw := ([-3, 0, 10 ^ 30] : List Int).flatMap fun term =>
    ([-9, 0, 10 ^ 30] : List Int).flatMap fun txId =>
      [false, true].map (rawFixture term txId)
  packets ++ raw

end CCFRaft.NativeAppendPacketFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeAppendPacketFixtures.cases).compress
