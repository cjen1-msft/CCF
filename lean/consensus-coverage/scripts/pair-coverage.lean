-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import ConsensusCoverage.PairWitnesses
import ConsensusCoverage.Snapshot
import Lean.Data.Json

open Lean ConsensusCoverage.PairQuestions

deriving instance FromJson, ToJson for Sample

private abbrev Row := Bool × Bool × Bool

private def bits (row : Row) : String :=
  String.ofList ([row.1, row.2.1, row.2.2].map fun b => if b then '1' else '0')

private def score (states : List (List Sample)) : Except String (List Row) := do
  let first :: _ :: _ := states | throw "need at least two snapshots"
  let ids := (first.map Sample.id).mergeSort
  if !ids.Nodup then throw "snapshot 1: duplicate node ID"
  for (s, i) in states.tail.zipIdx 2 do
    unless (s.map Sample.id).mergeSort == ids do
      throw s!"snapshot {i}: expected the same node IDs exactly once each"
  (states.zip states.tail).zipIdx 1 |>.mapM fun ((s, t), i) => do
    let row := snapshotLabel s t
    unless row ∈ table do throw s!"step {i}: unreachable proof row {bits row}"
    return row

private def report (runs : List (String × List Row)) : IO Unit := do
  for (name, rows) in runs do
    IO.println s!"{name}: {rows.length} steps, rows: {String.intercalate " " (rows.map bits)}"
  let hits := (runs.flatMap Prod.snd).eraseDups
  let missing := (table.filter (· ∉ hits)).map bits
  IO.println s!"{hits.length}/{table.length} reachable rows covered; missing: \
    {if missing.isEmpty then "none" else String.intercalate " " missing}"

private def scoreJson (value : Json) : Except String (List Row) := do
  score (← fromJson? value)

def main : List String → IO Unit
  | ["check"] => do
    let some traces := examples | throw <| IO.userError "model witness disabled"
    let runs ← traces.zipIdx.mapM fun (states, i) => do
      let actual ← IO.ofExcept (scoreJson (toJson (states.map snapshot)))
      let expected := (states.zip states.tail).map fun (s, t) => label s t
      unless actual == expected do throw <| IO.userError "snapshot/proof label mismatch"
      return (s!"model run {i + 1}", actual)
    report runs
    unless table.all (fun r => (runs.flatMap Prod.snd).contains r) do
      throw <| IO.userError "model witnesses missed a reachable row"
  | "trace" :: path :: paths => do
    let runs ← (path :: paths).mapM fun (file : String) => do
      let data ← IO.FS.readFile file
      let rows ← IO.ofExcept ((Json.parse data >>= scoreJson).mapError (s!"{file}: {·}"))
      return (file, rows)
    report runs
  | _ => throw <| IO.userError "usage: pair-coverage.lean check | trace FILE [FILE ...]"
