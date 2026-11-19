-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import ConsensusCoverage.StateCoverage
import ConsensusCoverage.FrontierWitnesses
import Consensus.Replay.Reduction

open Consensus Consensus.Replay ConsensusCoverage

private structure Score where
  states : List StateCoverage.Row := []
  edges : List FrontierRows.Row := []
  past : List Model.State := []

private def record [BEq α] (xs : List α) (x : α) := if xs.contains x then xs else x :: xs

private def start (cfg : CCF.Finset Nat) (s : Model.State) : Score :=
  { states := [StateCoverage.read cfg s []] }

private def visit (cfg : CCF.Finset Nat) (score : Score) (s t : Model.State) : Score :=
  let past := s :: score.past
  let edge := FrontierRows.historyLabel cfg s t score.past
  { states := record score.states (edge.zeroAfter, edge.backedAfter),
    edges := record score.edges edge, past }

private def report (states : List StateCoverage.Row) (edges : List FrontierRows.Row) : IO Unit := do
  let table := StateCoverage.activeTable
  let bits (xs : List Bool) := String.ofList (xs.map fun b => if b then '1' else '0')
  let key (row : StateCoverage.Row) := bits [row.1, row.2]
  let edgeKey (r : FrontierRows.Row) :=
    bits [r.zeroBefore, r.backedBefore, r.wonPrimary, r.zeroAfter, r.backedAfter]
  unless states.all (· ∈ table) do throw <| IO.userError "unexpected state on a nonempty replay"
  let missing := table.filter (· ∉ states)
  IO.println s!"{table.length - missing.length}/{table.length} reachable nonempty state profiles; missing: \
    {if missing.isEmpty then "none" else String.intercalate " " (missing.map key)}"
  unless edges.all (· ∈ FrontierRows.table) do throw <| IO.userError "unexpected projected step"
  let missing := FrontierRows.table.filter (· ∉ edges)
  IO.println s!"{FrontierRows.table.length - missing.length}/{FrontierRows.table.length} projected step rows \
    (state profiles + new primary); missing: \
    {if missing.isEmpty then "none" else String.intercalate " " (missing.map edgeKey)}"

private def fromCapture (file : String) : IO Score := do
  let records ← readLog file
  let result := do
    let (events, declared) ← prepareEvents (← records)
    let r ← reduce events declared
    foldActions r.header r.instructions (start r.header.bootstrap r.header.initial) (visit r.header.bootstrap)
  let (counts, score) ← IO.ofExcept (result.mapError fun error => s!"{file}: {error}")
  IO.println s!"{file}: {counts.actions} validated model actions, {counts.observations} replay observations"
  return score

def main : List String → IO Unit
  | ["check"] => do
    let some edges := FrontierRows.witnessRows | throw <| IO.userError "disabled witness schedule"
    let states := edges.flatMap fun r => [(r.zeroBefore, r.backedBefore), (r.zeroAfter, r.backedAfter)]
    report states edges
    unless StateCoverage.activeTable.all (· ∈ states) && FrontierRows.table.all (· ∈ edges) do
      throw <| IO.userError "incomplete model witnesses"
  | "trace" :: file :: more => do
    let scores ← (file :: more).mapM fromCapture
    report (scores.flatMap Score.states) (scores.flatMap Score.edges)
  | _ => throw <| IO.userError "usage: proof-coverage.lean check | trace FILE.ndjson [FILE.ndjson ...]"
