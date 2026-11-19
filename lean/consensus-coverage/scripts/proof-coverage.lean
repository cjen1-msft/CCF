-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import ConsensusCoverage.StateCoverage
import ConsensusCoverage.PairWitnesses
import Consensus.Replay.Reduction

open Consensus Consensus.Replay ConsensusCoverage

private structure Score where
  states : List StateCoverage.Row := []
  past : List Model.State := []

private def record [BEq α] (xs : List α) (x : α) := if xs.contains x then xs else x :: xs

private def start (cfg : CCF.Finset Nat) (s : Model.State) : Score :=
  { states := [StateCoverage.read cfg s []] }

private def visit (cfg : CCF.Finset Nat) (score : Score) (s t : Model.State) : Score :=
  let past := s :: score.past
  { states := record score.states (StateCoverage.read cfg t past), past }

private def report (states : List StateCoverage.Row) : IO Unit := do
  let table := StateCoverage.activeTable
  let key (row : StateCoverage.Row) :=
    s!"{if row.1 then 1 else 0}{if row.2 then 1 else 0}"
  unless states.all (· ∈ table) do throw <| IO.userError "unexpected state on a nonempty replay"
  let missing := table.filter (· ∉ states)
  IO.println s!"{table.length - missing.length}/{table.length} reachable nonempty state profiles; missing: \
    {if missing.isEmpty then "none" else String.intercalate " " (missing.map key)}"

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
    let some runs := PairQuestions.examples | throw <| IO.userError "disabled witness schedule"
    let mut keys := []
    for ss in runs do
      let first :: _ := ss | throw <| IO.userError "empty witness"
      let score := (ss.zip ss.tail).foldl (fun acc (s,t) => visit {0, 1} acc s t) (start {0, 1} first)
      keys := score.states ++ keys
    report keys
    unless StateCoverage.activeTable.all (· ∈ keys) do throw <| IO.userError "incomplete state witnesses"
  | "trace" :: file :: more => do
    let scores ← (file :: more).mapM fromCapture
    report (scores.flatMap Score.states)
  | _ => throw <| IO.userError "usage: proof-coverage.lean check | trace FILE.ndjson [FILE.ndjson ...]"
