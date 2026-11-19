-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import ConsensusCoverage.StateCoverage
import ConsensusCoverage.FrontierWitnesses
import ConsensusCoverage.LeaderCoverage
import ConsensusCoverage.CaptureBounds
import Consensus.Replay.Reduction

open Consensus Consensus.Replay ConsensusCoverage

private structure SliceScore where
  hits : List StateCoverage.Row := []
  unknown : Nat := 0

private structure Score where
  states : List StateCoverage.Row := []
  edges : List FrontierRows.Row := []
  multiEdges : Option (List LeaderWitnesses.Key) := none
  rows : List CaptureBounds.Row := []
  quiet : SliceScore := {}
  nomination : SliceScore := {}
  past : List Model.State := []

private def record [BEq α] (xs : List α) (x : α) := if xs.contains x then xs else x :: xs

private def SliceScore.add (score : SliceScore) (key : StateCoverage.Row) : Option Bool → SliceScore
  | some true => {score with hits := record score.hits key}
  | some false => score
  | none => {score with unknown := score.unknown + 1}

private def start (cfg : CCF.Finset Nat) (s : Model.State) : Score :=
  { states := [StateCoverage.read cfg s []], multiEdges := if s.nodes.length ≥ 2 then some [] else none }

private def visit (cfg : CCF.Finset Nat) (score : Score) (s : Model.State) (a : Model.Action) (t : Model.State) : Score :=
  let past := s :: score.past
  let e := ReplayAnswers.read cfg s a t score.past
  let edge := e.key.1
  let (row, quiet) := CaptureBounds.read e
  let pre := (edge.zeroBefore, edge.backedBefore)
  { states := record score.states (edge.zeroAfter, edge.backedAfter),
    edges := record score.edges edge,
    multiEdges := score.multiEdges.map fun seen => record seen e.key,
    rows := row :: score.rows,
    quiet := score.quiet.add pre quiet,
    nomination := score.nomination.add pre (CaptureBounds.signature? row NominationRows.bits),
    past }

private def stateKey (row : StateCoverage.Row) : String :=
  String.ofList ([row.1, row.2].map fun b => if b then '1' else '0')

private def reportSlice (name : String) (scores : List SliceScore) : IO Unit := do
  let missing := StateCoverage.activeTable.filter (· ∉ scores.flatMap SliceScore.hits)
  IO.println s!"{StateCoverage.activeTable.length - missing.length}/{StateCoverage.activeTable.length} confirmed \
    {name} step labels; not confirmed: {if missing.isEmpty then "none" else String.intercalate " " (missing.map stateKey)}; \
    actions with undetermined slice membership: {(scores.map SliceScore.unknown).sum}"

private def report (states : List StateCoverage.Row) (edges : List FrontierRows.Row) : IO Unit := do
  let table := StateCoverage.activeTable
  let bits (xs : List Bool) := String.ofList (xs.map fun b => if b then '1' else '0')
  let edgeKey (r : FrontierRows.Row) :=
    bits [r.zeroBefore, r.backedBefore, r.wonPrimary, r.zeroAfter, r.backedAfter]
  unless states.all (· ∈ table) do throw <| IO.userError "unexpected state on a nonempty replay"
  let missing := table.filter (· ∉ states)
  IO.println s!"{table.length - missing.length}/{table.length} reachable nonempty state profiles; missing: \
    {if missing.isEmpty then "none" else String.intercalate " " (missing.map stateKey)}"
  unless edges.all (· ∈ FrontierRows.table) do throw <| IO.userError "unexpected projected step"
  let missing := FrontierRows.table.filter (· ∉ edges)
  IO.println s!"{FrontierRows.table.length - missing.length}/{FrontierRows.table.length} projected step rows \
    (state profiles + new primary); missing: \
    {if missing.isEmpty then "none" else String.intercalate " " (missing.map edgeKey)}"

private def reportLeaders (edges : List LeaderWitnesses.Key) : IO Unit := do
  let table := LeaderCoverage.multiTable
  unless edges.all (· ∈ table) do throw <| IO.userError "unexpected multi-node leader row"
  let missing := table.filter (· ∉ edges)
  let key (k : LeaderWitnesses.Key) :=
    let r := k.1
    String.ofList ([r.zeroBefore, r.backedBefore, r.wonPrimary, r.zeroAfter, r.backedAfter, k.2].map
      fun b => if b then '1' else '0')
  IO.println s!"{table.length - missing.length}/{table.length} multi-node leader rows \
    (state profiles + 3 leader questions); missing: \
    {if missing.isEmpty then "none" else String.intercalate " " (missing.map key)}"

private def fromCapture {α : Type} (file : String) (start : CCF.Finset Nat → Model.State → α)
    (visit : CCF.Finset Nat → α → Model.State → Model.Action → Model.State → α) : IO α := do
  let records ← readLog file
  let result := do
    let (events, declared) ← prepareEvents (← records)
    let r ← reduce events declared
    foldRecordedActions r.header r.instructions (start r.header.bootstrap r.header.initial) (visit r.header.bootstrap)
  let (counts, score) ← IO.ofExcept (result.mapError fun error => s!"{file}: {error}")
  IO.println s!"{file}: {counts.actions} validated model actions, {counts.observations} replay observations"
  return score

private def printAnswers (file : String) : IO Unit := do
  let init := fun (_ : CCF.Finset Nat) (_ : Model.State) => (([] : List Model.State), (#[] : Array String))
  let (_, lines) ← fromCapture file init fun cfg (past, lines) s a t =>
    let e := ReplayAnswers.read cfg s a t past
    let sectionBits (bs : Array FullProfile.Question) := String.ofList <| bs.toList.map fun q =>
      match ReplayAnswers.answer e q with
      | some true => '1'
      | some false => '0'
      | none => '?'
    let pre := sectionBits (FullProfile.stateBranches.map FullProfile.Question.pre)
    let step := sectionBits (FullProfile.stepBranches.map FullProfile.Question.step)
    let post := sectionBits (FullProfile.stateBranches.map FullProfile.Question.post)
    (s :: past, lines.push s!"{lines.size + 1}\t{repr e.tag}\t{pre}\t{step}\t{post}")
  IO.println "action\tkind\tpre[12]\tstep[433]\tpost[12]   (1=true, 0=false, ?=unknown)"
  for line in lines do IO.println line

def main : List String → IO Unit
  | ["columns"] => do
    IO.println "section\tbit (1-based)\tgenerated question"
    for q in FullProfile.questions do
      match q with
      | .pre b => IO.println s!"pre\t{b.ctorIdx + 1}\t{repr b}"
      | .step b => IO.println s!"step\t{b.ctorIdx + 1}\t{repr b}"
      | .post b => IO.println s!"post\t{b.ctorIdx + 1}\t{repr b}"
  | ["check"] => do
    let some edges := FrontierRows.witnessRows | throw <| IO.userError "disabled witness schedule"
    let states := edges.flatMap fun r => [(r.zeroBefore, r.backedBefore), (r.zeroAfter, r.backedAfter)]
    report states edges
    unless StateCoverage.activeTable.all (· ∈ states) && FrontierRows.table.all (· ∈ edges) do
      throw <| IO.userError "incomplete model witnesses"
    let some keys := LeaderWitnesses.multiWitnessRows | throw <| IO.userError "disabled multi-node witness schedule"
    reportLeaders keys
    unless LeaderCoverage.multiTable.all (· ∈ keys) do throw <| IO.userError "incomplete multi-node witnesses"
  | "trace" :: file :: more => do
    let scores ← (file :: more).mapM fun path => fromCapture path start visit
    let rows := scores.reverse.flatMap Score.rows
    let lower := (CaptureBounds.select rows).length
    let count := if lower == rows.length then s!"exactly {lower}" else s!"{lower} to {rows.length}"
    IO.println s!"{count} distinct full proof labels in these captures (global denominator unknown)"
    report (scores.flatMap Score.states) (scores.flatMap Score.edges)
    let multi := scores.filterMap Score.multiEdges
    if multi.isEmpty then IO.println "multi-node leader rows: not applicable (no multi-node capture)"
    else reportLeaders multi.flatten
    reportSlice "all-false" (scores.map Score.quiet)
    reportSlice "fresh-nomination signature" (scores.map Score.nomination)
  | ["answers", file] => printAnswers file
  | _ => throw <| IO.userError "usage: proof-coverage.lean check | trace FILE.ndjson [FILE.ndjson ...] | answers FILE.ndjson | columns"
