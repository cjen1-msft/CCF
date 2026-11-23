-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import ConsensusCoverage.StateCoverage
import ConsensusCoverage.FrontierWitnesses
import ConsensusCoverage.LeaderCoverage
import ConsensusCoverage.CaptureBounds
import ConsensusCoverage.Families
import Consensus.Replay.Reduction
import Std.Data.TreeMap.Basic

open Consensus Consensus.Replay ConsensusCoverage

private structure Score where
  states : List StateCoverage.Row := []
  edges : List FrontierRows.Row := []
  multiEdges : Option (List LeaderWitnesses.Key) := none
  rows : List CaptureBounds.Row := []
  quiet : List StateCoverage.Row := []
  nomination : List StateCoverage.Row := []
  families : Std.TreeMap String Nat := {}
  past : List Model.State := []

private def record [BEq α] (xs : List α) (x : α) := if xs.contains x then xs else x :: xs

private def start (cfg : CCF.Finset Nat) (s : Model.State) : Score :=
  { states := [StateCoverage.read cfg s []], multiEdges := if s.nodes.length ≥ 2 then some [] else none }

private def visit (cfg : CCF.Finset Nat) (score : Score) (s : Model.State) (a : Model.Action) (t : Model.State) : Score :=
  let past := s :: score.past
  let e := ReplayAnswers.read cfg s a t score.past
  let edge := e.key.1
  let row := CaptureBounds.read e
  let pre := (edge.zeroBefore, edge.backedBefore)
  let family := Families.code (Families.classify cfg s a t score.past)
  { states := record score.states (edge.zeroAfter, edge.backedAfter),
    edges := record score.edges edge,
    multiEdges := score.multiEdges.map fun seen => record seen e.key,
    rows := row :: score.rows,
    quiet := if e.inert then record score.quiet pre else score.quiet,
    nomination := if e.nomination then record score.nomination pre else score.nomination,
    families := score.families.alter family (fun n => some (n.getD 0 + 1)),
    past }

private def stateKey (row : StateCoverage.Row) : String :=
  String.ofList ([row.1, row.2].map fun b => if b then '1' else '0')

private def reportSlice (name : String) (hits : List StateCoverage.Row) : IO Unit := do
  let missing := StateCoverage.activeTable.filter (· ∉ hits)
  IO.println s!"{StateCoverage.activeTable.length - missing.length}/{StateCoverage.activeTable.length} \
    {name} step labels; missing: {if missing.isEmpty then "none" else String.intercalate " " (missing.map stateKey)}"

private def reportFamilies (scores : List Score) : IO Unit := do
  let counts := scores.foldl (init := ({} : Std.TreeMap String Nat)) fun total score =>
    score.families.foldl (fun acc name count => acc.alter name (fun n => some (n.getD 0 + count))) total
  let closed := [Families.Family.quiet, .freshNomination, .delayedNomination].map Families.code
  let closedCounts := closed.map fun name => (name, counts.getD name 0)
  let summary := String.intercalate " " (closedCounts.map fun (name, count) => s!"{name}={count}")
  IO.println s!"closed families ({(closedCounts.map Prod.snd).sum} actions): {summary}"
  IO.println s!"open family bits (1=fresh, 0=stale): {Families.evidenceOrder}"
  IO.println "open family\tactions"
  for (name, count) in counts.toList do
    unless closed.contains name do
      IO.println s!"{name}\t{count}"

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
    reportSlice "all-false" (scores.flatMap Score.quiet)
    reportSlice "fresh-nomination signature" (scores.flatMap Score.nomination)
    reportFamilies scores
  | ["answers", file] => printAnswers file
  | _ => throw <| IO.userError
    ("usage: proof-coverage.lean check | trace FILE.ndjson [FILE.ndjson ...] | answers FILE.ndjson | columns\n" ++
      s!"trace open families: open:<action kind>:<7 bits> (1=fresh, 0=stale), in order: {Families.evidenceOrder}")
