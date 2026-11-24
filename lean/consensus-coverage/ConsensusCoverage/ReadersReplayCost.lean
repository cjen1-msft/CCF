module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public meta import ConsensusCoverage.Readers
public meta import ConsensusCoverage.ReplayAnswers
public meta import Consensus.Replay.Reduction

open Consensus Consensus.Replay ConsensusCoverage

meta section

public def main (args : List String) : IO Unit := do
  let [file] := args | throw <| IO.userError "usage: ReplayCost.lean CAPTURE.ndjson"
  let trials := (← IO.getEnv "CCF_READERS_TRIALS").bind String.toNat? |>.getD 1
  if trials == 0 then throw <| IO.userError "require at least one cost trial"
  let records ← IO.ofExcept (← readLog file)
  let (events, declared) ← IO.ofExcept (prepareEvents records)
  let replay ← IO.ofExcept (reduce events declared)
  let (counts, actions) ← IO.ofExcept (foldRecordedActions replay.header replay.instructions
    (#[] : Array (Model.State × Model.Action × Model.State))
    (fun found before act after => found.push (before, act, after)))
  let cfg := replay.header.bootstrap
  let covered := Readers.covered
  IO.eprintln s!"validated {counts.actions} actions, {counts.observations} observations; {covered.length} readers"
  IO.println "trial\taction\treader\telapsed_ns\tresult\tbaseline"
  let mut comparisons := 0
  let mut calls := 0
  let mut positive := 0
  for trial in [:trials] do
    let mut past := []
    for (row, (before, act, after)) in actions.toList.zipIdx.map Prod.swap do
      let action := row + 1
      let start ← IO.monoNanosNow
      let evidence := Readers.read cfg before act after past
      let good := evidence.view.isSome
      let stop ← IO.monoNanosNow
      unless good do throw <| IO.userError s!"missing prepared view on action {action}"
      IO.println s!"{trial + 1}\t{action}\tPREPARE\t{stop - start}\t-\t-"
      let reference := ReplayAnswers.read cfg before act after past
      for b in covered do
        let start ← IO.monoNanosNow
        let result := Readers.read? evidence b
        let stop ← IO.monoNanosNow
        let some answer := result | throw <| IO.userError s!"action {action}, {repr b}: absent"
        let old := ReplayAnswers.answer reference (.step b)
        if let some expected := old then
          unless answer == expected do
            throw <| IO.userError s!"action {action}, {repr b}: {answer} != {expected}"
          comparisons := comparisons + 1
        calls := calls + 1
        if answer then positive := positive + 1
        IO.println s!"{trial + 1}\t{action}\t{repr b}\t{stop - start}\t{answer}\t{repr old}"
      let missing := (FullProfile.stepBranches.filter fun b => !covered.contains b &&
        (ReplayAnswers.answer reference (.step b)).isNone).size
      IO.eprintln s!"trial {trial + 1}, action {action}: generated ? = {FullProfile.stepBranches.size - covered.length}, combined ? = {missing}"
      (← IO.getStdout).flush
      past := before :: past
  unless calls == trials * actions.size * covered.length do
    throw <| IO.userError "incomplete measurement"
  IO.eprintln s!"trials={trials} calls={calls} positive={positive} overlap_agreed={comparisons} errors=0"

end
