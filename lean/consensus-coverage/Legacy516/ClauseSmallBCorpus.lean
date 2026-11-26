module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.ClauseMatchAck
public import ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.ClauseRankRead
import all ConsensusCoverage.ClauseSmallBMessageFloorGate
import all ConsensusCoverage.ReadersCorpus
import all ConsensusCoverage.ReadersTotal
import Std.Data.HashMap

namespace ConsensusCoverage.ClauseSmallB.Corpus

open ActionProfile ClauseExactTables ClauseMatchAck ClauseQuestions

private def bitChar (b : Bool) : Char := if b then '1' else '0'

private def endpoint (r : StateCoverage.Row) : String := String.ofList [bitChar r.1, bitChar r.2]

private def fast (col : Classes.StepBranch) : Bool :=
  match col with
  | .rankAtGrant_persist_inr | .grantFactsBefore_grant_inl
  | .maxCommittableIndexBounded_values_nil | .maxCommittableIndexBounded_values_cons
  | .maxCommittableIndexBounded_signature_pos | .maxCommittableIndexBounded_signature_neg => false
  | _ => true

private def readStep (cols : List Classes.StepBranch) (projected : Bool) (s : Step) : IO String := do
  let read := ReadersTotal.read s.cfg s.before s.act s.after s.past
  let floor := Thunk.mk fun _ => MessageFloorGate.relevant s
  let bits ← cols.mapM fun col => do
    if projected && !fast col then return '*'
    if col == .rankAtGrant_persist_inl then return bitChar (ClauseRankRead.retained s)
    if (col == .leader_floor_led_inl || col == .leader_floor_led_inr) && !floor.get then return '0'
    let some bit := read col | throw (IO.userError s!"Missing answer for {repr col}")
    return bitChar bit
  let (pre, post) := endpoints s
  return s!"{String.ofList bits} {endpoint pre}>{endpoint post}"

private abbrev Picks := Std.HashMap String (Nat × Nat)

private def add (picks : Picks) (key : String) (pick : Nat × Nat) : Picks :=
  match picks[key]? with
  | some previous =>
    if pick.1 < previous.1 || pick.1 == previous.1 && pick.2 < previous.2 then
      picks.insert key pick
    else picks
  | none => picks.insert key pick

private def worker (cols : List Classes.StepBranch) (projected : Bool) (shard workers : Nat) :
    IO (Nat × Picks) := do
  let mut picks := {}
  let mut count := 0
  for i in [:ReadersCorpus.scheduleCount] do
    if i % workers == shard then
      let some steps := ReadersCorpus.steps i | throw (IO.userError s!"Invalid schedule {i}")
      for (s, j) in steps.zipIdx do
        let key ← readStep cols projected s
        picks := add picks key (i, j)
        count := count + 1
  return (count, picks)

/-- `lean --run .../ClauseSmallBCorpus.lean CLAUSE WORKERS [fast]`.
`*` denotes an omitted coordinate rather than a negative answer. -/
public def run (clause : Clause) (workers : Nat) (projected : Bool) : IO Unit := do
  if workers == 0 then throw (IO.userError "Expected a positive worker count")
  let cols := nonTrunk clause
  let mut jobs := #[]
  for i in [:workers] do
    jobs := jobs.push (← IO.asTask (worker cols projected i workers))
  let mut picks := {}
  let mut count := 0
  for job in jobs do
    let (n, rows) ← IO.ofExcept job.get
    count := count + n
    for (key, index) in rows.toList do
      picks := add picks key index
  for (key, i, j) in picks.toArray.qsort (fun a b => a.1 < b.1) do
    IO.println s!"{key} {i}:{j}"
  IO.println s!"{repr clause}: {count} steps, {picks.size} observed rows"

end ConsensusCoverage.ClauseSmallB.Corpus

open ConsensusCoverage.ClauseQuestions in
public def main (args : List String) : IO Unit := do
  let err := IO.userError "Expected CLAUSE WORKERS [fast]"
  let clause : Clause ← match args[0]? with
    | some "message_terms" => pure .message_terms
    | some "led_cur" => pure .led_cur
    | some "leader_led" => pure .leader_led
    | some "grantFacts" => pure .grantFacts
    | _ => throw err
  let some workers := args[1]?.bind String.toNat? | throw err
  unless args.length == 2 || args.length == 3 && args[2]? == some "fast" do throw err
  ConsensusCoverage.ClauseSmallB.Corpus.run clause workers (args[2]? == some "fast")
