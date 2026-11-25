module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

meta import all ConsensusCoverage.CensusPartition
meta import all ConsensusCoverage.EventSupport
meta import all ConsensusCoverage.Readers
meta import all ConsensusCoverage.ReplayAnswers
import all ConsensusCoverage.SolvedWitnesses
meta import Lean

/-! Export the kernel-checked unsettled roster. The formula and its immediate
normalized reach calls are declaration names, not guesses from case names.
Regenerate the checked-in roster from the repository root after `lake build`:

```
WS=$(python3 lean/relevance/scripts/workspace.py consensus-coverage)
CENSUS_UNSETTLED_OUT="$PWD/lean/consensus-coverage/unsettled.tsv" \
  lake -d "$WS/consensus-coverage" env lean lean/consensus-coverage/scripts/census-unsettled.lean
```
-/

open Lean Meta Elab Command ConsensusCoverage

private meta def shortName [Repr α] (x : α) : String := (reprStr x).splitOn "." |>.getLast!

run_cmd liftTermElabM do
  let stream ← match ← IO.getEnv "CENSUS_UNSETTLED_OUT" with
    | some path => pure (IO.FS.Stream.ofHandle (← IO.FS.Handle.mk path .write))
    | none => IO.getStdout
  stream.putStrLn "question\texact_reader\tallowed_events\tformula\tdirect_reaches"
  let scope := `ConsensusCoverage.SolvedWitnesses
  for b in CensusPartition.unsettled do
    let q := shortName b
    let root := scope ++ Name.mkSimple ("step_" ++ q)
    let body := (← getConstInfoDefn root).value
    let reaches := (body.getUsedConstants.filter fun n =>
      n.getPrefix == scope && n.getString!.startsWith "reach_").toList.map (·.getString!)
    let allowed := (EventSupport.allowed b).map shortName
    let exactReader := Readers.covered.contains b || ReplayAnswers.unconditional.contains b
    stream.putStrLn s!"{q}\t{exactReader}\t{String.intercalate "," allowed}\t{root}\t{String.intercalate "," reaches.mergeSort}"
  stream.flush
