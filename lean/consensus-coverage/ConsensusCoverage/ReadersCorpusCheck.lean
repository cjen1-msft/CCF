module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public meta import ConsensusCoverage.Readers
public meta import ConsensusCoverage.ReadersCorpus
public meta import ConsensusCoverage.ReplayAnswers
public meta import ConsensusCoverage.CaseWitnesses

open ConsensusCoverage

meta section

private structure Sample where
  schedule : Nat
  offset : Nat
  evidence : Readers.Evidence
  baseline : ReplayAnswers.Evidence

private def samples : IO (List Sample) := do
  let mut out := #[]
  for i in [:ReadersCorpus.scheduleCount] do
    let some steps := ReadersCorpus.steps i | throw (IO.userError s!"invalid schedule {i}")
    for (s, offset) in steps.zipIdx do
      out := out.push ⟨i, offset, Readers.read s.cfg s.before s.act s.after s.past,
        ReplayAnswers.read s.cfg s.before s.act s.after s.past⟩
  return out.toList.mergeSort (fun a b => a.offset ≤ b.offset)

private structure Obs where
  firstYes : Option (Nat × Nat) := none
  hasUnknown : Bool := false
  elapsed : List Nat := []
  exactInferred : Nat := 0
  negativesInferred : Nat := 0

private def observe (rows : List Sample) (b : Classes.StepBranch) : IO (Obs × Bool) := do
  let exact := Readers.covered.contains b
  let (knownYes, remaining) :=
    (rows.map fun s => (s, ReplayAnswers.answer s.baseline (.step b))).partition (·.2 == some true)
  if let (s, _) :: _ := knownYes then
    -- Both readers are sound, and the exact one is total.
    if exact then return ({ firstYes := some (s.schedule, s.offset), exactInferred := 1 }, true)
  let mut result : Obs := {}
  for (s, baseline) in knownYes ++ remaining do
    let answer ← if exact && baseline.isSome then do
        result := { result with exactInferred := result.exactInferred + 1 }
        pure baseline
      else if result.hasUnknown && baseline == some false then do
        -- Either false or unknown cannot alter the class once an unknown is known.
        result := { result with negativesInferred := result.negativesInferred + 1 }
        pure none
      else do
        let start ← IO.monoNanosNow
        let found := Readers.read? s.evidence b
        let elapsed := (← IO.monoNanosNow) - start
        if let some v := found then
          if let some old := baseline then
            unless v == old do throw (IO.userError s!"disagreement at {s.schedule}:{s.offset} on {repr b}")
        result := { result with
          elapsed := elapsed :: result.elapsed
          hasUnknown := result.hasUnknown || found.isNone }
        pure found
    if answer == some true then
      result := { result with firstYes := some (s.schedule, s.offset) }
      break
  return (result, !knownYes.isEmpty)

public def main (args : List String) : IO Unit := do
  if args == ["--case-witnessed"] then
    for b in CaseWitnesses.witnessed do IO.println (repr b)
    return
  let shard :: shards :: selected := args |
    throw (IO.userError "usage: ReadersCorpusCheck.lean SHARD SHARDS [QUESTION ...]")
  let some shard := shard.toNat? | throw (IO.userError "invalid shard")
  let some shards := shards.toNat? | throw (IO.userError "invalid shard count")
  unless shard < shards do throw (IO.userError "shard outside range")
  let sample ← samples
  IO.eprintln s!"{ReadersCorpus.scheduleCount} initialized schedules; {sample.length} steps; shard {shard}/{shards}"
  IO.println "question\tclass\tschedule\toffset\tbaseline_yes\texact_inferred\tnegatives_inferred\tcalls\tmin_ns\tmedian_ns\tmax_ns"
  (← IO.getStdout).flush
  let trace := (← IO.getEnv "CCF_READERS_TRACE").isSome
  for (b, i) in FullProfile.stepBranches.toList.zipIdx do
    if i % shards != shard then continue
    let name := toString (repr b)
    if !selected.isEmpty && !selected.contains ((name.splitOn ".").getLast!) then continue
    if trace then IO.eprintln s!"reading {name}"
    let (observed, baseline) ← observe sample b
    let (status, schedule, offset) := match observed.firstYes with
      | some (s, i) => ("yes", toString s, toString i)
      | none => (if observed.hasUnknown then "unknown" else "no", "-", "-")
    let ns := observed.elapsed.mergeSort
    let stat (x : Option Nat) := x.map toString |>.getD "-"
    let row := [name, status, schedule, offset, toString baseline,
      toString observed.exactInferred, toString observed.negativesInferred, toString ns.length, stat ns.head?,
      stat (ns[ns.length / 2]?), stat ns.getLast?]
    IO.println (String.intercalate "\t" row)
    (← IO.getStdout).flush

end
