module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public meta import ConsensusCoverage.Readers
public meta import ConsensusCoverage.ReadersCorpus
public meta import ConsensusCoverage.ReplayAnswers
public meta import ConsensusCoverage.CaseWitnesses

open ConsensusCoverage

meta section

open Consensus.Model Consensus.Model.Node

private abbrev ActionKey := Sum (Nat × Input) (Nat × Nat × Message)

private def actionKey : Action → ActionKey
  | .local n i => .inl (n, i)
  | .deliver e => .inr (e.source, e.target, e.payload)

private structure ReplayKey where
  cfg : List Nat
  nodes : List Nat
  reverseActions : List ActionKey
  deriving DecidableEq

private structure Sample where
  schedule : Nat
  offset : Nat
  evidence : Readers.Evidence
  baseline : ReplayAnswers.Evidence
  copies : Nat := 1

private def samples : IO (List Sample) := do
  let mut keys : Array ReplayKey := #[]
  let mut out := #[]
  for i in [:ReadersCorpus.scheduleCount] do
    let some steps := ReadersCorpus.steps i | throw (IO.userError s!"invalid schedule {i}")
    let mut trace := []
    for (s, offset) in steps.zipIdx do
      trace := actionKey s.act :: trace
      -- Initialization and model steps are functions of this entire input prefix.
      let key : ReplayKey := ⟨s.cfg.val, s.nodes, trace⟩
      if let some k := keys.findIdx? (fun prior => decide (prior = key)) then
        out := out.modify k (fun s => { s with copies := s.copies + 1 })
      else
        keys := keys.push key
        out := out.push ⟨i, offset, Readers.read s.cfg s.before s.act s.after s.past,
          ReplayAnswers.read s.cfg s.before s.act s.after s.past, 1⟩
  return out.toList.mergeSort (fun a b => a.offset ≤ b.offset)

private structure Obs where
  firstYes : Option (Nat × Nat) := none
  hasUnknown : Bool := false
  elapsed : List Nat := []
  exactInferred : Nat := 0
  negativesInferred : Nat := 0
  duplicates : Nat := 0

private def observe (rows : List Sample) (b : Classes.StepBranch) (search : Option Nat) :
    IO (Obs × Bool) := do
  let exact := Readers.covered.contains b
  let (knownYes, remaining) :=
    (rows.map fun s => (s, ReplayAnswers.answer s.baseline (.step b))).partition (·.2 == some true)
  if let (s, _) :: _ := knownYes then
    -- Both readers are sound, and the exact one is total.
    if exact then return ({ firstYes := some (s.schedule, s.offset), exactInferred := 1 }, true)
  let candidates : List (Sample × Option Bool) := match search with
    | none => knownYes ++ remaining
    | some limit =>
      (knownYes ++ remaining.filter (fun (_, answer) => answer != some false)).take limit
  let mut result : Obs := {}
  for (s, baseline) in candidates do
    result := { result with duplicates := result.duplicates + (s.copies - 1) }
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
  let steps := sample.foldl (fun n s => n + s.copies) 0
  IO.eprintln s!"{ReadersCorpus.scheduleCount} initialized schedules; {steps} steps; shard {shard}/{shards}"
  IO.eprintln s!"{sample.length} distinct initialized action prefixes"
  IO.println "question\tclass\tschedule\toffset\tbaseline_yes\texact_inferred\tnegatives_inferred\tduplicates\tcalls\tmin_ns\tmedian_ns\tmax_ns"
  (← IO.getStdout).flush
  let trace := (← IO.getEnv "CCF_READERS_TRACE").isSome
  let search ← (← IO.getEnv "CCF_READERS_SEARCH_PREFIXES").mapM fun value =>
    match value.toNat? with
    | some (limit + 1) => pure (limit + 1)
    | _ => throw (IO.userError "CCF_READERS_SEARCH_PREFIXES must be a positive integer")
  for (b, i) in FullProfile.stepBranches.toList.zipIdx do
    if i % shards != shard then continue
    let name := toString (repr b)
    if !selected.isEmpty && !selected.contains ((name.splitOn ".").getLast!) then continue
    if trace then IO.eprintln s!"reading {name}"
    let (observed, baseline) ← observe sample b search
    -- A bounded positive search cannot classify a row without a hit.
    if search.isSome && observed.firstYes.isNone then
      IO.eprintln s!"unmeasured {name}: no hit in bounded positive search"
      continue
    let (status, schedule, offset) := match observed.firstYes with
      | some (s, i) => ("yes", toString s, toString i)
      | none => (if observed.hasUnknown then "unknown" else "no", "-", "-")
    let ns := observed.elapsed.mergeSort
    let stat (x : Option Nat) := x.map toString |>.getD "-"
    let row := [name, status, schedule, offset, toString baseline,
      toString observed.exactInferred, toString observed.negativesInferred, toString observed.duplicates,
      toString ns.length, stat ns.head?,
      stat (ns[ns.length / 2]?), stat ns.getLast?]
    IO.println (String.intercalate "\t" row)
    (← IO.getStdout).flush

end
