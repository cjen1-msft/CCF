module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public meta import ConsensusCoverage.Readers
public meta import ConsensusCoverage.ReadersCorpus
public meta import ConsensusCoverage.ReplayAnswers
public meta import ConsensusCoverage.CaseWitnesses

open ConsensusCoverage

namespace ConsensusCoverage.ReadersCorpusReplay

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
  tag : EventSupport.Tag
  evidence : Thunk Readers.Evidence
  baseline : Thunk ReplayAnswers.Evidence
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
        out := out.push ⟨i, offset, EventSupport.actionTag s.act,
          Thunk.mk fun _ => Readers.read s.cfg s.before s.act s.after s.past,
          Thunk.mk fun _ => ReplayAnswers.read s.cfg s.before s.act s.after s.past, 1⟩
  return out.toList.mergeSort (fun a b => a.offset ≤ b.offset)

private structure Obs where
  firstYes : Option (Nat × Nat) := none
  hasUnknown : Bool := false
  elapsed : List Nat := []
  eligible : Nat := 0
  tried : Nat := 0
  exactInferred : Nat := 0
  negativesInferred : Nat := 0
  duplicates : Nat := 0

private def observe (rows : List Sample) (b : Classes.StepBranch) (positivesOnly : Bool)
    (limit : Option Nat) (read : Readers.Evidence → Classes.StepBranch → Option Bool) :
    IO (Obs × Bool) := do
  let exact := Readers.covered.contains b
  let allowed := EventSupport.allowed b
  -- Excluded action kinds cannot be positive, but a partial reader may still
  -- return unknown on them. Only omit those steps from positive searches.
  let rows := if positivesOnly then rows.filter (fun s => decide (s.tag ∈ allowed)) else rows
  let candidates := rows.map fun s => (s, ReplayAnswers.answer s.baseline.get (.step b))
  let baselineYes := candidates.any (·.2 == some true)
  let candidates := if positivesOnly then candidates.filter (·.2 != some false) else candidates
  let eligible := candidates.length
  let candidates := limit.elim candidates candidates.take
  let mut result : Obs := { eligible }
  for (s, baseline) in candidates do
    result := { result with tried := result.tried + 1, duplicates := result.duplicates + (s.copies - 1) }
    let answer ← if exact && baseline.isSome then do
        result := { result with exactInferred := result.exactInferred + 1 }
        pure baseline
      else if result.hasUnknown && baseline == some false then do
        -- Either false or unknown cannot alter the class once an unknown is known.
        result := { result with negativesInferred := result.negativesInferred + 1 }
        pure none
      else do
        let evidence := s.evidence.get
        let start ← IO.monoNanosNow
        let found := read evidence b
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
  return (result, baselineYes)

public def run (read : Readers.Evidence → Classes.StepBranch → Option Bool) (args : List String) : IO Unit := do
  if args == ["--case-witnessed"] then
    for b in CaseWitnesses.witnessed do IO.println (repr b)
    return
  if args == ["--event-eligible"] then
    let rows ← samples
    IO.println "question\tevent_eligible_prefixes"
    for b in FullProfile.stepBranches do
      let allowed := EventSupport.allowed b
      IO.println s!"{repr b}\t{(rows.filter fun s => decide (s.tag ∈ allowed)).length}"
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
  IO.println "question\tclass\tschedule\toffset\tbaseline_yes\texact_inferred\tnegatives_inferred\tduplicates\tcalls\tmin_ns\tmedian_ns\tmax_ns\teligible_prefixes\ttried_prefixes"
  (← IO.getStdout).flush
  let trace := (← IO.getEnv "CCF_READERS_TRACE").isSome
  let search ← (← IO.getEnv "CCF_READERS_SEARCH_PREFIXES").mapM fun value =>
    match value.toNat? with
    | some (limit + 1) => pure (limit + 1)
    | _ => throw (IO.userError "CCF_READERS_SEARCH_PREFIXES must be a positive integer")
  let positivesOnly := search.isSome || (← IO.getEnv "CCF_READERS_POSITIVE_ONLY").isSome
  for (b, i) in FullProfile.stepBranches.toList.zipIdx do
    if i % shards != shard then continue
    let name := toString (repr b)
    if !selected.isEmpty && !selected.contains ((name.splitOn ".").getLast!) then continue
    if trace then IO.eprintln s!"reading {name}"
    let (observed, baseline) ← observe sample b positivesOnly search read
    let (status, schedule, offset) := match observed.firstYes with
      | some (s, i) => ("yes", toString s, toString i)
      | none =>
        if positivesOnly then
          (if observed.tried == observed.eligible then "no_hit" else "prefix_limit", "-", "-")
        else (if observed.hasUnknown then "unknown" else "no", "-", "-")
    let ns := observed.elapsed.mergeSort
    let stat (x : Option Nat) := x.map toString |>.getD "-"
    let row := [name, status, schedule, offset, toString baseline,
      toString observed.exactInferred, toString observed.negativesInferred, toString observed.duplicates,
      toString ns.length, stat ns.head?,
      stat (ns[ns.length / 2]?), stat ns.getLast?, toString observed.eligible, toString observed.tried]
    IO.println (String.intercalate "\t" row)
    (← IO.getStdout).flush

end

end ConsensusCoverage.ReadersCorpusReplay
