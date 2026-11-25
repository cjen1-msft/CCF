module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.CensusExactRow
import all ConsensusCoverage.Readers
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReadersCorpus
import all ConsensusCoverage.ReadersTotal
import all ConsensusCoverage.ReplayAnswers
import all ConsensusCoverage.StateCoverage

namespace ConsensusCoverage.ClauseCensus

open ClauseQuestions ActionProfile

private def mask (bs : List Classes.StepBranch) : Nat :=
  bs.foldl (fun n b => n ||| (1 <<< b.ctorIdx)) 0

private def endpoints (s : Step) : Nat :=
  let p := StateCoverage.read s.cfg s.before s.past
  let q := StateCoverage.read s.cfg s.after (s.before :: s.past)
  (p.1.toNat + 2 * p.2.toNat + 4 * q.1.toNat + 8 * q.2.toNat) <<< 516

private def trunk (b : Classes.StepBranch) : Bool :=
  (Clause.all.countP (fun c => (questions c).contains b)) ≥ 26

/-- Deterministic global order of first occurrences. An initial configuration,
deployed nodes, and the *resolved* action prefix determine every input to the
reader, including the full newest-first history and sparse delivery choices. -/
private def distinctSteps : IO (Nat × Array (Nat × Nat × Step)) := do
  let mut seen := #[]
  let mut out := #[]
  let mut count := 0
  for i in [:ReadersCorpus.scheduleCount] do
    let some ss := ReadersCorpus.steps i | throw (IO.userError s!"invalid schedule {i}")
    let mut history : List Consensus.Model.Action := []
    for (s,j) in ss.zipIdx do
      count := count + 1
      history := s.act :: history
      let key := (s.cfg, s.nodes, history)
      unless seen.contains key do
        seen := seen.push key
        out := out.push (i,j,s)
  return (count, out)

private def columns (mode : String) := ReadersTotal.covered.filter fun b =>
  let slow := b == .rankAtGrant_persist_inl || b == .rankAtGrant_persist_inr
  match mode with
  | "fast" => !slow
  | "ranking" => slow
  | "local" => !trunk b && ((questions .active).contains b || (questions .match_ack).contains b)
  | _ => true

/-- Reuse already-proved answers before calling the total reader. In particular
a failed guard is *unknown*, so it falls through rather than becoming false. -/
public def query (s : Step) : Classes.StepBranch → Option Bool :=
  let replay := ReplayAnswers.read s.cfg s.before s.act s.after s.past
  let view := (ReadersAtoms.ofXAction s.cfg s.before s.after s.past s.act).map
    fun x => (CensusExactRow.exactView s.cfg x).val
  let fallback := ReadersTotal.read s.cfg s.before s.act s.after s.past
  fun b => (ReadersRefuted.read? b).orElse fun _ => (ReplayAnswers.answer replay (.step b)).orElse fun _ =>
    (view.bind (· b)).orElse fun _ => fallback b

public theorem query_eq (s : Step) {b : Classes.StepBranch} (mem : b ∈ ReadersTotal.covered) :
    query s b = ReadersTotal.read s.cfg s.before s.act s.after s.past b := by
  unfold query
  rw [ReadersTotal.read_total s mem]
  cases neg : ReadersRefuted.read? b
  case some v => exact congrArg some (ReadersRefuted.read?_correct s neg).symm
  rw [Option.orElse_none]
  cases h : ReplayAnswers.answer (ReplayAnswers.read s.cfg s.before s.act s.after s.past) (.step b) with
  | some v => simp only [Option.orElse_some, ReplayAnswers.sound s _ h]
  | none =>
    simp only [Option.orElse_none]
    obtain ⟨x, made, _⟩ := ReadersAtoms.ofXAction_matches s
    rw [made]
    simp only [Option.map_some, Option.bind_some, (CensusExactRow.exactView s.cfg x).property]
    cases read : @ReadersCompiler.readView ⟨s.cfg⟩ x b with
    | none => rfl
    | some v =>
      have eq : ReadersTotal.compiled? (Readers.read s.cfg s.before s.act s.after s.past) b =
          some v := by
        change (ReadersAtoms.ofXAction s.cfg s.before s.after s.past s.act).bind
          (fun y => @ReadersCompiler.readView ⟨s.cfg⟩ y b) = some v
        rw [made]
        exact read
      rw [ReadersTotal.compiled?_correct s eq]
      rfl

/-- Emit exact bit masks for the certified corpus. Optional disjoint shards
are assigned *after* prefix deduplication, independently of reader speed. -/
public def run (mode : String := "all") (shard : Nat := 0) (shards : Nat := 1) : IO Unit := do
  unless ["all", "fast", "ranking", "local"].contains mode && shard < shards do
    throw (IO.userError "expected all|fast|ranking|local and 0 <= shard < shards")
  let (count, ss) ← distinctSteps
  let bs := columns mode
  IO.println s!"corpus\t{count}\t{ss.size}\t{bs.length}"
  let endpointMask := 15 <<< 516
  for c in Clause.all do
    let coords := (questions c).filter bs.contains
    IO.println s!"clause\t{repr c}\t{(questions c).length}\t{coords.length}\t{mask coords ||| endpointMask}"
  let stdout ← IO.getStdout
  for ((i,j,s),k) in ss.toList.zipIdx do
    if k % shards != shard then continue
    let read := query s
    let mut word := endpoints s
    for b in bs do
      let some v := read b | throw (IO.userError s!"missing coordinate {b.ctorIdx} at {i}:{j}")
      if v then word := word ||| (1 <<< b.ctorIdx)
    stdout.putStrLn s!"row\t{k}\t{i}\t{j}\t{word}"
    stdout.flush

end ConsensusCoverage.ClauseCensus
