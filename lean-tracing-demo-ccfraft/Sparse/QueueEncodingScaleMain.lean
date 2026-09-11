import Sparse.QueueSummaryEncoding
import Lean.Data.Json

namespace CCFRaft.Sparse.QueueEncodingScale

open QueueStream

private def events (size : Nat) (cycle : Bool) : List (Event QueueEncoding.InputInt) :=
  (List.range size).map fun index =>
    if cycle && index % 2 == 1 then .pop (.literal 1) else .send (.literal 1)

private def profile (name : String) (trace : List (Event QueueEncoding.InputInt))
    (length : QueueEncoding.InputInt) (expected : Option String := none)
    (summarize : Bool := false) : IO Unit := do
  let start <- IO.monoNanosNow
  let formulas <- IO.mkRef (if summarize then QueueSummaryEncoding.encode [] trace length
    else QueueInitialEncoding.encode [] trace length)
  let encoded <- IO.monoNanosNow
  let formula <- formulas.get
  let commands <- IO.mkRef (SmtScript.compile formula)
  let compiled <- IO.monoNanosNow
  let commandList <- commands.get
  let result <- IO.mkRef (SmtScript.renderCommands commandList)
  let finish <- IO.monoNanosNow
  let script <- result.get
  let encodedTrace := if summarize then QueueSummaryEncoding.normalize trace else trace
  let extra := match expected with
    | none => []
    | some verdict => [("expected", Lean.toJson verdict), ("script", Lean.toJson script)]
  IO.println (Lean.Json.mkObj ([
    ("case", Lean.toJson name),
    ("events", Lean.toJson trace.length),
    ("encoded_events", Lean.toJson encodedTrace.length),
    ("tracked_keys", Lean.toJson (QueueInitialEncoding.eventKeys trace).length),
    ("query_pairs", Lean.toJson (QueueEncoding.syntaxQueries
      (QueueInitialEncoding.eventKeys encodedTrace) encodedTrace []).length),
    ("encoding_ns", Lean.toJson (finish - start)),
    ("formula_ns", Lean.toJson (encoded - start)),
    ("commands_ns", Lean.toJson (compiled - encoded)),
    ("text_ns", Lean.toJson (finish - compiled)),
    ("bytes", Lean.toJson script.utf8ByteSize)] ++ extra)).compress
  ( <- IO.getStdout).flush

def run (sizes : List Nat) (summarize : Bool := false) : IO Unit := do
  for cycle in [false, true] do
    for size in sizes do
      profile s!"{if cycle then "cycle" else "send"}-{size}" (events size cycle)
        (.literal 0) none summarize

def runFixtures (size : Nat) (summarize : Bool := false) : IO Unit := do
  for valid in [true, false] do
    let verdict := if valid then "sat" else "unsat"
    for cycle in [false, true] do
      let finalLength := if valid then (size - 1) % 2 else 2
      let finalLength := if cycle then finalLength else if valid then 1 else 2
      profile s!"{if cycle then "cycle" else "send"}-{size}-{verdict}"
        (events (size - 1) cycle ++ [.length finalLength]) (.literal 0) (some verdict) summarize
    profile s!"unknown-million-{size}-{verdict}"
      ([.length 1000000] ++ List.replicate (size - 2) (.send (.symbolic 0)) ++
        [.length (if valid then 1000001 else 1000002)])
      (.symbolic 1) (some verdict) summarize

def runMixedFixtures (size keys : Nat) (summarize : Bool := false) : IO Unit := do
  for valid in [true, false] do
    let verdict := if valid then "sat" else "unsat"
    for (symbolic, cycle) in [(false, false), (true, false), (true, true)] do
      let trace := (List.range (size - 1)).map fun index =>
        let key := (if cycle then index / 2 else index) % keys
        let value := if symbolic then QueueEncoding.InputInt.symbolic key else .literal key
        if cycle && index % 2 == 1 then Event.pop value else .send value
      let finalLength := if cycle then (size - 1) % 2 else keys
      profile s!"mixed-{if symbolic then "symbolic" else "literal"}-{if cycle then "cycle" else "send"}-{size}-{keys}-{verdict}"
        (trace ++ [.length (if valid then finalLength else if cycle then 2 else keys + 1)])
        (.literal 0) (some verdict) summarize

end CCFRaft.Sparse.QueueEncodingScale

def main (args : List String) : IO UInt32 := do
  let (summarize, args) := match args with
    | "--summarize" :: rest => (true, rest)
    | _ => (false, args)
  if let ["--fixtures", count] := args then
    if let some size := count.toNat? then
      if 3 <= size then
        CCFRaft.Sparse.QueueEncodingScale.runFixtures size summarize
        return 0
    ( <- IO.getStderr).putStrLn "fixture event count must be a natural number >= 3"
    return 1
  if let ["--mixed-fixtures", count, keyCount] := args then
    if let (some size, some keys) := (count.toNat?, keyCount.toNat?) then
      if 3 <= size && 0 < keys && keys < size then
        CCFRaft.Sparse.QueueEncodingScale.runMixedFixtures size keys summarize
        return 0
    ( <- IO.getStderr).putStrLn "mixed fixtures require event count >= 3 and 0 < keys < events"
    return 1
  let some sizes := args.mapM String.toNat? |
    ( <- IO.getStderr).putStrLn
      "usage: QueueEncodingScaleMain.lean [--summarize] [event-count ... | --fixtures event-count | --mixed-fixtures event-count keys]"
    return 1
  CCFRaft.Sparse.QueueEncodingScale.run (if sizes.isEmpty then [20, 40, 80] else sizes) summarize
  return 0
