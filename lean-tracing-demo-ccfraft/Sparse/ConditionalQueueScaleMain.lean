import Sparse.ConditionalQueueTraceEncoding
import Lean.Data.Json

set_option autoImplicit false

namespace CCFRaft.Sparse.ConditionalQueueScale

open Smt (Term)
open QueueStream (Event)
open QueueEncoding (InputInt)

structure Fixture where
  name : String
  input : SmtScript.Formula
  entries : List ConditionalQueueEncoding.Entry
  finalLength : Nat
  expected : String
  activeWrites : Nat

def makeFixture (size keys : Nat) (cycle symbolic alternating : Bool) (verdict : String) : Fixture :=
  let actions := size - 1
  let active := fun index => !alternating || index % 2 == 0
  let key := fun index =>
    let id := (if cycle then index / 2 else index) % keys
    if symbolic then InputInt.symbolic id else .literal id
  let entries := (List.range actions).map fun index =>
    (Term.unknown .bool index, if cycle && index % 2 == 1 then Event.pop (key index) else .send (key index))
  let activeWrites := ((List.range actions).filter active).length
  let distinctActive := ((List.range actions).filter active).map fun index =>
    (if cycle then index / 2 else index) % keys
  let bound := if cycle && !alternating then actions % 2 else distinctActive.dedup.length
  let finalLength := if verdict == "unsat" then bound + 1 else if verdict == "alias" then 1 else bound
  { name := s!"{size}-{if cycle then s!"cycle{keys}" else "send"}-{if symbolic then "symbolic" else "literal"}-{if alternating then "alternating" else "all"}-{verdict}"
    input := (List.range size).map fun index =>
      .equal (.unknown .bool index) (.boolean (index == actions || active index))
    entries := entries ++ [(Term.unknown .bool actions, .length finalLength)]
    finalLength
    expected := if verdict == "unsat" then "unsat" else "sat"
    activeWrites }

structure Emission where
  script : String
  assertions : Nat
  commands : Nat
  formulaNs : Nat
  commandsNs : Nat
  textNs : Nat

-- Reading through the ref prevents a repeated warm-up expression from being shared.
def emit (fixtureRef : IO.Ref Fixture) : IO Emission := do
  let fixture <- fixtureRef.get
  let start <- IO.monoNanosNow
  let formulas <- IO.mkRef (ConditionalQueueTraceEncoding.encode fixture.input fixture.entries (.literal 0))
  let encoded <- IO.monoNanosNow
  let formula <- formulas.get
  let commands <- IO.mkRef (SmtScript.compile formula)
  let compiled <- IO.monoNanosNow
  let commandList <- commands.get
  let text <- IO.mkRef (SmtScript.renderCommands commandList)
  let finished <- IO.monoNanosNow
  let script <- text.get
  return Emission.mk script formula.length commandList.length
    (encoded - start) (compiled - encoded) (finished - compiled)

def run (fixture : Fixture) : IO Unit := do
  let fixtureRef <- IO.mkRef fixture
  let warm <- emit fixtureRef
  let warmNs := warm.formulaNs + warm.commandsNs + warm.textNs
  let warmBytes := warm.script.utf8ByteSize
  let measured <- emit fixtureRef
  unless warmBytes == measured.script.utf8ByteSize do
    throw (IO.userError "warm and measured script sizes differ")
  let writes := QueueReadback.writeCount (fixture.entries.map Prod.snd)
  let keys := (ConditionalQueueEncoding.keysOf fixture.entries).length
  let pops := (ConditionalQueueTraceEncoding.popRows fixture.entries).length
  IO.println (Lean.Json.mkObj [
    ("case", Lean.toJson fixture.name),
    ("original_events", Lean.toJson fixture.entries.length),
    ("static_writes", Lean.toJson writes),
    ("active_writes", Lean.toJson fixture.activeWrites),
    ("inactive_writes", Lean.toJson (writes - fixture.activeWrites)),
    ("tracked_keys", Lean.toJson keys),
    ("grid_rows", Lean.toJson (writes * keys)),
    ("histogram_rows", Lean.toJson ((pops + 1) * keys)),
    ("initial_length", Lean.toJson (0 : Nat)),
    ("final_length", Lean.toJson fixture.finalLength),
    ("expected", Lean.toJson fixture.expected),
    ("assertions", Lean.toJson measured.assertions),
    ("commands", Lean.toJson measured.commands),
    ("formula_ns", Lean.toJson measured.formulaNs),
    ("commands_ns", Lean.toJson measured.commandsNs),
    ("text_ns", Lean.toJson measured.textNs),
    ("encoding_ns", Lean.toJson (measured.formulaNs + measured.commandsNs + measured.textNs)),
    ("warm_encoding_ns", Lean.toJson warmNs),
    ("bytes", Lean.toJson measured.script.utf8ByteSize),
    ("script", Lean.toJson measured.script)]).compress
  ( <- IO.getStdout).flush

end CCFRaft.Sparse.ConditionalQueueScale

def main (args : List String) : IO UInt32 := do
  if let [count, shape, keyMode, guardMode, verdict] := args then
    if let some size := count.toNat? then
      let cycle := shape != "send"
      let keys := if shape == "cycle4" then 4 else if cycle then (size - 1) / 2 else size - 1
      if size >= 10 && size % 2 == 0 &&
          ["cycle4", "cycleDistinct", "send"].contains shape &&
          ["literal", "symbolic"].contains keyMode &&
          ["alternating", "all"].contains guardMode &&
          ["sat", "unsat", "alias"].contains verdict &&
          (verdict != "alias" || (keyMode == "symbolic" && guardMode == "alternating")) then
        CCFRaft.Sparse.ConditionalQueueScale.run
          (CCFRaft.Sparse.ConditionalQueueScale.makeFixture size keys cycle (keyMode == "symbolic")
            (guardMode == "alternating") verdict)
        return 0
  ( <- IO.getStderr).putStrLn
    "usage: ConditionalQueueScaleMain EVEN_EVENTS>=10 cycle4|cycleDistinct|send literal|symbolic alternating|all sat|unsat|alias (alias requires symbolic alternating)"
  return 1
