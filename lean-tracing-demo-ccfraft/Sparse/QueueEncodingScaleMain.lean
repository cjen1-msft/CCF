import Sparse.QueueInitialEncoding
import Lean.Data.Json

namespace CCFRaft.Sparse.QueueEncodingScale

open QueueStream

private def events (size : Nat) (cycle : Bool) : List (Event QueueEncoding.InputInt) :=
  (List.range size).map fun index =>
    if cycle && index % 2 == 1 then .pop (.literal 1) else .send (.literal 1)

def run (sizes : List Nat) : IO Unit := do
  for cycle in [false, true] do
    for size in sizes do
      let inputs <- IO.mkRef (events size cycle)
      let trace <- inputs.get
      let start <- IO.monoNanosNow
      let formulas <- IO.mkRef (QueueInitialEncoding.encode [] trace (.literal 0))
      let encoded <- IO.monoNanosNow
      let formula <- formulas.get
      let commands <- IO.mkRef (SmtScript.compile formula)
      let compiled <- IO.monoNanosNow
      let commandList <- commands.get
      let result <- IO.mkRef (SmtScript.renderCommands commandList)
      let finish <- IO.monoNanosNow
      let script <- result.get
      IO.println (Lean.Json.mkObj [
        ("case", Lean.toJson s!"{if cycle then "cycle" else "send"}-{size}"),
        ("events", Lean.toJson size),
        ("encoding_ns", Lean.toJson (finish - start)),
        ("formula_ns", Lean.toJson (encoded - start)),
        ("commands_ns", Lean.toJson (compiled - encoded)),
        ("text_ns", Lean.toJson (finish - compiled)),
        ("bytes", Lean.toJson script.utf8ByteSize)]).compress
      ( <- IO.getStdout).flush

end CCFRaft.Sparse.QueueEncodingScale

def main (args : List String) : IO UInt32 := do
  let some sizes := args.mapM String.toNat? |
    ( <- IO.getStderr).putStrLn "usage: QueueEncodingScaleMain.lean [event-count ...]"
    return 1
  CCFRaft.Sparse.QueueEncodingScale.run (if sizes.isEmpty then [20, 40, 80] else sizes)
  return 0
