-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Prototype.BranchReduction

def main (arguments : List String) : IO UInt32 := do
  let text <- (<- IO.getStdin).readToEnd
  let result : Except String Lean.Json := do
    let document <- Lean.Json.parse text
    match arguments with
    | ["baseline"] =>
      return Lean.Json.mkObj [
        ("schema", Lean.toJson "ccfraft-lean-branch-prototype/v1"),
        ("proof_status", Lean.toJson "unchanged baseline encoder"),
        ("decisions", Lean.toJson ([] : List Lean.Json)),
        ("encoding", <- CCFRaft.NativeEncode.encodeParameterizedFrameDetails document)]
    | ["guarded"] => CCFRaft.BranchPrototype.encodePrototype document true
    | ["specialised"] => CCFRaft.BranchPrototype.encodePrototype document false
    | _ => throw "expected baseline, guarded, or specialised"
  match result with
  | .ok report =>
    IO.println report.compress
    return 0
  | .error error =>
    (<- IO.getStderr).putStrLn s!"branch prototype: {error}"
    return 2
