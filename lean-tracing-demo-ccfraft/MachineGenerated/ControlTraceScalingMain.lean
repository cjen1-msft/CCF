-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.TraceEncodingProofs
import TraceCertificate

set_option autoImplicit false

def main (args : List String) : IO UInt32 := do
  unless !args.isEmpty do
    (← IO.getStderr).putStrLn "usage: ControlTraceScalingMain.lean CERTIFICATE..."
    return 1
  for path in args do
    let text ← IO.FS.readFile path
    match Lean.Json.parse text >>= CCFRaft.TraceCertificate.decode with
    | .error error =>
        (← IO.getStderr).putStrLn s!"{path}: {error}"
        return 1
    | .ok input =>
        let formula := (CCFRaft.TraceEncoding.checkedEncoder input.unknowns.size).encode
          input.bounds input.entry input.trace
        let occurrences := formula.foldl (fun count group =>
          group.clauses.foldl (fun count clause =>
            count + clause.expression.bindings.length) count) 0
        IO.println (Lean.Json.mkObj
          [("certificate", Lean.toJson path),
           ("binding_occurrences", Lean.toJson occurrences)]).compress
  return 0
