-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeEncode

def main (arguments : List String) : IO UInt32 := do
  let input <- (← IO.getStdin).readToEnd
  let result := do
    let document <- Lean.Json.parse input
    if input.trimAscii.toString != document.compress then
      throw "expected canonical JSON: sorted keys, no extra whitespace or duplicate keys"
    match arguments with
    | [] => CCFRaft.NativeEncode.encode document
    | ["--batch"] => do
      let scripts <- (<- document.getArr?).mapM CCFRaft.NativeEncode.encode
      return (Lean.toJson scripts).compress
    | _ => throw "usage: NativeEncodeMain [--batch]"
  match result with
  | .ok output =>
    IO.println output
    return 0
  | .error error =>
    (← IO.getStderr).putStrLn s!"native encoding error: {error}"
    return 2
