-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeParameterizedFrame

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeParameterizedFrameFixtures

open Lean NativeEncode

def fixture (index : Nat) (item : Json) : Except String Json := do
  let document <- field item "trace"
  let compiled <- compileParameterizedFrame document
  return Json.mkObj [
    ("name", toJson s!"parameterized-frame-{index}"),
    ("script", toJson (NativeSmt.renderScript compiled.assertions.toList)),
    ("groups", toJson compiled.groups),
    ("expected", <- field item "expected")]

end CCFRaft.NativeParameterizedFrameFixtures

def main (arguments : List String) : IO Unit := do
  let input <- (<- IO.getStdin).readToEnd
  let result := do
    let parsed <- Lean.Json.parse input
    let items <- parsed.getArr?
    if arguments = ["--decode"] then
      return items.toList.map fun document =>
        match CCFRaft.NativeEncode.decodeParameterizedFrameDocument document with
        | .ok _ => Lean.Json.null
        | .error error => Lean.toJson error
    else if arguments.isEmpty then
      (items.toList.zipIdx).mapM fun (item, index) =>
        CCFRaft.NativeParameterizedFrameFixtures.fixture index item
    else
      throw "expected no arguments or --decode"
  match result with
  | .ok fixtures => IO.println (Lean.toJson fixtures).compress
  | .error error => throw (IO.userError error)
