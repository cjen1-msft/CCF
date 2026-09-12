-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendReceive
import Sparse.NativeAppendReceiveFixtureInstructions

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeAppendReceiveFixtures

open Lean NativeSmt NativeEncode

def fixture (index : Nat) (item : Json) : Except String Json := do
  let input <- decodeDocumentWith fixtureInstruction (<- field item "trace")
  let program : EncodeM input.width Unit := do
    initialFrameDomains input.width
    for instruction in input.instructions do
      match instruction with
      | .inr (source, destination) => receiveAppend source destination
      | .inl observation => frameInstruction observation
  let (_, final) <- program.run (initialEncoding input.width input.bootstrap)
  return Json.mkObj [("name", toJson s!"append-receive-{index}"),
    ("script", toJson (renderScript final.assertions.toList)), ("expected", <- field item "expected")]

end CCFRaft.NativeAppendReceiveFixtures

def main : IO Unit := do
  let input <- (<- IO.getStdin).readToEnd
  let result := do
    let parsed <- Lean.Json.parse input
    ((<- parsed.getArr?).toList.zipIdx).mapM fun (item, index) =>
      CCFRaft.NativeAppendReceiveFixtures.fixture index item
  match result with
  | .ok fixtures => IO.println (Lean.toJson fixtures).compress
  | .error error => throw (IO.userError error)
