-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeFrameEncode
import Sparse.NativeClientRequest

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeClientRequestFixtures

open Lean NativeSmt NativeEncode

def fixtureInstruction (width : PNat) (names : Array String) (value : Json) :
    Except String (FrameInstruction width ⊕ (Fin width × Nat)) := do
  if (<- (<- field value "kind").getStr?) = "clientRequest" then
    fields value ["kind", "node", "transaction"]
    return .inr ((<- resolve width names (<- field value "node")),
      (<- (<- field value "transaction").getNat?))
  else
    return .inl (<- decodeFrameInstruction width names value)

def fixture (index : Nat) (item : Json) : Except String Json := do
  let input <- decodeDocumentWith fixtureInstruction (<- field item "trace")
  let program : EncodeM input.width Unit := do
    initialFrameDomains input.width
    for instruction in input.instructions do
      match instruction with
      | .inl instruction => frameInstruction instruction
      | .inr (source, transaction) => clientRequest source (.integer transaction)
  let (_, final) <- program.run (initialEncoding input.width input.bootstrap)
  return Json.mkObj [
    ("name", toJson s!"client-request-{index}"),
    ("script", toJson (renderScript final.assertions.toList)),
    ("expected", <- field item "expected")]

end CCFRaft.NativeClientRequestFixtures

def main : IO Unit := do
  let input <- (<- IO.getStdin).readToEnd
  let result := do
    let parsed <- Lean.Json.parse input
    ((<- parsed.getArr?).toList.zipIdx).mapM fun (item, index) =>
      CCFRaft.NativeClientRequestFixtures.fixture index item
  match result with
  | .ok fixtures => IO.println (Lean.toJson fixtures).compress
  | .error error => throw (IO.userError error)
