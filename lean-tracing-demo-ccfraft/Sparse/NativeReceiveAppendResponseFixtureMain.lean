-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeFrameEncode
import Sparse.NativeAppendResponse

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeReceiveAppendResponseFixtures

open Lean NativeSmt NativeEncode

private def fixtureInstruction (width : PNat) (names : Array String) (value : Json) :
    Except String (FrameInstruction width ⊕ (Fin width × Fin width)) := do
  let kind <- (<- field value "kind").getStr?
  if kind = "receiveAppendEntriesResponse" then
    fields value ["kind", "source", "destination"]
    return .inr (<- resolve width names (<- field value "source"),
      <- resolve width names (<- field value "destination"))
  else
    return .inl (<- decodeFrameInstruction width names value)

private def fixture (index : Nat) (item : Json) : Except String Json := do
  let input <- decodeDocumentWith fixtureInstruction (<- field item "trace")
  let program : EncodeM input.width Unit := do
    initialFrameDomains input.width
    for instruction in input.instructions do
      match instruction with
      | .inl observation => frameInstruction observation
      | .inr (source, destination) =>
        let before <- get
        receiveAppendResponse source destination
        unless (<- get).next == before.next + 19 do
          throw "append response fixture has incorrect fresh references"
  let (_, final) <- program.run (initialEncoding input.width input.bootstrap)
  return Json.mkObj [
    ("name", toJson s!"append-response-{index}"),
    ("script", toJson (renderScript final.assertions.toList)),
    ("expected", <- field item "expected")]

end CCFRaft.NativeReceiveAppendResponseFixtures

def main : IO Unit := do
  let input <- (<- IO.getStdin).readToEnd
  let result := do
    let parsed <- Lean.Json.parse input
    ((<- parsed.getArr?).toList.zipIdx).mapM fun (item, index) =>
      CCFRaft.NativeReceiveAppendResponseFixtures.fixture index item
  match result with
  | .ok fixtures => IO.println (Lean.toJson fixtures).compress
  | .error error => throw (IO.userError error)
