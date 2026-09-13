-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeFrameEncode
import Sparse.NativeVoteResponse

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeReceiveVoteResponseFixtures

open Lean NativeSmt NativeEncode

private def fixtureInstruction (width : PNat) (names : Array String) (value : Json) :
    Except String (FrameInstruction width ⊕ (Bool × Fin width × Fin width)) := do
  let kind <- (<- field value "kind").getStr?
  if kind = "receiveRequestVoteResponse" || kind = "receiveRequestPreVoteResponse" then
    fields value ["kind", "source", "destination"]
    return .inr (kind = "receiveRequestPreVoteResponse",
      <- resolve width names (<- field value "source"),
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
      | .inr (preVote, source, destination) =>
        let before <- get
        receiveVoteResponse preVote source destination
        unless (<- get).next == before.next + 18 do
          throw "vote response fixture has incorrect fresh references"
  let (_, final) <- program.run (initialEncoding input.width input.bootstrap)
  return Json.mkObj [
    ("name", toJson s!"vote-response-{index}"),
    ("script", toJson (renderScript final.assertions.toList)),
    ("expected", <- field item "expected")]

end CCFRaft.NativeReceiveVoteResponseFixtures

def main : IO Unit := do
  let input <- (<- IO.getStdin).readToEnd
  let result := do
    let parsed <- Lean.Json.parse input
    ((<- parsed.getArr?).toList.zipIdx).mapM fun (item, index) =>
      CCFRaft.NativeReceiveVoteResponseFixtures.fixture index item
  match result with
  | .ok fixtures => IO.println (Lean.toJson fixtures).compress
  | .error error => throw (IO.userError error)
