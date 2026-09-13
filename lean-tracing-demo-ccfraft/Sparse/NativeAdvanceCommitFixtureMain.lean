-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAdvanceCommit
import Sparse.NativeFrameEncode

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeAdvanceCommitFixtures

open Lean NativeSmt NativeEncode

def fixtureInstruction (width : PNat) (names : Array String) (value : Json) :
    Except String (FrameInstruction width ⊕ Fin width) := do
  if (<- (<- field value "kind").getStr?) = "advanceCommitIndex" then
    fields value ["kind", "node"]
    return .inr (<- resolve width names (<- field value "node"))
  else
    return .inl (<- decodeFrameInstruction width names value)

def fixture (index : Nat) (item : Json) : Except String Json := do
  let input <- decodeDocumentWith fixtureInstruction (<- field item "trace")
  let program : EncodeM input.width Unit := do
    initialFrameDomains input.width
    for instruction in input.instructions do
      match instruction with
      | .inl observation => frameInstruction observation
      | .inr source => advanceCommitIndex source
  let (_, final) <- program.run (initialEncoding input.width input.bootstrap)
  return Json.mkObj [
    ("name", toJson s!"advance-commit-{index}"),
    ("script", toJson (renderScript final.assertions.toList)),
    ("expected", <- field item "expected")]

end CCFRaft.NativeAdvanceCommitFixtures

def main : IO Unit := do
  let input <- (<- IO.getStdin).readToEnd
  let result := do
    let parsed <- Lean.Json.parse input
    ((<- parsed.getArr?).toList.zipIdx).mapM fun (item, index) =>
      CCFRaft.NativeAdvanceCommitFixtures.fixture index item
  match result with
  | .ok fixtures => IO.println (Lean.toJson fixtures).compress
  | .error error => throw (IO.userError error)
