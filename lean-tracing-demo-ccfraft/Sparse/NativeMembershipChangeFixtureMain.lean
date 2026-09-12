-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeMembershipChange
import Sparse.NativeMembershipFixtureInstructions

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeMembershipChangeFixtures

open Lean NativeSmt NativeEncode NativeMembershipFixtures

def fixture (index : Nat) (item : Json) : Except String Json := do
  let input <- decodeDocumentWith fixtureInstruction (<- field item "trace")
  let program : EncodeM input.width Unit := do
    initialFrameDomains input.width
    for instruction in input.instructions do
      match instruction with
      | .inr (source, configuration) => membershipChange source configuration
      | .inl observation => frameInstruction observation
  let (_, final) <- program.run (initialEncoding input.width input.bootstrap)
  return Json.mkObj [("name", toJson s!"membership-change-{index}"),
    ("script", toJson (renderScript final.assertions.toList)), ("expected", <- field item "expected")]

end CCFRaft.NativeMembershipChangeFixtures

def main : IO Unit := do
  let input <- (<- IO.getStdin).readToEnd
  let result := do
    let parsed <- Lean.Json.parse input
    ((<- parsed.getArr?).toList.zipIdx).mapM fun (item, index) =>
      CCFRaft.NativeMembershipChangeFixtures.fixture index item
  match result with
  | .ok fixtures => IO.println (Lean.toJson fixtures).compress
  | .error error => throw (IO.userError error)
