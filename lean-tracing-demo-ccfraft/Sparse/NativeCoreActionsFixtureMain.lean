-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendReceive
import Sparse.NativeAppendReceiveFixtureInstructions
import Sparse.NativeMembershipChange
import Sparse.NativeMembershipFixtureInstructions

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeCoreActionFixtures

open Lean NativeSmt NativeEncode

def fixtureInstruction (width : PNat) (names : Array String) (value : Json) :
    Except String
      (FrameInstruction width ⊕ ((Fin width × Fin width) ⊕ (Fin width × Finset (Fin width)))) := do
  if (<- (<- field value "kind").getStr?) = "receiveAppendEntries" then
    match <- NativeAppendReceiveFixtures.fixtureInstruction width names value with
    | .inl instruction => return .inl instruction
    | .inr receive => return .inr (.inl receive)
  else
    match <- NativeMembershipFixtures.fixtureInstruction width names value with
    | .inl instruction => return .inl instruction
    | .inr membership => return .inr (.inr membership)

def fixture (index : Nat) (item : Json) : Except String Json := do
  let input <- decodeDocumentWith fixtureInstruction (<- field item "trace")
  let program : EncodeM input.width Unit := do
    initialFrameDomains input.width
    for instruction in input.instructions do
      match instruction with
      | .inl observation => frameInstruction observation
      | .inr (.inl (source, destination)) => receiveAppend source destination
      | .inr (.inr (source, configuration)) => membershipChange source configuration
  let (_, final) <- program.run (initialEncoding input.width input.bootstrap)
  return Json.mkObj [("name", toJson s!"core-actions-{index}"),
    ("script", toJson (renderScript final.assertions.toList)), ("expected", <- field item "expected")]

end CCFRaft.NativeCoreActionFixtures

def main : IO Unit := do
  let input <- (<- IO.getStdin).readToEnd
  let result := do
    let parsed <- Lean.Json.parse input
    ((<- parsed.getArr?).toList.zipIdx).mapM fun (item, index) =>
      CCFRaft.NativeCoreActionFixtures.fixture index item
  match result with
  | .ok fixtures => IO.println (Lean.toJson fixtures).compress
  | .error error => throw (IO.userError error)
