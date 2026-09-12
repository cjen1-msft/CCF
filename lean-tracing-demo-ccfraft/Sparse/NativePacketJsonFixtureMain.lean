-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativePacketJson
import Sparse.NativeArrayFixtureJson

set_option autoImplicit false
set_option warningAsError true

private def roundTrip (input : Lean.Json) : Except String Lean.Json := do
  let packets <- input.getArr?
  let values <- packets.toList.mapM fun value => do
    let packet <- CCFRaft.NativeEncode.decodePacket 3 #["a", "b", "c"] value
    pure (CCFRaft.NativeArrayFixtures.messageJson packet)
  return Lean.toJson values

def main : IO Unit := do
  let input <- (<- IO.getStdin).readToEnd
  match Lean.Json.parse input >>= roundTrip with
  | .error message => throw (IO.userError message)
  | .ok result => IO.println result.compress
