-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeMembershipWrites
import Sparse.NativeNodeRowFixtureTerms
import Lean.Data.Json

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeMembershipWriteFixtures

open Lean NativeSmt NativeEncode NativeNodeRowWriteFixtures

def cases : Except String Json := do
  let mut rejected := #[]
  for kind in ["added", "completed", "row"] do
    for symbol in [24, 25, 74, 92, 1024] do
      let values := rowTerms (row 3)
      let operation : EncodeM 3 Unit := membershipWrites 0
        (if kind = "added" then .free (.bits 3) symbol else .bits 0)
        (if kind = "row" then { values with currentTerm := .free .int symbol } else values)
        (if kind = "completed" then .free (.bits 3) symbol else .bits 0)
      match operation.run (initialEncoding 3 {0, 1}) with
      | .error error =>
        rejected := rejected.push (Json.mkObj [
          ("kind", toJson kind), ("symbol", toJson symbol), ("error", toJson error)])
      | .ok _ => throw "membership writes accepted an unallocated input symbol"
  return toJson rejected

end CCFRaft.NativeMembershipWriteFixtures

def main : IO Unit :=
  match CCFRaft.NativeMembershipWriteFixtures.cases with
  | .ok result => IO.println result.compress
  | .error error => throw (IO.userError error)
