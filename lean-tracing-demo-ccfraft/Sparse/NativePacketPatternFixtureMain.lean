-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativePacketPatternJson
import Sparse.NativePacketPatternTerm
import Sparse.NativeScript

set_option autoImplicit false
set_option warningAsError true

open CCFRaft CCFRaft.NativeEncode NativeSmt Lean

private def compileCase (input : Json) : Except String Json := do
  fields input ["name", "packet", "pattern"]
  let name <- (<- field input "name").getStr?
  let packet <- decodePacket 3 #["a", "b", "c"] (<- field input "packet")
  let pattern <- field input "pattern"
  match decodePacketPattern 3 #["a", "b", "c"] pattern with
  | .error message => return Json.mkObj [("name", toJson name), ("error", toJson message)]
  | .ok pattern =>
    let value : Expr (packetTy 3) := .free (packetTy 3) 0
    let observed := packetPatternTerm pattern value
    let script := renderScript [
      .equal value (packetTerm packet),
      observed,
      .forall_ .bool (packetPatternTerm pattern (value.weaken .bool)),
      .forall_ .int (packetPatternTerm pattern (value.weaken .int))] true
    return Json.mkObj [
      ("name", toJson name),
      ("expected", toJson (if pattern.matches packet then "sat" else "unsat")),
      ("script", toJson script)]

def main : IO Unit := do
  let input <- (<- IO.getStdin).readToEnd
  match Json.parse input >>= fun value => do
      let cases <- value.getArr?
      cases.toList.mapM compileCase with
  | .error message => throw (IO.userError message)
  | .ok cases => IO.println (toJson cases).compress
