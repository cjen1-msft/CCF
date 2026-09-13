-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeQueuePattern
import Sparse.NativePacketPatternJson
import Sparse.NativeScript

set_option autoImplicit false
set_option warningAsError true

open CCFRaft CCFRaft.NativeEncode NativeSmt Lean

private def compileCase (input : Json) : Except String Json := do
  fields input ["name", "packet", "pattern", "source", "head", "length", "index", "invalidTerm"]
  let name <- (<- field input "name").getStr?
  let packet <- decodePacket 3 #["a", "b", "c"] (<- field input "packet")
  let pattern <- decodePacketPattern 3 #["a", "b", "c"] (<- field input "pattern")
  let source <- resolve 3 #["a", "b", "c"] (<- field input "source")
  let head <- natural (<- field input "head")
  let length <- natural (<- field input "length")
  let index <- natural (<- field input "index")
  let invalidTerm <- (<- field input "invalidTerm").getBool?
  let value : Expr (packetTy 3) :=
    if invalidTerm then
      .pair (.pair (.integer (-1)) (.snd (.fst (packetTerm packet)))) (.snd (packetTerm packet))
    else packetTerm packet
  let cells : Expr (.array .int (packetTy 3)) := .free (.array .int (packetTy 3)) 0
  let selected := queuePattern source (.integer head) (.integer length) cells index pattern
  let normalized := if invalidTerm || packet.source != source then defaultQueuePacket source else packet
  let expected := index < length && pattern.matches normalized
  return Json.mkObj [
    ("name", toJson name),
    ("expected", toJson (if expected then "sat" else "unsat")),
    ("script", toJson (renderScript [
      .equal (.select cells (.integer (head + index))) value,
      selected,
      .forall_ .bool (queuePattern source (.integer head) (.integer length)
        (cells.weaken .bool) index pattern),
      .forall_ .int (queuePattern source (.integer head) (.integer length)
        (cells.weaken .int) index pattern)] true))]

def main : IO Unit := do
  let input <- (<- IO.getStdin).readToEnd
  match Json.parse input >>= fun value => do
      let cases <- value.getArr?
      cases.toList.mapM compileCase with
  | .error message => throw (IO.userError message)
  | .ok cases => IO.println (toJson cases).compress
