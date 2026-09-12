-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeQueueStoreEncoding
import Sparse.NativeQueuePopEncoding
import Sparse.NativeFrameEncode

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeQueueStoreFixtures

open Lean NativeSmt NativeEncode

def identities : List (Fin 3) := [0, 1, 2]

def initialNetwork (head length : Int) : NativeArrayQueue.Network (Fin 3) Nat :=
  fun _ source =>
    { head := head.toNat, length := length.toNat, cells := fun _ => defaultQueuePacket (width := 3) source }

def initialQueues (head length : Int) : EncodeM 3 Unit := do
  let columns := (<- get).toColumns
  for destination in identities do
    for source in identities do
      assertion (.equal
        (.select (.select (.free (.array .int (.array .int .int)) columns.queueHead)
          (.integer destination.val)) (.integer source.val)) (.integer head))
      assertion (.equal
        (.select (.select (.free (.array .int (.array .int .int)) columns.queueLength)
          (.integer destination.val)) (.integer source.val)) (.integer length))
      if 0 < length.toNat then
        for index in [0, length.toNat - 1] do
          assertion (.equal
            (.select (queueCellsTerm columns.queueCells (.integer destination.val) (.integer source.val))
              (.integer (head.toNat + index))) (packetTerm (defaultQueuePacket (width := 3) source)))

def observe (network : NativeArrayQueue.Network (Fin 3) Nat) (initialLength count : Nat)
    (conflict : Bool) : EncodeM 3 Unit := do
  for destination in identities do
    for source in identities do
      let queue := network destination source
      let expected := queue.length + if conflict && destination == 1 && source == 0 then 1 else 0
      frameInstruction (.queueLength source destination expected)
      for index in [0, initialLength - 1] ++ (List.range count).map (initialLength + ·) do
        if index < queue.length then
          frameInstruction (.queuePoint source destination index (queue.cells (queue.head + index)))

def fixture (name : String) (packets : List (Message (Fin 3) Nat)) (head length : Int)
    (conflict : Bool) : Except String Json := do
  let program : EncodeM 3 Unit := do
    initialQueues head length
    let mut network := initialNetwork head length
    for (packet, index) in packets.zipIdx do
      if index == 0 then
        assertion (.equal (.free (packetTy 3) 23) (packetTerm (width := 3) packet))
        pushQueue (width := 3) packet.destination packet.source (.free (packetTy 3) 23)
      else
        pushQueue (width := 3) packet.destination packet.source (packetTerm (width := 3) packet)
      network := NativeArrayQueue.send network packet
      observe network length.toNat (index + 1) false
    if conflict then
      observe network length.toNat packets.length true
  let (_, final) <- program.run (initialEncoding 3 {0})
  unless final.next == 24 + 2 * packets.length && final.queueHead == 22 &&
      final.queueLength == final.next - 2 && final.queueCells == final.next - 1 do
    throw "queue fixture has incorrect fresh references"
  return Json.mkObj [
    ("name", toJson name), ("script", toJson (renderScript final.assertions.toList)),
    ("expected", toJson (if conflict then "unsat" else "sat"))]

def rejected (before : Encoding 3) (id : Nat) : Except String Json :=
  match (pushQueue (width := 3) 1 0 (.free (packetTy 3) id)).run before with
  | .error message => .ok (Json.mkObj [("next", toJson before.next), ("id", toJson id), ("error", toJson message)])
  | .ok _ => .error s!"queue fixture unexpectedly accepted symbol {id} at counter {before.next}"

def observeQueue (network : NativeArrayQueue.Network (Fin 3) Nat) (destination source : Fin 3) :
    EncodeM 3 Unit := do
  let columns := (<- get).toColumns
  let queue := network destination source
  frameInstruction (.queueLength source destination queue.length)
  assertion (.equal (queueScalarTerm columns.queueHead (.integer destination.val) (.integer source.val))
    (.integer queue.head))
  for index in List.range queue.length do
    frameInstruction (.queuePoint source destination index (queue.cells (queue.head + index)))

def popFixture (name : String) (packets : List (Message (Fin 3) Nat)) (head length : Int)
    (conflict : Bool) : Except String Json := do
  let program : EncodeM 3 Unit := do
    initialQueues head length
    let mut network := initialNetwork head length
    for packet in packets do
      let before <- get
      popQueue packet.destination packet.source
      let popped <- get
      unless popped.next == before.next + 2 && popped.queueLength == before.next &&
          popped.queueHead == before.next + 1 && popped.queueCells == before.queueCells do
        throw "pop fixture has incorrect fresh references"
      network := NativeArrayQueue.popSource network packet.destination packet.source
      observeQueue network packet.destination packet.source
      for _ in [0, 1] do
        pushQueue packet.destination packet.source (packetTerm packet)
        network := NativeArrayQueue.send network packet
        observeQueue network packet.destination packet.source
      for _ in [0, 1, 2] do
        popQueue packet.destination packet.source
        network := NativeArrayQueue.popSource network packet.destination packet.source
        observeQueue network packet.destination packet.source
    for destination in identities do
      for source in identities do
        observeQueue network destination source
    if conflict then
      frameInstruction (.queueLength 0 1 ((network 1 0).length + 1))
  let (_, final) <- program.run (initialEncoding 3 {0})
  return Json.mkObj [
    ("name", toJson name), ("script", toJson (renderScript final.assertions.toList)),
    ("expected", toJson (if conflict then "unsat" else "sat"))]

def cases (input : Json) : Except String Json := do
  let mut fixtures := #[]
  let mut popFixtures := #[]
  for (samples, kind) in (<- input.getArr?).toList.zipIdx do
    let packets <- (<- samples.getArr?).toList.mapM (decodePacket 3 #["a", "b", "c"])
    if packets.isEmpty then throw "queue fixture requires packets"
    for (head, length) in [(0, 0), (3, 2), (10 ^ 30, 10 ^ 30), (-3, -5)] do
      for conflict in [false, true] do
        fixtures := fixtures.push (<- fixture s!"queue-store-{kind}-{head}-{length}-{conflict}"
          packets head length conflict)
    for (head, length) in [(0, 0), (3, 1), (10 ^ 30, 2), (-3, -5)] do
      for conflict in [false, true] do
        popFixtures := popFixtures.push (<- popFixture s!"queue-pop-{kind}-{head}-{length}-{conflict}"
          packets head length conflict)
  let before := initialEncoding 3 {0}
  let (_, after) <- (pushQueue (width := 3) 1 0 (packetTerm (.proposeVoteRequest
    { term := 1, source := 0, destination := 1 }))).run before
  let errors <- [before.next, before.next + 1, before.next + 1000].mapM (rejected before)
  let laterErrors <- [after.next, after.next + 1].mapM (rejected after)
  return Json.mkObj [("fixtures", toJson fixtures), ("popFixtures", toJson popFixtures),
    ("rejected", toJson (errors ++ laterErrors))]

end CCFRaft.NativeQueueStoreFixtures

def main : IO Unit := do
  let input <- (<- IO.getStdin).readToEnd
  match Lean.Json.parse input >>= CCFRaft.NativeQueueStoreFixtures.cases with
  | .ok result => IO.println result.compress
  | .error message => throw (IO.userError message)
