-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAllocation
import Sparse.NativeNodeRowFixtureTerms
import Sparse.NativeFrameEncode
import Sparse.NativeArrayFixtureJson

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeAllocationFixtures

open Lean NativeSmt NativeEncode NativeArrayFixtures NativeNodeRowWriteFixtures

private instance : Bootstrap (Fin 3) :=
  { configuration := {0, 1}, leader := 0, leader_mem := by simp }

def members (mask : Nat) : Finset (Fin 3) :=
  ((List.finRange 3).filter fun node => mask.testBit node.val).toFinset

def fixture (presentMask addedMask mode mutation : Nat) : Except String Json := do
  let target : Fin 3 := ⟨(presentMask + addedMask) % 3, Nat.mod_lt _ (by decide)⟩
  let requested := members addedMask
  let added := if mode = 0 then requested ∩ {target} else requested
  let second := members ((addedMask + 3) % 8)
  let state : State (Fin 3) Nat :=
    { nodes := NodeStore.ofFinset (members presentMask)
        (fun node => row (presentMask + node.val))
      network := fun node => [
        .proposeVoteRequest { term := 7, source := node, destination := node },
        .requestVoteResponse { term := 2, source := 0, destination := node, voteGranted := true },
        .requestVoteResponse { term := 2, source := 0, destination := node, voteGranted := true }]
      hasJoined := {0, 2}, submittedTxIds := {9, 10 ^ 30}
      preVoteStatus := fun node => if node = 1 then .capable else .enabled
      retirementCompleted := fun node => {node, 1} }
  let once := { state with nodes := state.nodes.allocate added }
  let actual := if mode = 2 then { once with nodes := once.nodes.allocate second } else once
  let observed := if mutation = 0 then actual else
    if mutation = 22 then
      let present := ((List.finRange 3).filter fun node => decide (actual.allocated node)).toFinset
      { actual with nodes := NodeStore.ofFinset (toggle target present) actual.nodes }
    else mutate actual target mutation
  let decode := fun frame =>
    (frameObservations frame [9, 10 ^ 30]).toArray.mapM (decodeFrameInstruction 3 #["a", "b", "c"])
  let before <- decode state
  let after <- decode observed
  let program : EncodeM 3 Unit := do
    initialFrameDomains 3
    for node in List.finRange 3 do
      unless decide (state.allocated node) do
        for (item, column) in (nodeRowWriteDefinitions (width := 3) {} node
            (rowTerms (row 19))).drop 1 |>.zipIdx do
          if column + 1 != 6 then
            assertion (.equal (.free item.1 (column + 1)) item.2)
      for position in ([-7, 10 ^ 30] : List Int) do
        assertion (.equal (entryAt 3 {} node.val (.integer position)) (hiddenEntry node))
    for item in before do frameInstruction item
    let requestedId <- define (.bits (encodeBits (width := 3) requested))
    let start <- get
    if mode = 0 then
      allocateNode target (.bit (.free (.bits 3) requestedId) target)
    else
      allocateNodes (.free (.bits 3) requestedId)
    let finish <- get
    let count := if mode = 0 then 17 else 51
    unless finish.next = start.next + count &&
        finish.assertions.size = start.assertions.size + count do
      throw "allocation changed its symbol or assertion count"
    if mode = 2 then
      let secondId <- define (.bits (encodeBits (width := 3) second))
      allocateNodes (.free (.bits 3) secondId)
    let columns := (<- get).toColumns
    for node in List.finRange 3 do
      for position in ([-7, 10 ^ 30] : List Int) do
        assertion (.equal (entryAt 3 columns node.val (.integer position)) (hiddenEntry node))
    for item in after do frameInstruction item
  let (_, final) <- program.run (initialEncoding 3 {0, 1})
  return Json.mkObj [
    ("name", toJson s!"allocation-{presentMask}-{addedMask}-{mode}-{mutation}"),
    ("present", toJson presentMask), ("added", toJson addedMask), ("mode", toJson mode),
    ("targetPresent", toJson (decide (state.allocated target))),
    ("targetAdded", toJson (decide (target ∈ added))), ("mutation", toJson mutation),
    ("script", toJson (renderScript final.assertions.toList)),
    ("expected", toJson (if mutation = 0 then "sat" else "unsat"))]

def cases : Except String Json := do
  let fixtures <- (List.range 8).flatMapM fun present =>
    (List.range 8).flatMapM fun added =>
      (List.range 3).flatMapM fun mode =>
        (List.range 23).mapM fun mutation => fixture present added mode mutation
  let mut rejected := #[]
  for kind in ["node", "set"] do
    for symbol in [24, 25, 40, 74, 1024] do
      let operation : EncodeM 3 Unit := if kind = "node" then
          allocateNode 1 (.free .bool symbol)
        else allocateNodes (.free (.bits 3) symbol)
      match operation.run (initialEncoding 3 {0, 1}) with
      | .error error =>
        rejected := rejected.push (Json.mkObj [
          ("kind", toJson kind), ("symbol", toJson symbol), ("error", toJson error)])
      | .ok _ => throw "allocation accepted an unallocated input symbol"
  return Json.mkObj [("fixtures", toJson fixtures), ("rejected", toJson rejected)]

end CCFRaft.NativeAllocationFixtures

def main : IO Unit :=
  match CCFRaft.NativeAllocationFixtures.cases with
  | .ok result => IO.println result.compress
  | .error error => throw (IO.userError error)
