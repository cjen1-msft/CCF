-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeFrameEncode

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeRelocatedColumnsFixtures

open Lean NativeSmt NativeEncode

def columnsAt (offset : Nat) : Columns :=
  { allocated := offset
    role := offset + 1
    newFollower := offset + 2
    logLength := offset + 3
    commit := offset + 4
    currentTerm := offset + 5
    logEntries := offset + 6
    retirementIndex := offset + 7
    retirementCommittableIndex := offset + 8
    retiredCommittedIndex := offset + 9
    votedFor := offset + 10
    votesGranted := offset + 11
    preVotesGranted := offset + 12
    membershipState := offset + 13
    sentIndex := offset + 14
    matchIndex := offset + 15
    hasJoined := offset + 16
    preVoteStatus := offset + 17
    retirementCompleted := offset + 18
    submittedTxIds := offset + 19
    submittedTxLimit := offset + 20
    queueLength := offset + 21
    queueHead := offset + 22
    queueCells := offset + 23 }

def execute (input : FrameDecoded) (offset : Nat) : Except String (Encoding input.width) := do
  let initial : Encoding input.width :=
    { toColumns := columnsAt offset
      bootstrap := encodeBits input.bootstrap
      next := offset + 24
      symbolsBounded := by simp }
  let (_, final) <- (input.instructions.toList.forM frameInstruction).run initial
  return final

def fixture (document : Json) : Except String Json := do
  let input <- decodeFrameDocument document
  let baseline <- execute input 0
  let symbols := (baseline.assertions.toList.flatMap Term.symbols).eraseDups
  let relocated <- ([24, 1000] : List Nat).mapM fun offset => do
    let final <- execute input offset
    return Json.mkObj [
      ("offset", toJson offset),
      ("next", toJson final.next),
      ("clauses", toJson (final.assertions.map fun expression => expression.syntax.render)),
      ("renames", toJson (symbols.map fun (sort, id) => (symbolName sort id, symbolName sort (id + offset))))]
  return Json.mkObj [
    ("next", toJson baseline.next),
    ("clauses", toJson (baseline.assertions.map fun expression => expression.syntax.render)),
    ("relocated", toJson relocated)]

def rejectedReferences : Except String (List Json) :=
  let cases : List (String × Columns × FrameInstruction 3) := [
    ("allocated", { allocated := 24 }, .node (.allocated 0 true)),
    ("logLength", { logLength := 24 }, .node (.logLength 0 0)),
    ("commit", { commit := 24 }, .node (.commit 0 0)),
    ("logEntries", { logEntries := 24 }, .node (.entry 0 0 { term := 0, content := .signature }))]
  cases.mapM fun (name, columns, item) =>
    let initial := { (initialEncoding 3 {0, 1}) with toColumns := columns }
    match (frameInstruction item).run initial with
    | .error message => .ok (Json.mkObj [("field", toJson name), ("error", toJson message)])
    | .ok _ => .error s!"accepted an unallocated {name} reference"

end CCFRaft.NativeRelocatedColumnsFixtures

def main : IO UInt32 := do
  let input <- (<- IO.getStdin).readToEnd
  let result := do
    let documents <- (<- Lean.Json.parse input).getArr?
    let fixtures <- documents.mapM CCFRaft.NativeRelocatedColumnsFixtures.fixture
    let rejected <- CCFRaft.NativeRelocatedColumnsFixtures.rejectedReferences
    return Lean.Json.mkObj [
      ("fixtures", Lean.toJson fixtures), ("rejectedReferences", Lean.toJson rejected)]
  match result with
  | .ok fixtures =>
    IO.println (Lean.toJson fixtures).compress
    return 0
  | .error error =>
    (← IO.getStderr).putStrLn error
    return 2
