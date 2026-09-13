-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeSubmittedWrite
import Lean.Data.Json

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeSubmittedWriteFixtures

open Lean NativeSmt NativeEncode

private def initial : Encoding 1 :=
  { bootstrap := 0, symbolsBounded := by simp }

example : (insertSubmitted (.free .int 24)).run initial =
    .error "internal encoder error: submitted transaction references an unallocated SMT symbol" := by
  rfl

example : (insertSubmitted (.free .int 25)).run initial =
    .error "internal encoder error: submitted transaction references an unallocated SMT symbol" := by
  rfl

example : (insertSubmitted (.free .int 26)).run initial =
    .error "internal encoder error: submitted transaction references an unallocated SMT symbol" := by
  rfl

private def rawCells (positions : List Int) : Expr (.array .int (.bits 1)) :=
  positions.foldl (fun cells index => .store cells (.integer index) (.bits 1))
    (.defaultValue _)

private def fixture (index : Nat) (limit : Int) (values : List Nat)
    (symbolic agrees : Bool) : Except String Json := do
  let positions : List Int := [-1, 0, 1, limit, limit + 1]
  let oldSet :=
    ((positions.filter fun position => 0 <= position && position < limit).map
      Int.toNat).toFinset
  let points : List Int := [-1, 0, 1, 2, 3, 5, 10^30, limit, limit + 1]
  let program : EncodeM 1 Unit := do
    assertion (.equal (.free .int 20) (.integer limit))
    assertion (.equal (.free (.array .int (.bits 1)) 19) (rawCells positions))
    let mut expected := oldSet
    for (value, slot) in values.zipIdx do
      let argument : Expr .int :=
        if symbolic then .free .int (10 + slot) else .integer value
      assertion (.equal argument (.integer value))
      insertSubmitted argument
      expected := insert value expected
      let after <- get
      assertAll (points.map fun point =>
        .equal (natSetMember after.submittedTxIds after.submittedTxLimit (.integer point))
          (.boolean (decide (0 <= point /\ point.toNat ∈ expected))))
      assertion (.equal
        (.select (.free (.array .int (.bits 1)) after.submittedTxIds) (.integer (-1)))
        (.bits 1))
      assertion (.equal
        (.select (.free (.array .int (.bits 1)) after.submittedTxIds)
          (.free .int after.submittedTxLimit))
        (.bits 1))
    if !agrees then
      let after <- get
      assertion (.not (natSetMember after.submittedTxIds after.submittedTxLimit
        (.integer (values.getLast?.getD 0))))
  let (_, after) <- program.run initial
  if after.next != 24 + 2 * values.length then
    throw "submitted insertion allocated an unexpected number of symbols"
  return Json.mkObj [
    ("name", toJson s!"submitted-write-{index}-{symbolic}-{agrees}"),
    ("limit", toJson limit),
    ("values", toJson values),
    ("script", toJson (renderScript after.assertions.toList)),
    ("expected", toJson (if agrees then "sat" else "unsat"))]

def cases : Except String (List Json) := do
  let scenarios : List (Int × List Nat) :=
    [0, 2, 10^30, -1, -(10^30)].flatMap fun (limit : Int) =>
      [[0], [5, 5], [0, 5, 10^30]].map fun values => (limit, values)
  let mut result := []
  for ((limit, values), index) in scenarios.zipIdx do
    for symbolic in [false, true] do
      for agrees in [false, true] do
        result := result ++ [<- fixture index limit values symbolic agrees]
  return result

end CCFRaft.NativeSubmittedWriteFixtures

def main : IO Unit := do
  match CCFRaft.NativeSubmittedWriteFixtures.cases with
  | .ok cases => IO.println (Lean.toJson cases).compress
  | .error message => throw (IO.userError message)
