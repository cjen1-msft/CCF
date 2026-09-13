-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeNatParameters
import Lean.Data.Json

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeNatParameterFixtures

open Lean NativeSmt NativeEncode

private def initial : Encoding 1 :=
  { bootstrap := 0, symbolsBounded := by simp }

private def fixture (count : Nat) (value : Nat) (negative : Bool) : Except String Json := do
  let program : EncodeM 1 Unit := do
    declareNatParameters count
    for index in List.finRange count do
      let argument := NatArgument.parameter index
      let expected : Int := if negative && index.val + 1 = count then -1 else value
      assertion (.equal (argument.term initial.next) (.integer expected))
  let (_, after) <- program.run initial
  if after.next != initial.next + count then
    throw "parameter declarations allocated an unexpected number of symbols"
  return Json.mkObj [
    ("name", toJson s!"parameters-{count}-{value}-{negative}"),
    ("script", toJson (renderScript after.assertions.toList)),
    ("expected", toJson (if negative then "unsat" else "sat"))]

private def literal (agrees : Bool) : Json :=
  let argument : NatArgument 0 := .literal 42
  let constraint : Expr .bool :=
    .equal (argument.term initial.next) (.integer (if agrees then 42 else 41))
  Json.mkObj [
    ("name", toJson s!"literal-argument-{agrees}"),
    ("script", toJson (renderScript [constraint])),
    ("expected", toJson (if agrees then "sat" else "unsat"))]

def cases : Except String (List Json) := do
  let mut result := []
  for count in [0, 1, 2, 17, 65] do
    for value in [0, 42, 10^30] do
      result := result ++ [<- fixture count value false]
      if 0 < count then
        result := result ++ [<- fixture count value true]
  return result ++ [literal false, literal true]

end CCFRaft.NativeNatParameterFixtures

def main : IO Unit := do
  match CCFRaft.NativeNatParameterFixtures.cases with
  | .ok cases => IO.println (Lean.toJson cases).compress
  | .error message => throw (IO.userError message)
