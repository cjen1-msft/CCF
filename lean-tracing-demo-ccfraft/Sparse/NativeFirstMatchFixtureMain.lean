-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeFirstMatchEncoding
import Sparse.NativeScript
import Lean.Data.Json

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeFirstMatchFixtures

open Lean NativeSmt NativeEncode

def flags : Nat -> List (List Bool)
  | 0 => [[]]
  | count + 1 => (flags count).flatMap fun earlier => [earlier ++ [false], earlier ++ [true]]

def assertion (nested : Bool) : Expr .bool :=
  if nested then
    .forall_ .int (implies (.equal (.bound .here) (.free .int 1))
      (.forall_ .int (implies (.equal (.bound .here) (.free .int 2))
        (firstMatchTerm (.bound (.there .here)) (.bound .here)
          (.select (.free (.array .int .bool) 0) (.bound .here))))))
  else firstMatchTerm (.free .int 1) (.free .int 2)
    (.select (.free (.array .int .bool) 0) (.bound .here))

def fixture (name : String) (cells : Expr (.array .int .bool)) (limit : Nat)
    (candidate : Int) (expected : Option Nat) (nested : Bool) : Json :=
  let withTails := .store (.store cells (.integer (-1)) (.boolean true)) (.integer limit) (.boolean true)
  let assertions : List (Expr .bool) := [
    .equal (.free (.array .int .bool) 0) withTails,
    .equal (.free .int 1) (.integer limit),
    .equal (.free .int 2) (.integer candidate),
    assertion nested]
  Json.mkObj [("name", toJson name), ("script", toJson (renderScript assertions)),
    ("expected", toJson (if candidate = firstMatchValue expected then "sat" else "unsat"))]

def cases : List Json :=
  let finite := (List.range 5).flatMap fun count =>
    ((flags count).zipIdx).flatMap fun (values, index) =>
      let cells : Expr (.array .int .bool) := values.zipIdx.foldl
        (fun cells (value, position) => .store cells (.integer position) (.boolean value)) (.defaultValue _)
      let log : List (Entry (Fin 3) Nat) :=
        values.map fun value => { term := 1, content := if value then .signature else .transaction 7 }
      let expected := (retirementCommittableIndexInLog log 0).map (· - 1)
      (((List.range (count + 4)).map fun candidate => (candidate : Int) - 2) ++ [10 ^ 30]).flatMap fun candidate =>
        [false, true].map fun nested =>
          fixture s!"first-match-{count}-{index}-{candidate}-{nested}" cells count candidate expected nested
  let huge : Nat := 10 ^ 30
  let sparse := [false, true].flatMap fun live =>
    let cells : Expr (.array .int .bool) := if live then
        .store (.defaultValue _) (.integer (huge - 1)) (.boolean true)
      else .defaultValue _
    ([-2, -1, 0, huge - 1, huge, huge + 1] : List Int).flatMap fun candidate =>
      [false, true].map fun nested =>
        fixture s!"first-match-huge-{live}-{candidate}-{nested}" cells huge candidate
          (if live then some (huge - 1) else none) nested
  finite ++ sparse

end CCFRaft.NativeFirstMatchFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeFirstMatchFixtures.cases).compress
