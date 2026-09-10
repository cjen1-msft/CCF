-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.Smt
import Sparse.SmtScript
import Sparse.SmtText
import Lean.Data.Json

set_option autoImplicit false

namespace CCFRaft.Sparse.SmtFixtures

open Smt Lean

private def first : Term .int := .unknown .int 0
private def second : Term .int := .unknown .int 1
private def header (argument : Term .int) : Term .int := .app .int .int 0 argument
private def equalHeader : List (Term .bool) :=
  [.equal (header first) (.integer 0), .equal (header second) (.integer 0)]

private def fixture (name expected : String) (declarations : List String)
    (assertions : List (Term .bool)) : Json :=
  let lines := ["(set-logic QF_UFLIA)"] ++ declarations ++
    assertions.map (fun assertion => "(assert " ++ assertion.render ++ ")") ++
    ["(check-sat)"]
  Json.mkObj [
    ("name", toJson name),
    ("expected", toJson expected),
    ("script", toJson (String.intercalate "\n" lines ++ "\n")),
    ("generated_script", toJson (SmtScript.render assertions))]

-- Literal declarations independently check the generated symbol-name convention.
private def packetDeclarations : List String :=
  ["(declare-const ci__ Int)", "(declare-const ci__1 Int)",
   "(declare-fun fii_ (Int) Int)"]

def fixtures : List Json :=
  let arithmetic : Term .bool := .equal (.sub (.integer (-2)) (.integer 3)) (.integer (-5))
  [
    fixture "empty-formula" "sat" [] [],
    fixture "repeated-symbols" "sat" ["(declare-const ci__ Int)"]
      [.equal first first, .equal first first],
    fixture "negative-arithmetic" "sat" [] [arithmetic],
    fixture "negative-contradiction" "unsat" [] [.not arithmetic],
    fixture "arithmetic-uf-alias" "unsat" ["(declare-fun fii_ (Int) Int)"]
      [.not (.equal (header (.add (.integer 1) (.integer 2))) (header (.integer 3)))],
    fixture "symbolic-uf-alias" "unsat" packetDeclarations
      [.equal first second, .not (.equal (header first) (header second))],
    fixture "unrestricted-other-values" "sat" ["(declare-fun fii_ (Int) Int)"]
      [.equal (header (.integer 1)) (.integer 0),
       .equal (header (.integer 2)) (.integer (-7))],
    fixture "symbol-kinds-and-sorts" "sat"
      ["(declare-const ci__ Int)", "(declare-const cb__ Bool)",
       "(declare-fun fii_ (Int) Int)", "(declare-fun fbi_ (Bool) Int)",
       "(declare-fun fib_ (Int) Bool)", "(declare-fun fbb_ (Bool) Bool)"]
      [.equal first (.integer (-9)), .not (.unknown .bool 0),
       .equal (header first) (.integer 6),
       .equal (.app .bool .int 0 (.unknown .bool 0)) (.integer (-6)),
       .app .int .bool 0 first,
       .not (.app .bool .bool 0 (.unknown .bool 0))],
    fixture "different-headers-cannot-alias" "unsat" packetDeclarations
      [.equal (header first) (.integer 0), .equal (header second) (.integer 1),
       .equal first second],
    fixture "same-headers-can-alias" "sat" packetDeclarations
      (equalHeader ++ [.equal first second]),
    fixture "same-headers-can-differ" "sat" packetDeclarations
      (equalHeader ++ [.not (.equal first second)])
  ]

private def sortJson : Ty -> Json
  | .bool => toJson "Bool"
  | .int => toJson "Int"

private def symbolJson : Symbol -> Json
  | .constant ty id =>
    Json.mkObj [("kind", toJson "constant"), ("result", sortJson ty), ("id", toJson id)]
  | .unary domain result id =>
    Json.mkObj [("kind", toJson "unary"), ("domain", sortJson domain),
      ("result", sortJson result), ("id", toJson id)]

private def symbolFixture (text : String) (expected : Option Symbol) : Json :=
  Json.mkObj [("text", toJson text), ("expected", toJson (expected.map symbolJson)),
    ("actual", toJson ((SmtText.parseSymbol text).map symbolJson))]

def symbolFixtures : List Json :=
  let ids := [0, 1, 2, 3, 15, 16, 255, 256, 1024, 1000000, 2 ^ 128 + 1]
  let symbols := ids.flatMap fun id =>
    [Symbol.constant .bool id, Symbol.constant .int id,
      Symbol.unary .bool .bool id, Symbol.unary .bool .int id,
      Symbol.unary .int .bool id, Symbol.unary .int .int id]
  let malformed := ["", "ci_", "cx__", "fix_1", "ci__2", "ci__0", "fii_10",
    " ci__", "ci__ ", "ci__) (check-sat)", "ci__" ++ String.singleton (Char.ofNat 955)]
  symbols.map (fun sym => symbolFixture sym.name (some sym)) ++
    malformed.map (fun text => symbolFixture text none)

end CCFRaft.Sparse.SmtFixtures

def main (args : List String) : IO UInt32 := do
  let fixtures :=
    match args with
    | [] => some CCFRaft.Sparse.SmtFixtures.fixtures
    | ["--symbols"] => some CCFRaft.Sparse.SmtFixtures.symbolFixtures
    | _ => none
  let some fixtures := fixtures |
    let stderr <- IO.getStderr
    stderr.putStrLn "usage: SmtFixtureMain.lean [--symbols]"
    return 1
  IO.println (Lean.Json.arr fixtures.toArray).compress
  return 0
