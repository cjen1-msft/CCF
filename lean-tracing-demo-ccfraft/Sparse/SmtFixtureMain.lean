-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.Smt
import Sparse.SmtScript
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

end CCFRaft.Sparse.SmtFixtures

def main (args : List String) : IO UInt32 := do
  unless args.isEmpty do
    let stderr <- IO.getStderr
    stderr.putStrLn "usage: SmtFixtureMain.lean"
    return 1
  IO.println (Lean.Json.arr CCFRaft.Sparse.SmtFixtures.fixtures.toArray).compress
  return 0
