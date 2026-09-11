-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.Smt
import Sparse.SmtScript
import Sparse.SmtText
import Sparse.SmtNumerals
import Sparse.SmtExpressionText
import Sparse.SmtScriptText
import Lean.Data.Json

set_option autoImplicit false

namespace CCFRaft.Sparse.SmtFixtures

open Smt Lean

private def first : Term .int := .unknown .int 0
private def second : Term .int := .unknown .int 1
private def header (argument : Term .int) : Term .int := .app .int .int 0 argument
private def equalHeader : List (Term .bool) :=
  [.equal (header first) (.integer 0), .equal (header second) (.integer 0)]

private def expressionAssignment : Assignment where
  constant ty _ := match ty with
    | .bool => false | .int => 0 | .nodes => 0
    | .content => .signature | .entry => { term := 0, content := .signature }
  unary _ result _ _ := match result with
    | .bool => false | .int => 0 | .nodes => 0
    | .content => .signature | .entry => { term := 0, content := .signature }

private def valueJson : Value -> Json
  | .boolean value => Json.mkObj [("Bool", toJson value)]
  | .integer value => Json.mkObj [("Int", toJson value)]
  | .nodes value => Json.mkObj [("Nodes", toJson value.toNat)]
  | .content value => Json.mkObj [("Content", toJson (reprStr value))]
  | .entry value => Json.mkObj [("Entry", toJson (reprStr value))]

private def expressionCase (name text : String) (expected : Option SExpr) : Json :=
  let actual := SmtExpressionText.parse text
  Json.mkObj [("name", toJson name), ("text", toJson text),
    ("expected_render", toJson (expected.map SExpr.render)),
    ("actual_render", toJson (actual.map SExpr.render)),
    ("expected_value", toJson ((expected.bind (SExpr.eval expressionAssignment)).map valueJson)),
    ("actual_value", toJson ((actual.bind (SExpr.eval expressionAssignment)).map valueJson))]

private def fixture (name expected : String) (declarations : List String)
    (assertions : List (Term .bool)) : Json :=
  let lines := ["(set-logic QF_UFLIA)"] ++ declarations ++
    assertions.map (fun assertion => "(assert " ++ assertion.render ++ ")") ++
    ["(check-sat)"]
  let generated := SmtScript.render assertions
  Json.mkObj [
    ("name", toJson name),
    ("expected", toJson expected),
    ("script", toJson (String.intercalate "\n" lines ++ "\n")),
    ("generated_script", toJson generated),
    ("parsed_script", toJson ((SmtScriptText.parse generated).map SmtScript.renderCommands)),
    ("command_value", toJson (SmtScript.run expressionAssignment (SmtScript.compile assertions))),
    ("parsed_value", toJson (SmtScriptText.runText expressionAssignment generated)),
    ("expressions", toJson (assertions.map fun term =>
      expressionCase name term.render (some term.lower)))]

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

private def sortJson (ty : Ty) : Json := toJson ty.render

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

private def numeralFixture (text : String) (expected : Option Nat) : Json :=
  Json.mkObj [("text", toJson text), ("expected", toJson expected),
    ("actual", toJson (SmtNumerals.parseNumeral text))]

def numeralFixtures : List Json :=
  let values := [0, 1, 9, 10, 99, 100, 255, 1000000, 2 ^ 128 + 1, 10 ^ 100]
  let malformed := ["", "00", "01", "-1", "-0", "+1", "(- 1)", "1_000",
    "0x10", "1.0", " 1", "1 ", "1) (check-sat)", String.singleton (Char.ofNat 1633)]
  values.map (fun value => numeralFixture (Atom.numeral value).render (some value)) ++
    malformed.map (fun text => numeralFixture text none)

private def nestedNegation : Nat -> SExpr
  | 0 => .atom (.boolean true)
  | depth + 1 => .list [.atom (.operator .not), nestedNegation depth]

def expressionFixtures : List Json :=
  let sum : SExpr := .list [.atom (.operator .add), .atom (.numeral 1), .atom (.numeral 2)]
  let illTyped : SExpr := .list [.atom (.operator .ite), .atom (.boolean true),
    .atom (.numeral 1), .atom (.boolean false)]
  let wrongArity : SExpr := .list [.atom (.operator .add), .atom (.numeral 1)]
  let nested := nestedNegation 256
  [
    expressionCase "mixed-whitespace" "\n(\t+\r 1 2)\t" (some sum),
    expressionCase "unselected-branch-type-error" illTyped.render (some illTyped),
    expressionCase "wrong-arity" wrongArity.render (some wrongArity),
    expressionCase "empty-list" "()" (some (.list [])),
    expressionCase "nested-empty-list" "(())" (some (.list [.list []])),
    expressionCase "deep-nesting" nested.render (some nested)
  ] ++ ["", "(", ")", "(+ 1 2", "(+ 1 2))", "true false", "(+ 01 2)",
    "(+ -1 2)", "(+ ci__0 2)", "unknown", "; comment\ntrue"].map
      (fun text => expressionCase "malformed" text none)

private def scriptCase (name text : String) (parsed : Bool) (expected : Option Bool) : Json :=
  Json.mkObj [("name", toJson name), ("text", toJson text),
    ("expected_render", toJson (if parsed then some text else none)),
    ("actual_render", toJson ((SmtScriptText.parse text).map SmtScript.renderCommands)),
    ("expected_value", toJson expected),
    ("actual_value", toJson (SmtScriptText.runText expressionAssignment text))]

private def scriptBody (body : String) : String :=
  "(set-logic QF_UFLIA)\n" ++ body ++ "(check-sat)\n"

def scriptFixtures : List Json :=
  let empty := scriptBody ""
  [
    scriptCase "empty-formula" empty true (some true),
    scriptCase "false-assertion" (scriptBody "(assert false)\n") true (some false),
    scriptCase "missing-declaration" (scriptBody "(assert cb__)\n") true none,
    scriptCase "mismatched-signature" (scriptBody "(declare-fun ci__ () Bool)\n") true none,
    scriptCase "duplicate-declaration"
      (scriptBody "(declare-fun ci__ () Int)\n(declare-fun ci__ () Int)\n") true none,
    scriptCase "nonboolean-assertion" (scriptBody "(assert 1)\n") true none,
    scriptCase "wrong-arity" (scriptBody "(assert (= 1))\n") true none,
    scriptCase "false-does-not-hide-error" (scriptBody "(assert false)\n(assert cb__)\n") true none
  ] ++ ["", "(set-logic QF_UFLIA)\n(check-sat)", empty ++ empty,
    empty ++ "(check-sat)\n", "(set-logic QF_UFLIA)\n", "(check-sat)\n",
    scriptBody "(push 1)\n", empty ++ "\n", "; comment\n" ++ empty,
    "(set-logic QF_BV)\n(check-sat)\n"].map (fun text => scriptCase "malformed" text false none)

end CCFRaft.Sparse.SmtFixtures

def main (args : List String) : IO UInt32 := do
  let fixtures :=
    match args with
    | [] => some CCFRaft.Sparse.SmtFixtures.fixtures
    | ["--symbols"] => some CCFRaft.Sparse.SmtFixtures.symbolFixtures
    | ["--numerals"] => some CCFRaft.Sparse.SmtFixtures.numeralFixtures
    | ["--expressions"] => some CCFRaft.Sparse.SmtFixtures.expressionFixtures
    | ["--scripts"] => some CCFRaft.Sparse.SmtFixtures.scriptFixtures
    | _ => none
  let some fixtures := fixtures |
    let stderr <- IO.getStderr
    stderr.putStrLn "usage: SmtFixtureMain.lean [--symbols | --numerals | --expressions | --scripts]"
    return 1
  IO.println (Lean.Json.arr fixtures.toArray).compress
  return 0
