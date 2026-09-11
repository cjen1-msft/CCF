-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeSmt

set_option autoImplicit false

namespace CCFRaft.NativeSmt

open NativeSExpr (Expr)

def preludeSyntax : List Expr := [
  .list [.atom "set-logic", .atom "ALL"],
  .list [.atom "declare-datatype", .atom "NativeUnit", .list [.list [.atom "native_unit"]]],
  .list [.atom "declare-datatypes", .list [.list [.atom "NativePair", .atom "2"]],
    .list [.list [.atom "par", .list [.atom "A", .atom "B"],
      .list [.list [.atom "native_pair", .list [.atom "native_fst", .atom "A"],
        .list [.atom "native_snd", .atom "B"]]]]]],
  .list [.atom "declare-datatypes", .list [.list [.atom "NativeSum", .atom "2"]],
    .list [.list [.atom "par", .list [.atom "A", .atom "B"],
      .list [.list [.atom "native_left", .list [.atom "native_left_value", .atom "A"]],
        .list [.atom "native_right", .list [.atom "native_right_value", .atom "B"]]]]]]]

def prelude : List String := preludeSyntax.map Expr.render

def declarationSyntax (symbol : Ty × Nat) : Expr :=
  .list [.atom "declare-const", .atom (symbolName symbol.1 symbol.2), symbol.1.syntax]

def assertionName (index : Nat) : String := s!"assertion_{index}"

def assertionSyntax (named : Bool) (index : Nat) (expression : Term [] .bool) : Expr :=
  .list [.atom "assert",
    if named then .list [.atom "!", expression.syntax, .atom ":named", .atom (assertionName index)]
    else expression.syntax]

def scriptSyntax (assertions : List (Term [] .bool)) (named : Bool := false) : List Expr :=
  preludeSyntax ++ (assertions.flatMap Term.symbols).dedup.map declarationSyntax ++
    assertions.mapIdx (assertionSyntax named) ++ [.list [.atom "check-sat"]]

def renderScript (assertions : List (Term [] .bool)) (named : Bool := false) : String :=
  String.intercalate "\n" ((scriptSyntax assertions named).map Expr.render ++ [""])

theorem prelude_rendered : prelude = [
    "(set-logic ALL)",
    "(declare-datatype NativeUnit ((native_unit)))",
    "(declare-datatypes ((NativePair 2)) ((par (A B) ((native_pair (native_fst A) (native_snd B))))))",
    "(declare-datatypes ((NativeSum 2)) ((par (A B) ((native_left (native_left_value A)) (native_right (native_right_value B))))))"] := by
  simp only [prelude, preludeSyntax, List.map_cons, List.map_nil, Expr.render]
  decide +kernel

end CCFRaft.NativeSmt

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeSmt).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
