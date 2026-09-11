-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeScript
import Sparse.NativeLowering

set_option autoImplicit false

namespace CCFRaft.NativeSmt

open NativeSExpr (Expr)

def parseDeclaration : Expr -> Option (Ty × Nat)
  | .list [.atom "declare-const", .atom name, sortExpression] => do
    let symbol <- parseSymbol name
    let sort <- parseSort sortExpression
    if symbol.1 = sort then some symbol else none
  | _ => none

theorem parse_declaration (symbol : Ty × Nat) :
    parseDeclaration (declarationSyntax symbol) = some symbol := by
  rcases symbol with ⟨sort, id⟩
  simp [parseDeclaration, declarationSyntax, parse_symbol_name, parse_sort_syntax]

theorem prelude_syntax_safe : forall command, command ∈ preludeSyntax -> command.Safe := by
  simp only [preludeSyntax, List.mem_cons, List.not_mem_nil, or_false, forall_eq_or_imp, forall_eq,
    Expr.Safe]
  decide +kernel

theorem declaration_syntax_safe (symbol : Ty × Nat) : (declarationSyntax symbol).Safe := by
  simp only [declarationSyntax, Expr.Safe, List.mem_cons, List.not_mem_nil,
    or_false, forall_eq_or_imp, forall_eq]
  exact ⟨by decide +kernel, symbolName_safe symbol.1 symbol.2, symbol.1.syntax_safe⟩

theorem assertion_name_safe (index : Nat) : NativeSExpr.SafeAtom (assertionName index) :=
  safe_atom_append (by decide +kernel) (numeral_safe index)

theorem assertion_syntax_safe (named : Bool) (index : Nat) (expression : Term [] .bool) :
    (assertionSyntax named index expression).Safe := by
  cases named <;>
    simp only [assertionSyntax, Bool.false_eq_true, ↓reduceIte, Expr.Safe, List.mem_cons,
      List.not_mem_nil, or_false, forall_eq_or_imp, forall_eq]
  · exact ⟨by decide +kernel, expression.syntax_safe⟩
  · exact ⟨by decide +kernel, by decide +kernel, expression.syntax_safe,
      by decide +kernel, assertion_name_safe index⟩

theorem script_syntax_safe (assertions : List (Term [] .bool)) (named : Bool) :
    forall command, command ∈ scriptSyntax assertions named -> command.Safe := by
  intro command member
  simp only [scriptSyntax, List.mem_append, List.mem_map, List.mem_mapIdx,
    List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with ((prelude | declaration) | assertion) | last
  · exact prelude_syntax_safe command prelude
  · rcases declaration with ⟨symbol, _, same⟩
    subst command
    exact declaration_syntax_safe symbol
  · rcases assertion with ⟨index, within, same⟩
    subst command
    exact assertion_syntax_safe named index assertions[index]
  · subst command
    simp only [Expr.Safe, List.mem_cons, List.not_mem_nil, or_false, forall_eq]
    decide +kernel

theorem script_commands_parse (assertions : List (Term [] .bool)) (named : Bool) :
    forall command, command ∈ scriptSyntax assertions named ->
      NativeSExpr.parse command.render = some command :=
  fun command member => NativeSExpr.parse_render command (script_syntax_safe assertions named command member)

example : parseDeclaration (.list [.atom "declare-const", .atom "c_B_0", .atom "Int"]) = none := by
  decide +kernel

example : parseDeclaration (.list [.atom "declare-const", .atom "b0", .atom "Bool"]) = none := by
  decide +kernel

end CCFRaft.NativeSmt

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeSmt).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
