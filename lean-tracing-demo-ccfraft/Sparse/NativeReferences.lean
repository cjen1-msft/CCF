-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeScriptSyntax

set_option autoImplicit false

namespace CCFRaft.NativeSmt

open NativeSExpr (Expr)
open Sparse.SmtNumerals (parseNumeral)

def atomSymbols (text : String) : List (Ty × Nat) :=
  match parseNumeral text with
  | some _ => []
  | none => (parseSymbol text).toList

def syntaxSymbols : Expr -> List (Ty × Nat)
  | .atom text => atomSymbols text
  | .list items => items.flatMap syntaxSymbols

theorem numeral_symbols (value : Nat) : atomSymbols (toString value) = [] := by
  have parsed : parseNumeral (toString value) = some value := Sparse.SmtNumerals.parseNumeral_render value
  simp [atomSymbols, parsed]

theorem free_symbols (sort : Ty) (id : Nat) :
    atomSymbols (symbolName sort id) = [(sort, id)] := by
  simp [atomSymbols, symbolName_not_numeral, parse_symbol_name]

theorem binder_symbols (level : Nat) : atomSymbols (binderName level) = [] := by
  have notSymbol : parseSymbol (binderName level) = none := by
    simp only [parseSymbol, binderName, String.toList_append]
    rfl
  simp [atomSymbols, notSymbol]
  split <;> rfl

theorem bit_word_symbols (value : Nat) : atomSymbols s!"bv{value}" = [] := by
  have notSymbol : parseSymbol s!"bv{value}" = none := by
    simp only [parseSymbol, String.toList_append]
    rfl
  simp [atomSymbols, notSymbol]
  split <;> rfl

theorem Ty.syntax_symbols (sort : Ty) : syntaxSymbols sort.syntax = [] := by
  induction sort with
  | bool | int | unit => simp [Ty.syntax, syntaxSymbols, atomSymbols]; rfl
  | bits width =>
    simp only [Ty.syntax, syntaxSymbols, List.flatMap_cons, List.flatMap_nil, numeral_symbols]
    simp [atomSymbols]
    exact ⟨rfl, rfl⟩
  | array key value first second | pair key value first second | sum key value first second =>
    simp [Ty.syntax, syntaxSymbols, atomSymbols, first, second]
    rfl

theorem Term.syntax_symbols :
    {context : List Ty} -> {sort : Ty} -> (expression : Term context sort) ->
      syntaxSymbols expression.syntax = expression.symbols
  | _, _, .boolean value => by
    cases value <;> simp [Term.syntax, Term.symbols, syntaxSymbols, atomSymbols] <;> rfl
  | _, _, .integer (.ofNat value)
  | _, _, .integer (.negSucc value) => by
    simp only [Term.syntax, Term.symbols, syntaxSymbols, List.flatMap_cons, List.flatMap_nil, numeral_symbols] <;>
      simp [atomSymbols] <;> rfl
  | _, _, .unit => by
    simp [Term.syntax, Term.symbols, syntaxSymbols, atomSymbols]
    rfl
  | _, _, .bits value => by
    simp only [Term.syntax, Term.symbols, syntaxSymbols, List.flatMap_cons, List.flatMap_nil,
      bit_word_symbols, numeral_symbols]
    simp [atomSymbols]
    rfl
  | _, _, .free sort id => by
    simpa only [Term.syntax, Term.symbols, syntaxSymbols] using free_symbols sort id
  | _, _, .bound ref => by
    simpa only [Term.syntax, Term.symbols, syntaxSymbols] using binder_symbols ref.level
  | _, _, .add left right
  | _, _, .sub left right
  | _, _, .le left right
  | _, _, .equal left right
  | _, _, .and left right
  | _, _, .or left right
  | _, _, .select left right
  | _, _, .pair left right
  | _, _, .bitsAnd left right
  | _, _, .bitsOr left right => by
    simp [Term.syntax, Term.symbols, syntaxSymbols, atomSymbols, left.syntax_symbols, right.syntax_symbols]
    rfl
  | _, _, .not value
  | _, _, .fst value
  | _, _, .snd value
  | _, _, .bitsNot value => by
    simp [Term.syntax, Term.symbols, syntaxSymbols, atomSymbols, value.syntax_symbols]
    rfl
  | _, _, .ite condition yes no
  | _, _, .store condition yes no => by
    simp [Term.syntax, Term.symbols, syntaxSymbols, atomSymbols,
      condition.syntax_symbols, yes.syntax_symbols, no.syntax_symbols, List.append_assoc]
    rfl
  | _, _, .forall_ sort body => by
    simp only [Term.syntax, Term.symbols, syntaxSymbols, List.flatMap_cons, List.flatMap_nil,
      binder_symbols, sort.syntax_symbols, body.syntax_symbols]
    simp [atomSymbols]
    rfl
  | _, _, .inl value
  | _, _, .inr value => by
    simp [Term.syntax, Term.symbols, syntaxSymbols, Ty.syntax_symbols, value.syntax_symbols, atomSymbols]
    rfl
  | _, _, .cases value left right => by
    simp only [Term.syntax, Term.symbols, syntaxSymbols, List.flatMap_cons, List.flatMap_nil,
      binder_symbols, value.syntax_symbols, left.syntax_symbols, right.syntax_symbols]
    simp [atomSymbols, List.append_assoc]
    rfl
  | _, _, .bit value index => by
    simp only [Term.syntax, Term.symbols, syntaxSymbols, List.flatMap_cons, List.flatMap_nil,
      numeral_symbols, value.syntax_symbols, show atomSymbols "#b1" = [] from rfl]
    simp [atomSymbols]
    rfl

theorem declared_syntax_symbols (assertions : List (Term [] .bool)) (expression : Term [] .bool)
    (member : expression ∈ assertions) (symbol : Ty × Nat) (occurs : symbol ∈ syntaxSymbols expression.syntax) :
    symbol ∈ (assertions.flatMap Term.symbols).dedup := by
  rw [List.mem_dedup]
  exact List.mem_flatMap.mpr ⟨expression, member, expression.syntax_symbols ▸ occurs⟩

theorem declaration_names_unique (assertions : List (Term [] .bool)) :
    ((assertions.flatMap Term.symbols).dedup.map (fun symbol => symbolName symbol.1 symbol.2)).Nodup := by
  apply List.Nodup.map _ (List.nodup_dedup _)
  intro left right same
  exact Prod.ext (symbolName_injective same).1 (symbolName_injective same).2

end CCFRaft.NativeSmt

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeSmt).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
