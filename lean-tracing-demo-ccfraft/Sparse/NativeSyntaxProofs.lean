-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeSmt
import Sparse.SmtExpressionText

set_option autoImplicit false

namespace CCFRaft.NativeSmt

open NativeSExpr (SafeAtom)

theorem safe_atom_append {left right : String} (first : SafeAtom left) (second : SafeAtom right) :
    SafeAtom (left ++ right) := by
  constructor
  · intro empty
    rw [String.toList_append, List.append_eq_nil_iff] at empty
    exact first.1 empty.1
  · intro char member
    rw [String.toList_append] at member
    rcases List.mem_append.mp member with earlier | later
    · exact first.2 char earlier
    · exact second.2 char later

theorem numeral_safe (value : Nat) : SafeAtom (toString value) :=
  ⟨Sparse.SmtExpressionText.atom_render_nonempty (.numeral value),
    Sparse.SmtExpressionText.atom_render_safe (.numeral value)⟩

theorem Ty.code_safe (sort : Ty) : SafeAtom sort.code := by
  induction sort with
  | bool | int | unit => decide +kernel
  | bits width =>
    exact safe_atom_append (safe_atom_append (by decide +kernel) (numeral_safe width.val)) (by decide +kernel)
  | array key value first second | pair key value first second | sum key value first second =>
    exact safe_atom_append (safe_atom_append (by decide +kernel) first) second

theorem symbolName_safe (sort : Ty) (id : Nat) : SafeAtom (symbolName sort id) :=
  safe_atom_append
    (safe_atom_append (safe_atom_append (by decide +kernel) sort.code_safe) (by decide +kernel))
    (numeral_safe id)

theorem binder_safe (depth : Nat) : SafeAtom (binderName depth) :=
  safe_atom_append (by decide +kernel) (numeral_safe depth)

theorem Ty.syntax_safe (sort : Ty) : sort.syntax.Safe := by
  induction sort with
  | bool | int | unit =>
    simp only [Ty.syntax, NativeSExpr.Expr.Safe]
    decide +kernel
  | bits width =>
    simp only [Ty.syntax, NativeSExpr.Expr.Safe, List.mem_cons, List.not_mem_nil,
      or_false, or_imp, forall_and, forall_eq]
    exact ⟨by decide +kernel, by decide +kernel, numeral_safe width.val⟩
  | array key value first second | pair key value first second | sum key value first second =>
    simp only [Ty.syntax, NativeSExpr.Expr.Safe, List.mem_cons, List.not_mem_nil,
      or_false, or_imp, forall_and, forall_eq]
    exact ⟨by decide +kernel, first, second⟩

theorem Ty.defaultSyntax_safe (sort : Ty) : sort.defaultSyntax.Safe := by
  induction sort with
  | bool | int | unit =>
    simp only [Ty.defaultSyntax, NativeSExpr.Expr.Safe]
    decide +kernel
  | bits width =>
    simp only [Ty.defaultSyntax, NativeSExpr.Expr.Safe, List.mem_cons, List.not_mem_nil,
      or_false, or_imp, forall_and, forall_eq]
    exact ⟨by decide +kernel, by decide +kernel, numeral_safe width.val⟩
  | array key value _ second | sum key value second _ =>
    simp only [Ty.defaultSyntax, NativeSExpr.Expr.Safe, List.mem_cons, List.not_mem_nil,
      or_false, or_imp, forall_and, forall_eq]
    exact ⟨⟨by decide +kernel, by decide +kernel, Ty.syntax_safe _⟩, second⟩
  | pair first second left right =>
    simp only [Ty.defaultSyntax, NativeSExpr.Expr.Safe, List.mem_cons, List.not_mem_nil,
      or_false, or_imp, forall_and, forall_eq]
    exact ⟨⟨by decide +kernel, by decide +kernel, Ty.syntax_safe _⟩, left, right⟩

theorem Term.syntax_safe : {context : List Ty} -> {sort : Ty} ->
    (expression : Term context sort) -> expression.syntax.Safe
  | _, _, .boolean value => by
    cases value <;> simp only [Term.syntax, NativeSExpr.Expr.Safe] <;> decide +kernel
  | _, _, .integer (.ofNat value) => by
    simpa only [Term.syntax, NativeSExpr.Expr.Safe] using numeral_safe value
  | _, _, .integer (.negSucc value) => by
    simp only [Term.syntax, NativeSExpr.Expr.Safe, List.mem_cons, List.not_mem_nil,
      or_false, or_imp, forall_and, forall_eq]
    exact ⟨by decide +kernel, numeral_safe (value + 1)⟩
  | _, _, .unit => by
    simp only [Term.syntax, NativeSExpr.Expr.Safe]
    decide +kernel
  | _, _, .bits (width := width) value => by
    simp only [Term.syntax, NativeSExpr.Expr.Safe, List.mem_cons, List.not_mem_nil,
      or_false, or_imp, forall_and, forall_eq]
    exact ⟨by decide +kernel, safe_atom_append (by decide +kernel) (numeral_safe value.toNat),
      numeral_safe width.val⟩
  | _, _, .free sort id => by
    simpa only [Term.syntax, NativeSExpr.Expr.Safe] using symbolName_safe sort id
  | _, _, .defaultValue sort => sort.defaultSyntax_safe
  | _, _, .bound ref => by
    simpa only [Term.syntax, NativeSExpr.Expr.Safe] using binder_safe ref.level
  | _, _, .add left right | _, _, .sub left right | _, _, .le left right
  | _, _, .equal left right | _, _, .and left right | _, _, .or left right
  | _, _, .select left right
  | _, _, .bitsAnd left right | _, _, .bitsOr left right => by
    simp only [Term.syntax, NativeSExpr.Expr.Safe, List.mem_cons, List.not_mem_nil,
      or_false, or_imp, forall_and, forall_eq]
    exact ⟨by decide +kernel, left.syntax_safe, right.syntax_safe⟩
  | _, .pair first second, .pair left right => by
    simp only [Term.syntax, NativeSExpr.Expr.Safe, List.mem_cons, List.not_mem_nil,
      or_false, or_imp, forall_and, forall_eq]
    exact ⟨⟨by decide +kernel, by decide +kernel, (Ty.pair first second).syntax_safe⟩,
      left.syntax_safe, right.syntax_safe⟩
  | _, _, .not value | _, _, .fst value | _, _, .snd value | _, _, .bitsNot value => by
    simp only [Term.syntax, NativeSExpr.Expr.Safe, List.mem_cons, List.not_mem_nil,
      or_false, or_imp, forall_and, forall_eq]
    exact ⟨by decide +kernel, value.syntax_safe⟩
  | _, _, .ite first second third | _, _, .store first second third => by
    simp only [Term.syntax, NativeSExpr.Expr.Safe, List.mem_cons, List.not_mem_nil,
      or_false, or_imp, forall_and, forall_eq]
    exact ⟨by decide +kernel, first.syntax_safe, second.syntax_safe, third.syntax_safe⟩
  | context, _, .forall_ sort body => by
    simp only [Term.syntax, NativeSExpr.Expr.Safe, List.mem_cons, List.not_mem_nil,
      or_false, or_imp, forall_and, forall_eq]
    exact ⟨by decide +kernel, ⟨binder_safe context.length, sort.syntax_safe⟩, body.syntax_safe⟩
  | _, .sum first second, .inl value | _, .sum first second, .inr value => by
    simp only [Term.syntax, NativeSExpr.Expr.Safe, List.mem_cons, List.not_mem_nil,
      or_false, or_imp, forall_and, forall_eq]
    exact ⟨⟨by decide +kernel, by decide +kernel, (Ty.sum first second).syntax_safe⟩, value.syntax_safe⟩
  | context, _, .cases value left right => by
    simp only [Term.syntax, NativeSExpr.Expr.Safe, List.mem_cons, List.not_mem_nil,
      or_false, or_imp, forall_and, forall_eq]
    exact ⟨by decide +kernel, value.syntax_safe,
      ⟨⟨by decide +kernel, binder_safe context.length⟩, left.syntax_safe⟩,
      ⟨⟨by decide +kernel, binder_safe context.length⟩, right.syntax_safe⟩⟩
  | _, _, .bit value index => by
    simp only [Term.syntax, NativeSExpr.Expr.Safe, List.mem_cons, List.not_mem_nil,
      or_false, or_imp, forall_and, forall_eq]
    exact ⟨by decide +kernel,
      ⟨⟨by decide +kernel, by decide +kernel, numeral_safe index.val, numeral_safe index.val⟩,
        value.syntax_safe⟩, by decide +kernel⟩

theorem Ty.parse_render (sort : Ty) : NativeSExpr.parse sort.render = some sort.syntax :=
  NativeSExpr.parse_render sort.syntax sort.syntax_safe

theorem Term.parse_render {context : List Ty} {sort : Ty} (expression : Term context sort) :
    NativeSExpr.parse expression.render = some expression.syntax :=
  NativeSExpr.parse_render expression.syntax expression.syntax_safe

end CCFRaft.NativeSmt

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeSmt).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
