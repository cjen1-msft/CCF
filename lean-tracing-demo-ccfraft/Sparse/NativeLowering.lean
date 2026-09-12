-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeInterpretation

set_option autoImplicit false

namespace CCFRaft.NativeSmt

open Sparse.SmtNumerals (parseNumeral)

theorem eval_boolean (assignment : Assignment) (environment : NamedLocals) (value : Bool) :
    evalAtom assignment environment (if value then "true" else "false") = some ⟨.bool, value⟩ := by
  cases value <;> rfl

theorem eval_unit (assignment : Assignment) (environment : NamedLocals) :
    evalAtom assignment environment "native_unit" = some ⟨.unit, ()⟩ := rfl

theorem eval_one_bit (assignment : Assignment) (environment : NamedLocals) :
    evalAtom assignment environment "#b1" = some ⟨.bits ⟨1, by decide⟩, 1⟩ := rfl

theorem eval_numeral (assignment : Assignment) (environment : NamedLocals) (value : Nat) :
    evalAtom assignment environment (toString value) = some ⟨.int, value⟩ := by
  have parsed : parseNumeral (toString value) = some value := Sparse.SmtNumerals.parseNumeral_render value
  simp [evalAtom, parsed]

theorem symbolName_not_numeral (sort : Ty) (id : Nat) :
    parseNumeral (symbolName sort id) = none := by
  simp only [parseNumeral, symbolName, String.toList_append]
  rfl

theorem eval_free (assignment : Assignment) (environment : NamedLocals) (sort : Ty) (id : Nat) :
    evalAtom assignment environment (symbolName sort id) = some ⟨sort, assignment sort id⟩ := by
  simp [evalAtom, symbolName_not_numeral, parse_symbol_name]

theorem eval_binder (assignment : Assignment) (environment : NamedLocals) (level : Nat) :
    evalAtom assignment environment (binderName level) = environment level := by
  have notNumeral : parseNumeral (binderName level) = none := by
    simp only [parseNumeral, binderName, String.toList_append]
    rfl
  have notSymbol : parseSymbol (binderName level) = none := by
    simp only [parseSymbol, binderName, String.toList_append]
    rfl
  simp [evalAtom, notNumeral, notSymbol, parse_binder_name]

theorem parse_bit_word (value : Nat) : parseBitWord s!"bv{value}" = some value := by
  have numeral : parseNumeral (toString value) = some value := Sparse.SmtNumerals.parseNumeral_render value
  simp only [parseBitWord, String.toList_append]
  change parseNumeral (String.ofList (toString value).toList) = _
  simpa using numeral

theorem eval_bit_literal {width : PNat} (value : BitVec width) :
    evalBitLiteral s!"bv{value.toNat}" (toString width.val) = some ⟨.bits width, value⟩ := by
  rcases width with ⟨width, positive⟩
  have numeral : parseNumeral (toString width) = some width := Sparse.SmtNumerals.parseNumeral_render width
  simp [evalBitLiteral, parse_bit_word, numeral, positive]

theorem Ty.defaultSyntax_eval (sort : Ty) (assignment : Assignment) (environment : NamedLocals) :
    evalSyntax assignment environment sort.defaultSyntax = some ⟨sort, sort.default⟩ := by
  induction sort with
  | bool =>
    rw [Ty.defaultSyntax, evalSyntax]
    exact eval_boolean assignment environment false
  | int =>
    rw [Ty.defaultSyntax, evalSyntax]
    exact eval_numeral assignment environment 0
  | unit =>
    rw [Ty.defaultSyntax, evalSyntax]
    exact eval_unit assignment environment
  | bits width =>
    rw [Ty.defaultSyntax, evalSyntax]
    simpa [Ty.default] using (eval_bit_literal (0 : BitVec width))
  | array key value _ second | sum key value second _ =>
    rw [Ty.defaultSyntax, evalSyntax] <;> try decide +kernel
    simp [Ty.default, parse_sort_syntax, applyConstructor, second]
  | pair first second left right =>
    rw [Ty.defaultSyntax, eval_application _ _ _ _ (by decide +kernel) (by decide +kernel) (by decide +kernel)]
    simp [Ty.default, evalArguments, applyOperator, left, right]

theorem Term.syntax_eval (assignment : Assignment) (environment : NamedLocals) :
    {context : List Ty} -> {sort : Ty} -> (expression : Term context sort) -> (locals : Locals context) ->
    environment.Rep locals ->
    evalSyntax assignment environment expression.syntax = some ⟨sort, expression.eval assignment locals⟩
  | _, _, .boolean value, locals, _ => by
    rw [Term.syntax, evalSyntax]
    exact eval_boolean assignment environment value
  | _, _, .integer (.ofNat value), locals, _ => by
    rw [Term.syntax, evalSyntax]
    exact eval_numeral assignment environment value
  | _, _, .integer (.negSucc value), locals, _ => by
    rw [Term.syntax, eval_application _ _ _ _ (by decide +kernel) (by decide +kernel) (by decide +kernel)]
    simp only [evalArguments]
    rw [evalSyntax, eval_numeral]
    simp [Term.eval, applyOperator, Int.negSucc_eq, Int.add_comm]
  | _, _, .unit, locals, _ => by
    rw [Term.syntax, evalSyntax]
    exact eval_unit assignment environment
  | _, _, .bits value, locals, _ => by
    rw [Term.syntax, evalSyntax]
    exact eval_bit_literal value
  | _, _, .defaultValue sort, locals, _ => sort.defaultSyntax_eval assignment environment
  | _, _, .free ty id, locals, _ => by
    rw [Term.syntax, evalSyntax]
    exact eval_free assignment environment ty id
  | _, _, .bound ref, locals, represented => by
    rw [Term.syntax, evalSyntax, eval_binder]
    exact represented _ ref
  | _, _, .add left right, locals, represented
  | _, _, .sub left right, locals, represented
  | _, _, .le left right, locals, represented
  | _, _, .equal left right, locals, represented
  | _, _, .and left right, locals, represented
  | _, _, .or left right, locals, represented
  | _, _, .select left right, locals, represented
  | _, _, .pair left right, locals, represented
  | _, _, .bitsAnd left right, locals, represented
  | _, _, .bitsOr left right, locals, represented => by
    rw [Term.syntax, eval_application _ _ _ _ (by decide +kernel) (by decide +kernel) (by decide +kernel)]
    simp [Term.eval, evalArguments, applyOperator,
      left.syntax_eval assignment environment locals represented,
      right.syntax_eval assignment environment locals represented]
  | _, _, .not value, locals, represented
  | _, _, .fst value, locals, represented
  | _, _, .snd value, locals, represented
  | _, _, .bitsNot value, locals, represented => by
    rw [Term.syntax, eval_application _ _ _ _ (by decide +kernel) (by decide +kernel) (by decide +kernel)]
    simp [Term.eval, evalArguments, applyOperator,
      value.syntax_eval assignment environment locals represented]
  | _, _, .ite first second third, locals, represented
  | _, _, .store first second third, locals, represented => by
    rw [Term.syntax, eval_application _ _ _ _ (by decide +kernel) (by decide +kernel) (by decide +kernel)]
    simp [Term.eval, evalArguments, applyOperator,
      first.syntax_eval assignment environment locals represented,
      second.syntax_eval assignment environment locals represented,
      third.syntax_eval assignment environment locals represented]
  | context, _, .forall_ ty body, locals, represented => by
    have bodyEval (value : ty.denote) := body.syntax_eval assignment
      (Function.update environment context.length (some ⟨ty, value⟩)) (locals.cons value)
        (represented.cons ty value)
    rw [Term.syntax, evalSyntax] <;> try decide +kernel
    simp [Term.eval, evalForall, parse_sort_syntax, parse_binder_name, bodyEval]
  | _, _, .inl value, locals, represented
  | _, _, .inr value, locals, represented => by
    rw [Term.syntax, evalSyntax] <;> try decide +kernel
    simp [Term.eval, parse_sort_syntax, applyConstructor,
      value.syntax_eval assignment environment locals represented]
  | context, result, .cases value left right, locals, represented => by
    have leftEval (argument) := left.syntax_eval assignment
      (Function.update environment context.length (some ⟨_, argument⟩)) (locals.cons argument)
        (represented.cons _ argument)
    have rightEval (argument) := right.syntax_eval assignment
      (Function.update environment context.length (some ⟨_, argument⟩)) (locals.cons argument)
        (represented.cons _ argument)
    simp only [Term.syntax, Term.eval]
    rw [evalSyntax, value.syntax_eval assignment environment locals represented] <;> try decide +kernel
    simp only [parse_binder_name, Bind.bind, Option.bind]
    rw [funext leftEval, funext rightEval, eval_match_values]
    rfl
  | _, _, .bit value index, locals, represented => by
    have numeral : parseNumeral (toString index.val) = some index.val :=
      Sparse.SmtNumerals.parseNumeral_render index.val
    have extracted :
        evalSyntax assignment environment (.list [.list [.atom "_", .atom "extract",
          .atom (toString index.val), .atom (toString index.val)], value.syntax]) =
          some ⟨.bits ⟨1, by decide⟩, BitVec.ofBool ((value.eval assignment locals).getLsbD index.val)⟩ := by
      rw [evalSyntax]
      simp [numeral, extractSingle, index.isLt,
        value.syntax_eval assignment environment locals represented]
    have oneBit : evalSyntax assignment environment (.atom "#b1") = some ⟨.bits ⟨1, by decide⟩, 1⟩ := by
      rw [evalSyntax]
      exact eval_one_bit assignment environment
    rw [Term.syntax, eval_application _ _ _ _ (by decide +kernel) (by decide +kernel) (by decide +kernel)]
    simp [Term.eval, evalArguments, extracted, oneBit, applyOperator]
    exact @one_bit_decision _ (Classical.propDecidable _)

theorem Term.render_eval {context : List Ty} {sort : Ty} (expression : Term context sort)
    (assignment : Assignment) (environment : NamedLocals) (locals : Locals context)
    (represented : environment.Rep locals) :
    evalText assignment environment expression.render = some ⟨sort, expression.eval assignment locals⟩ := by
  rw [evalText, expression.parse_render, Option.bind_some]
  exact expression.syntax_eval assignment environment locals represented

theorem Term.closed_render_eval {sort : Ty} (expression : Term [] sort) (assignment : Assignment) :
    evalText assignment (fun _ => none) expression.render =
      some ⟨sort, expression.eval assignment Locals.empty⟩ :=
  expression.render_eval assignment _ Locals.empty (NamedLocals.empty _)

end CCFRaft.NativeSmt

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeSmt).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
