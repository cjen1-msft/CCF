-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeSmt

set_option autoImplicit false

namespace CCFRaft.NativeSmt

abbrev Renaming (source target : List Ty) :=
  {sort : Ty} -> Variable source sort -> Variable target sort

def Renaming.underBinder {source target : List Ty} (rename : Renaming source target)
    (binder : Ty) : Renaming (binder :: source) (binder :: target)
  | _, .here => .here
  | _, .there ref => .there (rename ref)

def Term.rename : {source target : List Ty} -> {sort : Ty} ->
    Renaming source target -> Term source sort -> Term target sort
  | _, _, _, _, .boolean value => .boolean value
  | _, _, _, _, .integer value => .integer value
  | _, _, _, _, .unit => .unit
  | _, _, _, _, .bits value => .bits value
  | _, _, _, _, .free sort id => .free sort id
  | _, _, _, rename, .bound ref => .bound (rename ref)
  | _, _, _, rename, .add left right => .add (left.rename rename) (right.rename rename)
  | _, _, _, rename, .sub left right => .sub (left.rename rename) (right.rename rename)
  | _, _, _, rename, .le left right => .le (left.rename rename) (right.rename rename)
  | _, _, _, rename, .equal left right => .equal (left.rename rename) (right.rename rename)
  | _, _, _, rename, .not value => .not (value.rename rename)
  | _, _, _, rename, .and left right => .and (left.rename rename) (right.rename rename)
  | _, _, _, rename, .or left right => .or (left.rename rename) (right.rename rename)
  | _, _, _, rename, .ite condition yes no =>
    .ite (condition.rename rename) (yes.rename rename) (no.rename rename)
  | _, _, _, rename, .forall_ sort body => .forall_ sort (body.rename (rename.underBinder sort))
  | _, _, _, rename, .select array index => .select (array.rename rename) (index.rename rename)
  | _, _, _, rename, .store array index value =>
    .store (array.rename rename) (index.rename rename) (value.rename rename)
  | _, _, _, rename, .pair left right => .pair (left.rename rename) (right.rename rename)
  | _, _, _, rename, .fst value => .fst (value.rename rename)
  | _, _, _, rename, .snd value => .snd (value.rename rename)
  | _, _, _, rename, .inl value => .inl (value.rename rename)
  | _, _, _, rename, .inr value => .inr (value.rename rename)
  | _, _, _, rename, .cases value left right =>
    .cases (value.rename rename) (left.rename (rename.underBinder _)) (right.rename (rename.underBinder _))
  | _, _, _, rename, .bitsAnd left right => .bitsAnd (left.rename rename) (right.rename rename)
  | _, _, _, rename, .bitsOr left right => .bitsOr (left.rename rename) (right.rename rename)
  | _, _, _, rename, .bitsNot value => .bitsNot (value.rename rename)
  | _, _, _, rename, .bit value index => .bit (value.rename rename) index

theorem Renaming.under_binder_agrees {source target : List Ty} (rename : Renaming source target)
    (left : Locals source) (right : Locals target)
    (same : forall {sort : Ty} (ref : Variable source sort), right _ (rename ref) = left _ ref)
    (binder : Ty) (value : binder.denote) {sort : Ty} (ref : Variable (binder :: source) sort) :
    (right.cons value) _ (rename.underBinder binder ref) = (left.cons value) _ ref := by
  cases ref
  · rfl
  · exact same _

theorem Term.rename_eval {source target : List Ty} {sort : Ty}
    (expression : Term source sort) (rename : Renaming source target) (assignment : Assignment)
    (left : Locals source) (right : Locals target)
    (same : forall {sort : Ty} (ref : Variable source sort), right _ (rename ref) = left _ ref) :
    (expression.rename rename).eval assignment right = expression.eval assignment left := by
  match expression with
  | .boolean _ | .integer _ | .unit | .bits _ | .free _ _ => rfl
  | .bound ref => exact same ref
  | .add first second | .sub first second | .le first second
  | .and first second | .or first second
  | .select first second | .pair first second
  | .bitsAnd first second | .bitsOr first second =>
    simp only [Term.rename, eval, rename_eval first _ assignment left right same,
      rename_eval second _ assignment left right same]
  | .equal first second =>
    simp only [Term.rename, eval]
    rw [rename_eval first rename assignment left right same,
      rename_eval second rename assignment left right same]
  | .not value | .fst value | .snd value | .inl value | .inr value
  | .bitsNot value | .bit value _ =>
    simp only [Term.rename, eval, rename_eval value _ assignment left right same]
  | .ite first second third | .store first second third =>
    simp only [Term.rename, eval, rename_eval first _ assignment left right same,
      rename_eval second _ assignment left right same, rename_eval third _ assignment left right same]
  | .forall_ binder body =>
    simp only [Term.rename, eval]
    apply congrArg (fun proposition : Prop => @decide proposition (Classical.propDecidable proposition))
    apply propext
    apply forall_congr'
    intro value
    rw [rename_eval body (rename.underBinder binder) assignment (left.cons value) (right.cons value)
      (rename.under_binder_agrees left right same binder value)]
  | .cases value first second =>
    simp only [Term.rename, eval, rename_eval value _ assignment left right same]
    cases value.eval assignment left with
    | inl argument =>
      exact rename_eval first _ assignment _ _ (rename.under_binder_agrees left right same _ argument)
    | inr argument =>
      exact rename_eval second _ assignment _ _ (rename.under_binder_agrees left right same _ argument)
termination_by structural expression

theorem Term.rename_symbols {source target : List Ty} {sort : Ty}
    (expression : Term source sort) (rename : Renaming source target) :
    (expression.rename rename).symbols = expression.symbols := by
  match expression with
  | .boolean _ | .integer _ | .unit | .bits _ | .free _ _ | .bound _ => rfl
  | .add first second | .sub first second | .le first second
  | .equal first second | .and first second | .or first second
  | .select first second | .pair first second
  | .bitsAnd first second | .bitsOr first second =>
    simp only [Term.rename, symbols, rename_symbols first, rename_symbols second]
  | .not value | .fst value | .snd value | .inl value | .inr value
  | .bitsNot value | .bit value _ =>
    simp only [Term.rename, symbols, rename_symbols value]
  | .ite first second third | .store first second third | .cases first second third =>
    simp only [Term.rename, symbols, rename_symbols first, rename_symbols second, rename_symbols third]
  | .forall_ _ body => exact rename_symbols body _
termination_by structural expression

def Term.weaken {context : List Ty} {sort : Ty} (expression : Term context sort) (binder : Ty) :
    Term (binder :: context) sort :=
  expression.rename Variable.there

theorem Term.weaken_eval {context : List Ty} {sort : Ty}
    (expression : Term context sort) (binder : Ty) (assignment : Assignment)
    (locals : Locals context) (value : binder.denote) :
    (expression.weaken binder).eval assignment (locals.cons value) = expression.eval assignment locals :=
  expression.rename_eval Variable.there assignment locals (locals.cons value) (fun _ => rfl)

theorem Term.weaken_symbols {context : List Ty} {sort : Ty}
    (expression : Term context sort) (binder : Ty) :
    (expression.weaken binder).symbols = expression.symbols :=
  expression.rename_symbols Variable.there

end CCFRaft.NativeSmt

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeSmt).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
