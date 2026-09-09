-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.Smt
import Mathlib.Data.List.Lex
import Mathlib.Data.Sum.Order

set_option autoImplicit false

/-!
# Executable structural ordering for SMT natural terms

The key is a flattened syntax tree. Child-key lengths delimit adjacent
subtrees, avoiding the very large integers produced by nested pairing
encodings.
-/

namespace TraceSmt.NatTerm

/-- One scalar component of a flattened term syntax key. -/
abbrev SyntaxAtom := Lex (Sum Nat String)

private def natAtom (value : Nat) : SyntaxAtom :=
  toLex (Sum.inl value)

private def stringAtom (value : String) : SyntaxAtom :=
  toLex (Sum.inr value)

/--
A compact, injective syntax key. Numeric constructor tags are followed by
primitive payloads and flattened child keys. Lengths delimit all but the final
child of multi-child constructors.
-/
def syntaxKey {holes : Nat} : NatTerm holes -> List SyntaxAtom
  | .literal value =>
      [natAtom 0, natAtom value]
  | .unknown index =>
      [natAtom 1, natAtom index.val]
  | .add left right =>
      let leftKey := left.syntaxKey
      let rightKey := right.syntaxKey
      natAtom 2 :: natAtom leftKey.length :: leftKey ++ rightKey
  | .named group slot label value =>
      [natAtom 3, natAtom group, natAtom slot, stringAtom label] ++
        value.syntaxKey

private theorem append_parts
    {α : Type}
    {left right left' right' : List α}
    (lengthEq : left.length = left'.length)
    (appendEq : left ++ right = left' ++ right') :
    left = left' /\ right = right' := by
  constructor
  · simpa [lengthEq] using congrArg (List.take left.length) appendEq
  · simpa [lengthEq] using congrArg (List.drop left.length) appendEq

/-- Distinct SMT term syntax trees have distinct flattened keys. -/
theorem syntaxKey_injective {holes : Nat} :
    Function.Injective (@syntaxKey holes) := by
  intro term
  induction term with
  | literal value =>
      intro other equal
      cases other <;> simp [syntaxKey, natAtom, stringAtom] at equal
      case literal value' =>
        cases equal
        rfl
  | unknown index =>
      intro other equal
      cases other <;> simp [syntaxKey, natAtom, stringAtom] at equal
      case unknown index' =>
        have : index = index' := Fin.ext equal
        cases this
        rfl
  | add left right leftInjective rightInjective =>
      intro other equal
      cases other <;> simp [syntaxKey, natAtom, stringAtom] at equal
      case add left' right' =>
        rcases append_parts equal.1 equal.2 with ⟨leftKey, rightKey⟩
        cases leftInjective leftKey
        cases rightInjective rightKey
        rfl
  | named group slot label value valueInjective =>
      intro other equal
      cases other <;> simp [syntaxKey, natAtom, stringAtom] at equal
      case named group' slot' label' value' =>
        cases equal.1
        cases equal.2.1
        cases equal.2.2.1
        cases valueInjective equal.2.2.2
        rfl

/--
Computable lexicographic structural order for terms. This instance makes
`Finset.sort` executable without changing term evaluation or SMT printing.
-/
instance {holes : Nat} : LinearOrder (NatTerm holes) :=
  LinearOrder.lift' syntaxKey syntaxKey_injective

end TraceSmt.NatTerm
