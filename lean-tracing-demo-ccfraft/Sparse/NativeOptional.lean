-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeValues

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def optionalIntTy : Ty := .sum .unit .int

def optionalValue {α : Type} (encode : α -> Int) : Option α -> optionalIntTy.denote
  | none => .inl ()
  | some value => .inr (encode value)

def optionalDecode {α : Type} (decode : Int -> Option α) :
    optionalIntTy.denote -> Option (Option α)
  | .inl _ => some none
  | .inr value => (decode value).map some

def optionalTerm {context : List Ty} {α : Type} (encode : α -> Int) :
    Option α -> Term context optionalIntTy
  | none => .inl .unit
  | some value => .inr (.integer (encode value))

theorem optional_term_eval {context : List Ty} {α : Type} (encode : α -> Int)
    (value : Option α) (assignment : Assignment) (locals : Locals context) :
    (optionalTerm encode value).eval assignment locals = optionalValue encode value := by
  cases value <;> rfl

theorem optional_decode_value {α : Type} (encode : α -> Int) (decode : Int -> Option α)
    (roundTrip : forall value, decode (encode value) = some value) (value : Option α) :
    optionalDecode decode (optionalValue encode value) = some value := by
  cases value <;> simp [optionalValue, optionalDecode, roundTrip]

theorem optional_value_iff {α : Type} (encode : α -> Int) (decode : Int -> Option α)
    (roundTrip : forall value, decode (encode value) = some value)
    (exactValue : forall value decoded, decode value = some decoded -> encode decoded = value)
    (value : optionalIntTy.denote) (expected : Option α) :
    value = optionalValue encode expected <-> optionalDecode decode value = some expected := by
  constructor
  · rintro rfl
    exact optional_decode_value encode decode roundTrip expected
  · cases value with
    | inl payload =>
      cases payload
      cases expected <;> simp [optionalDecode, optionalValue]
    | inr value =>
      cases expected with
      | none => simp [optionalDecode]
      | some expected =>
        simp only [optionalDecode, Option.map_eq_some_iff]
        rintro ⟨decoded, successful, same⟩
        cases Option.some.inj same
        exact congrArg Sum.inr (exactValue value _ successful).symm

def naturalValue? (value : Int) : Option Nat :=
  if 0 <= value then some value.toNat else none

@[simp] theorem natural_value_round_trip (value : Nat) : naturalValue? value = some value := by
  simp [naturalValue?]

theorem natural_value_exact (value : Int) (decoded : Nat) (successful : naturalValue? value = some decoded) :
    (decoded : Int) = value := by
  unfold naturalValue? at successful
  split at successful
  · cases Option.some.inj successful
    exact Int.toNat_of_nonneg (by omega)
  · contradiction

def nodeValue? (width : PNat) (value : Int) : Option (Fin width) :=
  if domain : 0 <= value /\ value < width.val then
    some ⟨value.toNat, by omega⟩
  else none

@[simp] theorem node_value_round_trip {width : PNat} (node : Fin width) :
    nodeValue? width node.val = some node := by
  simp [nodeValue?, node.isLt]

theorem node_value_exact {width : PNat} (value : Int) (decoded : Fin width)
    (successful : nodeValue? width value = some decoded) : (decoded.val : Int) = value := by
  unfold nodeValue? at successful
  split at successful
  · cases Option.some.inj successful
    exact Int.toNat_of_nonneg (by omega)
  · contradiction

def optionalNatDomain {context : List Ty} (value : Term context optionalIntTy) : Term context .bool :=
  .cases value (.boolean true) (.le (.integer 0) (.bound .here))

def optionalNodeDomain {context : List Ty} (width : PNat) (value : Term context optionalIntTy) :
    Term context .bool :=
  .cases value (.boolean true)
    (.and (.le (.integer 0) (.bound .here)) (.not (.le (.integer width.val) (.bound .here))))

theorem optional_nat_domain_correct {context : List Ty} (value : Term context optionalIntTy)
    (assignment : Assignment) (locals : Locals context) :
    (optionalNatDomain value).eval assignment locals = true <->
      (optionalDecode naturalValue? (value.eval assignment locals)).isSome = true := by
  cases observed : value.eval assignment locals <;>
    simp [optionalNatDomain, Term.eval, observed, Locals.cons, optionalDecode, naturalValue?]

theorem optional_node_domain_correct {context : List Ty} (width : PNat) (value : Term context optionalIntTy)
    (assignment : Assignment) (locals : Locals context) :
    (optionalNodeDomain width value).eval assignment locals = true <->
      (optionalDecode (nodeValue? width) (value.eval assignment locals)).isSome = true := by
  cases observed : value.eval assignment locals <;>
    simp [optionalNodeDomain, Term.eval, observed, Locals.cons, optionalDecode, nodeValue?]

theorem optional_nat_literal_correct {context : List Ty} (value : Term context optionalIntTy)
    (expected : Option Nat) (assignment : Assignment) (locals : Locals context) :
    (Term.equal value (optionalTerm Nat.cast expected)).eval assignment locals = true <->
      optionalDecode naturalValue? (value.eval assignment locals) = some expected := by
  simp only [Term.eval, decide_eq_true_eq, optional_term_eval]
  exact optional_value_iff Nat.cast naturalValue? natural_value_round_trip natural_value_exact _ expected

theorem optional_node_literal_correct {context : List Ty} {width : PNat} (value : Term context optionalIntTy)
    (expected : Option (Fin width)) (assignment : Assignment) (locals : Locals context) :
    (Term.equal value (optionalTerm (fun node : Fin width => (node.val : Int)) expected)).eval assignment locals =
      true <->
      optionalDecode (nodeValue? width) (value.eval assignment locals) = some expected := by
  simp only [Term.eval, decide_eq_true_eq, optional_term_eval]
  exact optional_value_iff (fun node => (node.val : Int)) (nodeValue? width)
    node_value_round_trip node_value_exact _ expected

example : optionalDecode naturalValue? (.inr (-1)) = none := by decide +kernel
example : optionalDecode naturalValue? (.inl ()) = some none := rfl
example : optionalDecode (nodeValue? ⟨21, by decide⟩) (.inr 21) = none := by decide +kernel
example : optionalDecode (nodeValue? ⟨21, by decide⟩) (.inr 20) = some (some ⟨20, by decide⟩) := by decide +kernel

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
