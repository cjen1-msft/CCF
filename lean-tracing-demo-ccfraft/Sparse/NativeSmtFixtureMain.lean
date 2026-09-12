-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeScript
import Sparse.NativeOptional
import Sparse.NativeNatSet
import Lean.Data.Json

set_option autoImplicit false

namespace CCFRaft.NativeSmt

structure Case where
  name : String
  formula : Term [] .bool
  expected : Bool
  correct : forall assignment, formula.eval assignment Locals.empty = expected

private def stored : Case :=
  { name := "array-store"
    formula := .equal (.select (.store (.free (.array .int .int) 0) (.integer 7) (.integer 9)) (.integer 7)) (.integer 9)
    expected := true
    correct := by intro assignment; simp [Term.eval] }

private def wrongStore : Case :=
  { name := "wrong-store"
    formula := .equal (.select (.store (.free (.array .int .int) 0) (.integer 7) (.integer 9)) (.integer 7)) (.integer 8)
    expected := false
    correct := by intro assignment; simp [Term.eval] }

private def nestedArray : Case :=
  { name := "nested-array"
    formula := .equal
      (.select (.select
        (.store (.free (.array .int (.array .int .int)) 0) (.integer 2)
          (.store (.free (.array .int .int) 1) (.integer 3) (.integer 11))) (.integer 2)) (.integer 3))
      (.integer 11)
    expected := true
    correct := by intro assignment; simp [Term.eval] }

private def constantArray : Case :=
  { name := "constant-array-by-constraint"
    formula := .or
      (.not (.forall_ .int
        (.equal (.select (.free (.array .int .int) 0) (.bound .here)) (.free .int 0))))
      (.equal (.select (.free (.array .int .int) 0) (.integer 100)) (.free .int 0))
    expected := true
    correct := by
      intro assignment
      by_cases all : forall index : Int,
        assignment (.array .int .int) 0 index = assignment .int 0
      · simp [Term.eval, Locals.cons, all]
      · simp [Term.eval, Locals.cons, all] }

private def pair : Case :=
  { name := "pair"
    formula := .equal (.fst (.pair (.integer (-3)) (.boolean true))) (.integer (-3))
    expected := true
    correct := by intro assignment; simp [Term.eval] }

private def sum : Case :=
  { name := "sum-match"
    formula := .equal
      (.cases (.inl (.integer 7) : Term [] (.sum .int .bool))
        (.add (.bound .here) (.integer 1)) (.integer 99))
      (.integer 8)
    expected := true
    correct := by intro assignment; simp [Term.eval, Locals.cons] }

private def capture : Case :=
  { name := "match-does-not-capture"
    formula := .forall_ .int
      (.equal
        (.cases (.inr (.boolean false) : Term [.int] (.sum .unit .bool))
          (.integer 99) (.bound (.there .here)))
        (.bound .here))
    expected := true
    correct := by intro assignment; simp [Term.eval, Locals.cons] }

private def nestedQuantifiers : Case :=
  { name := "nested-quantifiers"
    formula := .forall_ .int (.not (.forall_ .int
      (.not (.equal (.bound .here) (.add (.bound (.there .here)) (.integer 1))))))
    expected := true
    correct := by intro assignment; simp [Term.eval, Locals.cons] }

private def wideBits : Case :=
  { name := "twenty-one-bits"
    formula := .bit (.bits (width := ⟨21, by decide⟩) (BitVec.ofNat 21 (2 ^ 20))) ⟨20, by decide⟩
    expected := true
    correct := by intro assignment; simp only [Term.eval]; decide +kernel }

private def widerBits : Case :=
  { name := "one-hundred-thirty-bits"
    formula := .bit (.bits (width := ⟨130, by decide⟩) (BitVec.ofNat 130 (2 ^ 129))) ⟨129, by decide⟩
    expected := true
    correct := by intro assignment; simp only [Term.eval]; decide +kernel }

private def bitsOperations : Case :=
  { name := "bits-operations"
    formula := .equal
      (.bitsAnd (.bitsOr (.bits (width := ⟨21, by decide⟩) 3) (.bits 4)) (.bitsNot (.bits 1)))
      (.bits 6)
    expected := true
    correct := by intro assignment; simp only [Term.eval, decide_eq_true_eq]; decide +kernel }

private def unitAndSecond : Case :=
  { name := "unit-and-second"
    formula := .and (.equal .unit .unit)
      (.snd (.pair (.integer 3) (.boolean true)))
    expected := true
    correct := by intro assignment; simp [Term.eval] }

private def typedSymbols : Case :=
  { name := "symbol-sort-disambiguation"
    formula := .and (.equal (.free .bool 0) (.free .bool 0))
      (.equal (.free .int 0) (.free .int 0))
    expected := true
    correct := by intro assignment; simp [Term.eval] }

private def overwrittenStore : Case :=
  { name := "extensional-store-overwrite"
    formula := .equal
      (.store (.store (.free (.array .int .int) 0) (.integer 3) (.integer 8)) (.integer 3) (.integer 9))
      (.store (.free (.array .int .int) 0) (.integer 3) (.integer 9))
    expected := true
    correct := by intro assignment; simp [Term.eval] }

private def assertedCondition : Case :=
  { name := "assertion-before-specialization"
    formula := .and (.free .bool 0)
      (.equal (.ite (.free .bool 0) (.integer 8) (.integer 12)) (.integer 12))
    expected := false
    correct := by
      intro assignment
      cases observed : assignment .bool 0 <;> simp [Term.eval, observed] }

private def arithmetic : Case :=
  { name := "negative-integer-arithmetic"
    formula := .le (.sub (.integer (-3)) (.integer 2)) (.integer (-5))
    expected := true
    correct := by intro assignment; simp [Term.eval] }

private def optionalNatural (name : String) (value : Option Int) : Case :=
  { name
    formula := NativeEncode.optionalNatDomain (NativeEncode.optionalTerm id value)
    expected := match value with | none => true | some index => decide (0 <= index)
    correct := by
      intro assignment
      cases value <;>
        simp [NativeEncode.optionalNatDomain, NativeEncode.optionalTerm, Term.eval, Locals.cons] }

private def optionalIdentity (name : String) (width : PNat) (value : Option Int) : Case :=
  { name
    formula := NativeEncode.optionalNodeDomain width (NativeEncode.optionalTerm id value)
    expected := match value with | none => true | some node => decide (0 <= node /\ node < width.val)
    correct := by
      intro assignment
      apply Bool.eq_iff_iff.mpr
      cases value <;>
        simp [NativeEncode.optionalNodeDomain, NativeEncode.optionalTerm, Term.eval, Locals.cons] }

private def natSetOutside (name : String) (index : Term [] .int) : Case :=
  { name
    formula := .and (NativeEncode.natSetDomain 0 1)
      (.and (.or (NativeEncode.lt index (.integer 0)) (.le (.free .int 1) index))
        (NativeEncode.natSetMember 0 index))
    expected := false
    correct := by
      intro assignment
      apply Bool.eq_false_iff.mpr
      intro held
      simp only [Term.eval, Bool.and_eq_true] at held
      obtain ⟨domain, outside, present⟩ := held
      have valid := (NativeEncode.nat_set_domain_correct assignment 0 1).mp domain
      have outside' : index.eval assignment Locals.empty < 0 \/
          assignment .int 1 <= index.eval assignment Locals.empty := by
        simpa [NativeEncode.lt, Term.eval] using outside
      simp [NativeEncode.natSetMember, Term.eval, valid.2 _ outside'] at present }

private def natSetNegativeLimit : Case :=
  { name := "nat-set-negative-limit"
    formula := .and (NativeEncode.natSetDomain 0 1)
      (NativeEncode.lt (.free .int 1) (.integer 0))
    expected := false
    correct := by
      intro assignment
      apply Bool.eq_false_iff.mpr
      intro held
      simp only [Term.eval, Bool.and_eq_true] at held
      obtain ⟨domain, negative⟩ := held
      have nonnegative := ((NativeEncode.nat_set_domain_correct assignment 0 1).mp domain).1
      simp [NativeEncode.lt, Term.eval] at negative
      exact (not_lt_of_ge nonnegative) negative }

private def natSetEmpty : Case :=
  { name := "nat-set-empty-prefix"
    formula := NativeEncode.implies
      (.and (NativeEncode.natSetDomain 0 1) (.equal (.free .int 1) (.integer 0)))
      (.forall_ .int (.not (NativeEncode.natSetMember 0 (.bound .here))))
    expected := true
    correct := by
      intro assignment
      rw [NativeEncode.implies_eval]
      intro held
      simp only [Term.eval, Bool.and_eq_true, decide_eq_true_eq] at held
      obtain ⟨domain, zero⟩ := held
      have valid := (NativeEncode.nat_set_domain_correct assignment 0 1).mp domain
      simp only [Term.eval, decide_eq_true_eq]
      intro index
      have outside : index < 0 \/ assignment .int 1 <= index := by
        rw [zero]
        exact lt_or_ge (index : Int) 0
      simp [NativeEncode.natSetMember, Term.eval, Locals.cons, valid.2 index outside] }

def cases : List Case := [
  stored, wrongStore, nestedArray, constantArray, pair, sum, capture, nestedQuantifiers,
  wideBits, widerBits, bitsOperations, unitAndSecond, typedSymbols, overwrittenStore,
  assertedCondition, arithmetic,
  optionalNatural "optional-index-none" none,
  optionalNatural "optional-index-zero" (some 0),
  optionalNatural "optional-index-large" (some (10 ^ 30)),
  optionalNatural "optional-index-negative" (some (-1)),
  optionalIdentity "optional-node-none" ⟨21, by decide⟩ none,
  optionalIdentity "optional-node-zero" ⟨21, by decide⟩ (some 0),
  optionalIdentity "optional-node-last" ⟨21, by decide⟩ (some 20),
  optionalIdentity "optional-node-past-end" ⟨21, by decide⟩ (some 21),
  optionalIdentity "optional-node-negative" ⟨21, by decide⟩ (some (-1)),
  natSetOutside "nat-set-negative-cell" (.integer (-1)),
  natSetOutside "nat-set-zero-cell" (.integer 0),
  natSetOutside "nat-set-large-cell" (.integer (10 ^ 30)),
  natSetOutside "nat-set-tail-cell" (.free .int 1),
  natSetNegativeLimit, natSetEmpty]

end CCFRaft.NativeSmt

run_cmd do
  for axiomName in (<- Lean.collectAxioms ``CCFRaft.NativeSmt.cases) do
    unless axiomName == ``propext || axiomName == ``Classical.choice ||
        axiomName == ``Quot.sound do
      throwError "unexpected fixture axiom: {axiomName}"

def main : IO Unit := do
  let fixtures := CCFRaft.NativeSmt.cases.map fun fixture =>
    Lean.Json.mkObj [("name", Lean.toJson fixture.name),
      ("expected", Lean.toJson (if fixture.expected then "sat" else "unsat")),
      ("script", Lean.toJson (CCFRaft.NativeSmt.renderScript [fixture.formula]))]
  IO.println (Lean.toJson fixtures).compress
