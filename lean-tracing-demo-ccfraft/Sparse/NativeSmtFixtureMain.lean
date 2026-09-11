-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeSmt
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

def cases : List Case := [
  stored, wrongStore, nestedArray, constantArray, pair, sum, capture, nestedQuantifiers,
  wideBits, widerBits, bitsOperations, unitAndSecond, typedSymbols, overwrittenStore,
  assertedCondition, arithmetic]

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
