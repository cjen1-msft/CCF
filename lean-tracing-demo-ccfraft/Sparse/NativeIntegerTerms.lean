-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeSmt

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def intMaxTerm {context : List Ty} (left right : Term context .int) : Term context .int :=
  .ite (.le left right) right left

theorem int_max_term_eval {context : List Ty} (left right : Term context .int)
    (assignment : Assignment) (locals : Locals context) :
    (intMaxTerm left right).eval assignment locals =
      max (left.eval assignment locals) (right.eval assignment locals) := by
  simp [intMaxTerm, Term.eval, max_def]

theorem int_max_zero_eval {context : List Ty} (value : Term context .int)
    (assignment : Assignment) (locals : Locals context) :
    (intMaxTerm (.integer 0) value).eval assignment locals =
      ((value.eval assignment locals).toNat : Int) := by
  rw [int_max_term_eval]
  change max 0 (value.eval assignment locals) = _
  by_cases nonnegative : (0 : Int) <= value.eval assignment locals
  · simp [max_eq_right nonnegative, Int.toNat_of_nonneg nonnegative]
  · have nonpositive := le_of_lt (lt_of_not_ge nonnegative)
    simp [max_eq_left nonpositive, Int.toNat_of_nonpos nonpositive]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
