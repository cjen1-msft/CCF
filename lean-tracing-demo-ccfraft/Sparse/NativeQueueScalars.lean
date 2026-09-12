-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeSmt

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def queueScalarTerm {context : List Ty} (column : Nat) (destination source : Term context .int) :
    Term context .int :=
  let cell := .select (.select (.free (.array .int (.array .int .int)) column) destination) source
  .ite (.le (.integer 0) cell) cell (.integer 0)

theorem queue_scalar_correct {context : List Ty} (column : Nat)
    (destination source : Term context .int) (assignment : Assignment) (locals : Locals context) :
    (queueScalarTerm column destination source).eval assignment locals =
      ((assignment (.array .int (.array .int .int)) column
        (destination.eval assignment locals) (source.eval assignment locals)).toNat : Int) := by
  by_cases nonnegative : 0 <= assignment (.array .int (.array .int .int)) column
      (destination.eval assignment locals) (source.eval assignment locals)
  · simp [queueScalarTerm, Term.eval, nonnegative, Int.toNat_of_nonneg nonnegative]
  · simp [queueScalarTerm, Term.eval, nonnegative,
      Int.toNat_of_nonpos (le_of_lt (lt_of_not_ge nonnegative))]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
