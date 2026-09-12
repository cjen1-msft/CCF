-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativePeerEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def queueLengthTerm {context : List Ty} (column : Nat) (destination source : Term context .int) :
    Term context .int :=
  .select (.select (.free (.array .int (.array .int .int)) column) destination) source

def queueLengthsDomain (width : PNat) (column : Nat) : Expr .bool :=
  .forall_ .int (implies
    (.and (.le (.integer 0) (.bound .here)) (lt (.bound .here) (.integer width.val)))
    (.forall_ .int (implies
      (.and (.le (.integer 0) (.bound .here)) (lt (.bound .here) (.integer width.val)))
      (.le (.integer 0) (queueLengthTerm column (.bound (.there .here)) (.bound .here))))))

def QueueLengthDomain (width : PNat) (assignment : Assignment) (column : Nat) : Prop :=
  forall destination source : Fin width,
    0 <= assignment (.array .int (.array .int .int)) column destination.val source.val

theorem queue_lengths_domain_correct (width : PNat) (column : Nat) (assignment : Assignment) :
    (queueLengthsDomain width column).eval assignment Locals.empty = true <->
      QueueLengthDomain width assignment column := by
  have integerDomain :
      (queueLengthsDomain width column).eval assignment Locals.empty = true <->
        forall destination : Int, 0 <= destination /\ destination < width.val ->
          forall source : Int, 0 <= source /\ source < width.val ->
            0 <= assignment (.array .int (.array .int .int)) column destination source := by
    simp only [queueLengthsDomain, Term.eval, decide_eq_true_eq]
    conv_lhs =>
      intro destination
      rw [implies_eval]
      intro within
      simp only [Term.eval, decide_eq_true_eq]
      intro source
      rw [implies_eval]
    simp [lt, queueLengthTerm, Term.eval, Locals.cons]
  rw [integerDomain, forall_identity_int]
  simp_rw [forall_identity_int]
  rfl

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
