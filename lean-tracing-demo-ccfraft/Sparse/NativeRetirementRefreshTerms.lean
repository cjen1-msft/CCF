-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayRetirement
import Sparse.NativeFirstMatchEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

@[simp] theorem int_one_add_nat_cast_le_nat_cast (left right : Nat) :
    (1 : Int) + left <= right <-> 1 + left <= right := by
  norm_cast

structure RetirementRefreshTerms (context : List Ty) where
  retirementIndex : Term context optionalIntTy
  retirementCommittableIndex : Term context optionalIntTy
  retiredCommittedIndex : Term context optionalIntTy
  membershipState : Term context .int

def scanIndexOptionalTerm {context : List Ty} (shift : Nat)
    (value : Term context .int) : Term context optionalIntTy :=
  .ite (.equal value (.integer (-1))) (.inl .unit)
    (.inr (.add (.integer shift) value))

theorem scan_index_optional_term_eval {context : List Ty}
    (assignment : Assignment) (locals : Locals context) (shift : Nat)
    (value : Term context .int) (choice : Option Nat)
    (sameValue : value.eval assignment locals = firstMatchValue choice) :
    (scanIndexOptionalTerm shift value).eval assignment locals =
      optionalValue Nat.cast (choice.map (shift + ·)) := by
  cases choice <;> simp [scanIndexOptionalTerm, Term.eval, sameValue,
    firstMatchValue, optionalValue]

def retirementRefreshTerms {context : List Ty}
    (commit retirement signaturePosition retiredPosition : Term context .int) :
    RetirementRefreshTerms context :=
  let retirementIndex := scanIndexOptionalTerm 0 retirement
  let retirementCommittableIndex := scanIndexOptionalTerm 1 signaturePosition
  let retiredIndex := scanIndexOptionalTerm 1 retiredPosition
  let committedRetired :=
    .ite (.equal retiredPosition (.integer (-1))) (.inl .unit)
      (.ite (.le (.add (.integer 1) retiredPosition) commit) retiredIndex (.inl .unit))
  let membershipState :=
    .ite (.equal retirement (.integer (-1))) (.integer (membershipCode .active))
      (.ite (.not (.equal committedRetired (.inl .unit)))
        (.integer (membershipCode .retiredCommitted))
        (.ite (.le retirement commit)
          (.integer (membershipCode .retirementCompleted))
          (.ite (.not (.equal signaturePosition (.integer (-1))))
            (.integer (membershipCode .retirementSigned))
            (.integer (membershipCode .retirementOrdered)))))
  { retirementIndex
    retirementCommittableIndex
    retiredCommittedIndex := committedRetired
    membershipState }

theorem retirement_refresh_terms_eval {context : List Ty} {N T : Type}
    (assignment : Assignment) (locals : Locals context)
    (commit retirement signaturePosition retiredPosition : Term context .int)
    (row : NativeArrayCheckQuorum.Local N T)
    (retirementChoice signatureChoice retiredChoice : Option Nat)
    (sameCommit : commit.eval assignment locals = (row.commit : Int))
    (sameRetirement :
      retirement.eval assignment locals = firstMatchValue retirementChoice)
    (sameSignature :
      signaturePosition.eval assignment locals = firstMatchValue signatureChoice)
    (sameRetired :
      retiredPosition.eval assignment locals = firstMatchValue retiredChoice) :
    let terms := retirementRefreshTerms commit retirement signaturePosition retiredPosition
    let refreshed := NativeArrayRetirement.refresh row retirementChoice
      (signatureChoice.map (1 + ·)) (retiredChoice.map (1 + ·))
    terms.retirementIndex.eval assignment locals =
        optionalValue Nat.cast refreshed.retirementIndex /\
      terms.retirementCommittableIndex.eval assignment locals =
        optionalValue Nat.cast refreshed.retirementCommittableIndex /\
      terms.retiredCommittedIndex.eval assignment locals =
        optionalValue Nat.cast refreshed.retiredCommittedIndex /\
      terms.membershipState.eval assignment locals =
        membershipCode refreshed.membershipState := by
  cases retirementChoice <;> cases signatureChoice <;> cases retiredChoice <;>
    simp only [retirementRefreshTerms, NativeArrayRetirement.refresh]
  all_goals
    simp [scanIndexOptionalTerm, Term.eval, sameCommit, sameRetirement, sameSignature,
      sameRetired, firstMatchValue, optionalValue]
  all_goals
    try simp_all [Option.filter]
  all_goals split <;> simp_all
  all_goals split <;> simp_all

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
