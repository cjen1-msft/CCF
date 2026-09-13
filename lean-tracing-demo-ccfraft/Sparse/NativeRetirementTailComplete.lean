-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeRetirementTailPrefixAssignment
import Sparse.NativeRetirementTailSuffixAssignment

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem retirement_tail_complete {width : PNat} [Bootstrap (Fin width)]
    (bootstrap : BitVec width) (source : Fin width)
    (rowTerms : NodeRowTerms width) (commit : Expr .int)
    (guards : Expr .int -> List (Expr .bool))
    (before after : Encoding width)
    (run : (retirementTail bootstrap source rowTerms commit guards).run before =
      .ok ((), after))
    (assignment : Assignment)
    (holds : Holds before.assertions.toList assignment)
    (valid : ReferencesValid before)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (frameRep : FrameColumnsRep assignment before.toColumns frame)
    (nativeRow : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (rowRep : rowTerms.Rep assignment nativeRow)
    (rowBounded : rowTerms.Bounded before.next)
    (commitNat : Nat)
    (sameCommit : commit.eval assignment Locals.empty = (commitNat : Int))
    (commitBounded :
      commit.symbols.all (fun symbol => symbol.2 < before.next) = true)
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (guardAccepted :
      forall candidateAssignment,
        assignment.AgreesBelow before.next candidateAssignment ->
        forall output : NativeArrayCheckQuorum.Local (Fin width) Nat,
          (retirementTailTerms before rowTerms commit).values.Rep
              candidateAssignment output ->
          output.toModel =
              refreshRetirementState source
                { nativeRow.toModel with commitIndex := commitNat } ->
          Holds (guards
            (retirementTailTerms before rowTerms commit).values.membershipState)
            candidateAssignment) :
    exists extended : Assignment,
      assignment.AgreesBelow before.next extended /\
        Holds after.assertions.toList extended := by
  obtain ⟨states, execution⟩ :=
    retirement_tail_success bootstrap source rowTerms commit guards before after run
  obtain ⟨prefixAssignment, prefixAgreement, refreshHolds, output, outputRep,
      outputModel⟩ :=
    retirement_tail_prefix_assignment bootstrap source rowTerms commit guards before
      after states execution assignment holds nativeRow rowRep rowBounded commitNat
      sameCommit commitBounded sameBootstrap
  have guardHolds :=
    guardAccepted prefixAssignment prefixAgreement output outputRep outputModel
  have guardsAssertedHolds :
      Holds states.guardsAsserted.assertions.toList prefixAssignment :=
    (assert_all_holds _ states.refreshAsserted states.guardsAsserted
      execution.runs.guardsRun prefixAssignment).mpr ⟨refreshHolds, guardHolds⟩
  have prefixFrameRep :
      FrameColumnsRep prefixAssignment before.toColumns frame :=
    frameRep.agrees_below before assignment prefixAssignment frame valid
      prefixAgreement
  have prefixRowRep : rowTerms.Rep prefixAssignment nativeRow :=
    rowRep.agrees_below assignment prefixAssignment rowTerms nativeRow before.next
      rowBounded prefixAgreement
  have boundedCommit :
      forall symbol, symbol ∈ commit.symbols -> symbol.2 < before.next := by
    intro symbol member
    simpa using List.all_eq_true.mp commitBounded symbol member
  have prefixCommit :
      commit.eval prefixAssignment Locals.empty = (commitNat : Int) :=
    (commit.eval_agrees_below assignment prefixAssignment Locals.empty before.next
      boundedCommit prefixAgreement).symm.trans sameCommit
  obtain ⟨extended, suffixAgreement, afterHolds⟩ :=
    retirement_tail_suffix_assignment bootstrap source rowTerms commit guards before
      after states execution prefixAssignment guardsAssertedHolds valid frame
      prefixFrameRep nativeRow prefixRowRep rowBounded commitBounded commitNat
      prefixCommit sameBootstrap
  have prefixToExtended :
      prefixAssignment.AgreesBelow before.next extended :=
    suffixAgreement.restrict (by rw [execution.guardsAssertedNext]; omega)
  exact ⟨extended, prefixAgreement.trans prefixToExtended, afterHolds⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
