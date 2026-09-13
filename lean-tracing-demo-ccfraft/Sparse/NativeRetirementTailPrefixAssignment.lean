-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeRetirementTailExecution
import Sparse.NativeRetirementRefreshAssignment
import Sparse.NativeCommitTermsEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem retirement_tail_prefix_assignment {width : PNat} [Bootstrap (Fin width)]
    (bootstrap : BitVec width) (source : Fin width)
    (rowTerms : NodeRowTerms width) (commit : Expr .int)
    (guards : Expr .int -> List (Expr .bool))
    (before after : Encoding width) (states : RetirementTailStates width)
    (execution :
      RetirementTailExecutionResult bootstrap source rowTerms commit guards
        before after states)
    (assignment : Assignment)
    (holds : Holds before.assertions.toList assignment)
    (nativeRow : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (rowRep : rowTerms.Rep assignment nativeRow)
    (rowBounded : rowTerms.Bounded before.next)
    (commitNat : Nat)
    (sameCommit : commit.eval assignment Locals.empty = (commitNat : Int))
    (commitBounded :
      commit.symbols.all (fun symbol => symbol.2 < before.next) = true)
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION) :
    exists extended : Assignment,
      assignment.AgreesBelow before.next extended /\
        Holds states.refreshAsserted.assertions.toList extended /\
        exists output : NativeArrayCheckQuorum.Local (Fin width) Nat,
          (retirementTailTerms before rowTerms commit).values.Rep extended output /\
            output.toModel =
              refreshRetirementState source
                { nativeRow.toModel with commitIndex := commitNat } := by
  let terms := retirementTailTerms before rowTerms commit
  obtain ⟨extended, agreement, baseHolds, refreshAccepted⟩ :=
    retirement_refresh_assignment before assignment holds bootstrap
      rowTerms.logLength rowTerms.logEntries source nativeRow.log sameBootstrap
      rowBounded.logLength rowBounded.logEntries rowRep.logLength rowRep.logEntries
  have actualRefresh :
      (retirementRefreshConstraints width bootstrap rowTerms.logLength
        rowTerms.logEntries source terms.first terms.retirement terms.signature
        terms.retired).eval extended Locals.empty = true := by
    simpa [terms, retirementTailTerms] using refreshAccepted
  have firstHolds :=
    fresh_holds before states.firstFresh before.next execution.runs.firstRun
      extended baseHolds
  have retirementHolds :=
    fresh_holds states.firstFresh states.retirementFresh (before.next + 1)
      execution.runs.retirementRun extended firstHolds
  have signatureHolds :=
    fresh_holds states.retirementFresh states.signatureFresh (before.next + 2)
      execution.runs.signatureRun extended retirementHolds
  have retiredHolds :=
    fresh_holds states.signatureFresh states.retiredFresh (before.next + 3)
      execution.runs.retiredRun extended signatureHolds
  have refreshAssertedHolds :
      Holds states.refreshAsserted.assertions.toList extended :=
    assertion_extension_holds _ states.retiredFresh states.refreshAsserted
      execution.runs.refreshRun extended retiredHolds actualRefresh
  have extendedRowRep : rowTerms.Rep extended nativeRow :=
    rowRep.agrees_below assignment extended rowTerms nativeRow before.next
      rowBounded agreement
  have boundedCommit :
      forall symbol, symbol ∈ commit.symbols -> symbol.2 < before.next := by
    intro symbol member
    simpa using List.all_eq_true.mp commitBounded symbol member
  have extendedCommit :
      commit.eval extended Locals.empty = (commitNat : Int) :=
    (commit.eval_agrees_below assignment extended Locals.empty before.next
      boundedCommit agreement).symm.trans sameCommit
  obtain ⟨output, outputRep, outputModel⟩ :=
    commit_refresh_constraints_output_sound extended bootstrap rowTerms source commit
      terms.first terms.retirement terms.signature terms.retired nativeRow commitNat
      extendedRowRep sameBootstrap extendedCommit actualRefresh
  exact ⟨extended, agreement, refreshAssertedHolds, output, by
    simpa [terms, retirementTailTerms] using outputRep, outputModel⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
