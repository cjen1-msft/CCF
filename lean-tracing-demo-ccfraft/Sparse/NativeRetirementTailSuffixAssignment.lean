-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeCommitTermsEncoding
import Sparse.NativeLogSummaryAssignment
import Sparse.NativeRetirementCompletedConstraintsEncoding
import Sparse.NativeRetirementTailExecution
import Sparse.NativeRetirementWritesEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem retirement_tail_suffix_assignment {width : PNat}
    [Bootstrap (Fin width)]
    (bootstrap : BitVec width) (source : Fin width)
    (rowTerms : NodeRowTerms width) (commit : Expr .int)
    (guards : Expr .int -> List (Expr .bool))
    (before after : Encoding width) (states : RetirementTailStates width)
    (execution :
      RetirementTailExecutionResult bootstrap source rowTerms commit guards before
        after states)
    (assignment : Assignment)
    (holds : Holds states.guardsAsserted.assertions.toList assignment)
    (valid : ReferencesValid before)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (frameRep : FrameColumnsRep assignment before.toColumns frame)
    (nativeRow : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (rowRep : rowTerms.Rep assignment nativeRow)
    (rowBounded : rowTerms.Bounded before.next)
    (commitBounded :
      commit.symbols.all (fun symbol => symbol.2 < before.next) = true)
    (commitNat : Nat)
    (sameCommit :
      commit.eval assignment Locals.empty = (commitNat : Int))
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION) :
    exists extended : Assignment,
      assignment.AgreesBelow states.guardsAsserted.next extended /\
        Holds after.assertions.toList extended := by
  let terms := retirementTailTerms before rowTerms commit
  let runs := execution.runs
  have beforeBeforeGuards : before.next <= states.guardsAsserted.next := by
    rw [execution.guardsAssertedNext]
    omega
  have rowGuardBounded : rowTerms.Bounded states.guardsAsserted.next :=
    rowBounded.mono beforeBeforeGuards
  have commitGuardBounded :
      commit.symbols.all
        (fun symbol => symbol.2 < states.guardsAsserted.next) = true := by
    rw [List.all_eq_true] at commitBounded ⊢
    intro symbol member
    have below : symbol.2 < before.next := by
      simpa only [decide_eq_true_eq] using commitBounded symbol member
    simpa only [decide_eq_true_eq] using
      lt_of_lt_of_le below beforeBeforeGuards
  obtain ⟨currentAssignment, currentAgreement, currentBaseHolds, currentAccepted⟩ :=
    current_configuration_index_assignment states.guardsAsserted assignment holds
      rowTerms.logLength rowTerms.logEntries commit nativeRow.log commitNat
      rowGuardBounded.logLength rowGuardBounded.logEntries commitGuardBounded
      rowRep.logLength sameCommit rowRep.logEntries
  have actualCurrentAccepted :
      (currentConfigurationIndexTerm width rowTerms.logLength rowTerms.logEntries
        commit terms.current).eval currentAssignment Locals.empty = true := by
    simpa [terms, retirementTailTerms, execution.guardsAssertedNext] using
      currentAccepted
  have currentFreshHolds :
      Holds states.currentFresh.assertions.toList currentAssignment :=
    fresh_holds states.guardsAsserted states.currentFresh (before.next + 4)
      runs.currentRun currentAssignment currentBaseHolds
  have currentAssertedHolds :
      Holds states.currentAsserted.assertions.toList currentAssignment :=
    assertion_extension_holds _ states.currentFresh states.currentAsserted
      runs.currentAssertionRun currentAssignment currentFreshHolds
      actualCurrentAccepted
  have assignmentToCurrent :
      assignment.AgreesBelow before.next currentAssignment :=
    currentAgreement.restrict beforeBeforeGuards
  have currentRowRep : rowTerms.Rep currentAssignment nativeRow :=
    rowRep.agrees_below assignment currentAssignment rowTerms nativeRow before.next
      rowBounded assignmentToCurrent
  have sameCommitCurrent :
      commit.eval currentAssignment Locals.empty = (commitNat : Int) := by
    have bounded :=
      fun symbol member => by
        simpa using List.all_eq_true.mp commitBounded symbol member
    exact
      (commit.eval_agrees_below assignment currentAssignment Locals.empty
        before.next bounded assignmentToCurrent).symm.trans sameCommit
  obtain ⟨writerAssignment, completedAgreement, writerHolds, _⟩ :=
    retirement_completed_constraints_complete_enabled bootstrap (.boolean true)
      rowTerms.logLength rowTerms.logEntries commit terms.current
      states.currentAsserted states.writerBefore (before.next + 5)
      runs.completedRun currentAssignment currentAssertedHolds nativeRow.log
      commitNat currentRowRep.logLength sameCommitCurrent sameBootstrap
      currentRowRep.logEntries (by simp [Term.eval]) actualCurrentAccepted
  have guardToWriter :
      assignment.AgreesBelow states.guardsAsserted.next writerAssignment :=
    currentAgreement.trans (completedAgreement.restrict (by
      rw [execution.currentAssertedNext, execution.guardsAssertedNext]
      omega))
  have assignmentToWriter :
      assignment.AgreesBelow before.next writerAssignment :=
    guardToWriter.restrict beforeBeforeGuards
  have writerFrameBefore :
      FrameColumnsRep writerAssignment before.toColumns frame :=
    frameRep.agrees_below before assignment writerAssignment frame valid
      assignmentToWriter
  have writerFrame :
      FrameColumnsRep writerAssignment states.writerBefore.toColumns frame := by
    rw [execution.writerColumns]
    exact writerFrameBefore
  have writerRowRep : rowTerms.Rep writerAssignment nativeRow :=
    rowRep.agrees_below assignment writerAssignment rowTerms nativeRow before.next
      rowBounded assignmentToWriter
  have sameCommitWriter :
      commit.eval writerAssignment Locals.empty = (commitNat : Int) := by
    have bounded :=
      fun symbol member => by
        simpa using List.all_eq_true.mp commitBounded symbol member
    exact
      (commit.eval_agrees_below assignment writerAssignment Locals.empty
        before.next bounded assignmentToWriter).symm.trans sameCommit
  have writerValid : ReferencesValid states.writerBefore := by
    cases valid
    constructor <;>
      simp_all only [execution.writerColumns, execution.writerNext] <;> omega
  have constraints :=
    retirement_tail_constraints bootstrap source rowTerms commit guards before after
      states execution writerAssignment writerHolds
  obtain ⟨output, valuesRep, _⟩ :=
    commit_refresh_constraints_output_sound writerAssignment bootstrap rowTerms source
      commit terms.first terms.retirement terms.signature terms.retired nativeRow
      commitNat writerRowRep sameBootstrap sameCommitWriter constraints.refresh
  obtain ⟨_, extended, writeAgreement, finalHolds, _⟩ :=
    retirement_writes_complete source terms.values terms.completed states.writerBefore
      after runs.writeRun writerAssignment writerHolds frame output writerFrame
      valuesRep writerValid
  have totalAgreement :
      assignment.AgreesBelow states.guardsAsserted.next extended :=
    guardToWriter.trans (writeAgreement.restrict (by
      rw [execution.writerNext, execution.guardsAssertedNext]
      omega))
  exact ⟨extended, totalAgreement, finalHolds⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
