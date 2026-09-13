-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeRetirementTail
import Sparse.NativeRetirementCompletedConstraintsEncoding
import Sparse.NativeRetirementWritesEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

structure RetirementTailTerms (width : PNat) where
  (first retirement signature retired current : Expr .int)
  completed : Expr (.bits width)
  values : NodeRowTerms width

def retirementTailTerms {width : PNat} (before : Encoding width)
    (row : NodeRowTerms width) (commit : Expr .int) : RetirementTailTerms width :=
  let first : Expr .int := .free .int before.next
  let retirement : Expr .int := .free .int (before.next + 1)
  let signature : Expr .int := .free .int (before.next + 2)
  let retired : Expr .int := .free .int (before.next + 3)
  let current : Expr .int := .free .int (before.next + 4)
  let completed : Expr (.bits width) := .free _ (before.next + 5)
  { first, retirement, signature, retired, current, completed
    values := commitRowTerms row commit retirement signature retired }

structure RetirementTailStates (width : PNat) where
  firstFresh : Encoding width
  retirementFresh : Encoding width
  signatureFresh : Encoding width
  retiredFresh : Encoding width
  refreshAsserted : Encoding width
  guardsAsserted : Encoding width
  currentFresh : Encoding width
  currentAsserted : Encoding width
  writerBefore : Encoding width

structure RetirementTailRuns {width : PNat} (bootstrap : BitVec width)
    (source : Fin width) (row : NodeRowTerms width) (commit : Expr .int)
    (guards : Expr .int -> List (Expr .bool)) (before after : Encoding width)
    (states : RetirementTailStates width) : Prop where
  firstRun :
    fresh.run before = .ok (before.next, states.firstFresh)
  retirementRun :
    fresh.run states.firstFresh = .ok (before.next + 1, states.retirementFresh)
  signatureRun :
    fresh.run states.retirementFresh = .ok (before.next + 2, states.signatureFresh)
  retiredRun :
    fresh.run states.signatureFresh = .ok (before.next + 3, states.retiredFresh)
  refreshRun :
    let terms := retirementTailTerms before row commit
    (assertion (retirementRefreshConstraints width bootstrap row.logLength row.logEntries
      source terms.first terms.retirement terms.signature terms.retired)).run
        states.retiredFresh = .ok ((), states.refreshAsserted)
  guardsRun :
    let terms := retirementTailTerms before row commit
    (assertAll (guards terms.values.membershipState)).run states.refreshAsserted =
      .ok ((), states.guardsAsserted)
  currentRun :
    fresh.run states.guardsAsserted = .ok (before.next + 4, states.currentFresh)
  currentAssertionRun :
    let terms := retirementTailTerms before row commit
    (assertion (currentConfigurationIndexTerm width row.logLength row.logEntries
      commit terms.current)).run states.currentFresh = .ok ((), states.currentAsserted)
  completedRun :
    let terms := retirementTailTerms before row commit
    (retirementCompletedConstraints bootstrap (.boolean true) row.logLength
      row.logEntries commit terms.current).run states.currentAsserted =
        .ok (before.next + 5, states.writerBefore)
  writeRun :
    let terms := retirementTailTerms before row commit
    (writeRetirementRow source terms.values terms.completed).run states.writerBefore =
      .ok ((), after)

structure RetirementTailConstraints {width : PNat} (bootstrap : BitVec width)
    (source : Fin width) (row : NodeRowTerms width) (commit : Expr .int)
    (guards : Expr .int -> List (Expr .bool)) (before : Encoding width)
    (assignment : Assignment) : Prop where
  priorHolds : Holds before.assertions.toList assignment
  refresh :
    let terms := retirementTailTerms before row commit
    (retirementRefreshConstraints width bootstrap row.logLength row.logEntries source
      terms.first terms.retirement terms.signature terms.retired).eval
        assignment Locals.empty = true
  guards :
    let terms := retirementTailTerms before row commit
    Holds (guards terms.values.membershipState) assignment
  current :
    let terms := retirementTailTerms before row commit
    (currentConfigurationIndexTerm width row.logLength row.logEntries commit
      terms.current).eval assignment Locals.empty = true

structure RetirementTailExecutionResult {width : PNat} (bootstrap : BitVec width)
    (source : Fin width) (row : NodeRowTerms width) (commit : Expr .int)
    (guards : Expr .int -> List (Expr .bool)) (before after : Encoding width)
    (states : RetirementTailStates width) : Prop where
  runs : RetirementTailRuns bootstrap source row commit guards before after states
  guardsAssertedNext : states.guardsAsserted.next = before.next + 4
  guardsAssertedColumns : states.guardsAsserted.toColumns = before.toColumns
  currentAssertedNext : states.currentAsserted.next = before.next + 5
  currentAssertedColumns : states.currentAsserted.toColumns = before.toColumns
  writerNext : states.writerBefore.next = before.next + 6 + 3 * width
  writerBootstrap : states.writerBefore.bootstrap = before.bootstrap
  writerColumns : states.writerBefore.toColumns = before.toColumns
  finalNext : after.next = before.next + 23 + 3 * width

theorem retirement_tail_success {width : PNat} (bootstrap : BitVec width)
    (source : Fin width) (row : NodeRowTerms width) (commit : Expr .int)
    (guards : Expr .int -> List (Expr .bool)) (before after : Encoding width)
    (run : (retirementTail bootstrap source row commit guards).run before =
      .ok ((), after)) :
    exists states : RetirementTailStates width,
      RetirementTailExecutionResult bootstrap source row commit guards before after states := by
  rw [retirementTail] at run
  obtain ⟨first, firstFresh, firstRun, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨firstEq, firstNext, firstBootstrap, firstColumns, _⟩ :=
    fresh_success before firstFresh first firstRun
  subst first
  obtain ⟨retirement, retirementFresh, retirementRun, run⟩ :=
    (bind_run _ _ _ _ _).mp run
  obtain ⟨retirementEq, retirementNext, retirementBootstrap, retirementColumns, _⟩ :=
    fresh_success firstFresh retirementFresh retirement retirementRun
  have retirementId : retirement = before.next + 1 := by
    rw [retirementEq, firstNext]
  subst retirement
  obtain ⟨signature, signatureFresh, signatureRun, run⟩ :=
    (bind_run _ _ _ _ _).mp run
  obtain ⟨signatureEq, signatureNext, signatureBootstrap, signatureColumns, _⟩ :=
    fresh_success retirementFresh signatureFresh signature signatureRun
  have signatureId : signature = before.next + 2 := by
    rw [signatureEq, retirementNext, firstNext]
  subst signature
  obtain ⟨retired, retiredFresh, retiredRun, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨retiredEq, retiredNext, retiredBootstrap, retiredColumns, _⟩ :=
    fresh_success signatureFresh retiredFresh retired retiredRun
  have retiredId : retired = before.next + 3 := by
    rw [retiredEq, signatureNext, retirementNext, firstNext]
  subst retired
  obtain ⟨⟨⟩, refreshAsserted, refreshRun, run⟩ :=
    (bind_run _ _ _ _ _).mp run
  have refreshShape := assertion_success _ retiredFresh refreshAsserted refreshRun
  obtain ⟨⟨⟩, guardsAsserted, guardsRun, run⟩ :=
    (bind_run _ _ _ _ _).mp run
  have guardsShape := assert_all_success _ refreshAsserted guardsAsserted guardsRun
  obtain ⟨current, currentFresh, currentRun, run⟩ :=
    (bind_run _ _ _ _ _).mp run
  obtain ⟨currentEq, currentNext, currentBootstrap, currentColumns, _⟩ :=
    fresh_success guardsAsserted currentFresh current currentRun
  have currentId : current = before.next + 4 := by
    rw [currentEq, guardsShape.1.next, refreshShape.1.next, retiredNext,
      signatureNext, retirementNext, firstNext]
  subst current
  obtain ⟨⟨⟩, currentAsserted, currentAssertionRun, run⟩ :=
    (bind_run _ _ _ _ _).mp run
  have currentAssertionShape :=
    assertion_success _ currentFresh currentAsserted currentAssertionRun
  obtain ⟨completed, writerBefore, completedRun, writeRun⟩ :=
    (bind_run _ _ _ _ _).mp run
  have completedShape :=
    retirement_completed_constraints_success bootstrap (.boolean true) row.logLength
      row.logEntries commit _ currentAsserted writerBefore completed completedRun
  have completedId : completed = before.next + 5 := by
    rw [completedShape.completedId, currentAssertionShape.1.next, currentNext,
      guardsShape.1.next, refreshShape.1.next, retiredNext, signatureNext,
      retirementNext, firstNext]
  subst completed
  have firstFreshNext : firstFresh.next = before.next + 1 := firstNext
  have retirementFreshNext : retirementFresh.next = before.next + 2 := by
    rw [retirementNext, firstFreshNext]
  have signatureFreshNext : signatureFresh.next = before.next + 3 := by
    rw [signatureNext, retirementFreshNext]
  have retiredFreshNext : retiredFresh.next = before.next + 4 := by
    rw [retiredNext, signatureFreshNext]
  have refreshAssertedNext : refreshAsserted.next = before.next + 4 := by
    rw [refreshShape.1.next, retiredFreshNext]
  have guardsAssertedNext : guardsAsserted.next = before.next + 4 := by
    rw [guardsShape.1.next, refreshAssertedNext]
  have currentFreshNext : currentFresh.next = before.next + 5 := by
    rw [currentNext, guardsAssertedNext]
  have currentAssertedNext : currentAsserted.next = before.next + 5 := by
    rw [currentAssertionShape.1.next, currentFreshNext]
  have guardsAssertedColumns : guardsAsserted.toColumns = before.toColumns :=
    guardsShape.1.columns.trans
      (refreshShape.1.columns.trans
        (retiredColumns.trans
          (signatureColumns.trans
            (retirementColumns.trans firstColumns))))
  have currentAssertedColumns : currentAsserted.toColumns = before.toColumns :=
    currentAssertionShape.1.columns.trans
      (currentColumns.trans guardsAssertedColumns)
  let states : RetirementTailStates width :=
    { firstFresh, retirementFresh, signatureFresh, retiredFresh, refreshAsserted,
      guardsAsserted, currentFresh, currentAsserted, writerBefore }
  have runs :
      RetirementTailRuns bootstrap source row commit guards before after states := by
    refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
    · simpa only [states] using firstRun
    · simpa only [states, firstFreshNext] using retirementRun
    · simpa only [states, retirementFreshNext] using signatureRun
    · simpa only [states, signatureFreshNext] using retiredRun
    · simpa only [states, retirementTailTerms, firstFreshNext, retirementFreshNext,
        signatureFreshNext] using refreshRun
    · simpa only [states, retirementTailTerms, firstFreshNext, retirementFreshNext,
        signatureFreshNext] using guardsRun
    · simpa only [states, guardsAssertedNext] using currentRun
    · simpa only [states, retirementTailTerms, guardsAssertedNext] using
        currentAssertionRun
    · simpa only [states, retirementTailTerms, guardsAssertedNext] using completedRun
    · simpa only [states, retirementTailTerms, firstFreshNext, retirementFreshNext,
        signatureFreshNext, currentAssertedNext] using writeRun
  have writerNext : writerBefore.next = before.next + 6 + 3 * width := by
    rw [completedShape.next, currentAssertionShape.1.next, currentNext,
      guardsShape.1.next, refreshShape.1.next, retiredNext, signatureNext,
      retirementNext, firstNext]
  have writerBootstrap : writerBefore.bootstrap = before.bootstrap :=
    completedShape.sameBootstrap.trans
      (currentAssertionShape.1.bootstrap.trans
        (currentBootstrap.trans
          (guardsShape.1.bootstrap.trans
            (refreshShape.1.bootstrap.trans
              (retiredBootstrap.trans
                (signatureBootstrap.trans
                  (retirementBootstrap.trans firstBootstrap)))))))
  have writerColumns : writerBefore.toColumns = before.toColumns :=
    completedShape.sameColumns.trans currentAssertedColumns
  have finalNext : after.next = before.next + 23 + 3 * width := by
    rw [retirement_writes_next source (retirementTailTerms before row commit).values
      (retirementTailTerms before row commit).completed writerBefore after runs.writeRun,
      writerNext]
    omega
  exact ⟨states, runs, guardsAssertedNext, guardsAssertedColumns,
    currentAssertedNext, currentAssertedColumns, writerNext, writerBootstrap,
    writerColumns, finalNext⟩

theorem retirement_tail_constraints {width : PNat} (bootstrap : BitVec width)
    (source : Fin width) (row : NodeRowTerms width) (commit : Expr .int)
    (guards : Expr .int -> List (Expr .bool)) (before after : Encoding width)
    (states : RetirementTailStates width)
    (execution :
      RetirementTailExecutionResult bootstrap source row commit guards before after states)
    (assignment : Assignment)
    (writerHolds : Holds states.writerBefore.assertions.toList assignment) :
    RetirementTailConstraints bootstrap source row commit guards before assignment := by
  let terms := retirementTailTerms before row commit
  have completedHolds := retirement_completed_constraints_holds_before bootstrap
    (.boolean true) row.logLength row.logEntries commit terms.current
    states.currentAsserted states.writerBefore (before.next + 5)
    execution.runs.completedRun assignment writerHolds
  have currentFacts :=
    assertion_holds _ states.currentFresh states.currentAsserted
      execution.runs.currentAssertionRun assignment completedHolds
  have guardsHolds := fresh_prior_holds states.guardsAsserted states.currentFresh
    (before.next + 4) execution.runs.currentRun assignment currentFacts.1
  have guardFacts :=
    (assert_all_holds _ states.refreshAsserted states.guardsAsserted
      execution.runs.guardsRun assignment).mp guardsHolds
  have refreshFacts :=
    assertion_holds _ states.retiredFresh states.refreshAsserted
      execution.runs.refreshRun assignment guardFacts.1
  have signatureHolds := fresh_prior_holds states.signatureFresh states.retiredFresh
    (before.next + 3) execution.runs.retiredRun assignment refreshFacts.1
  have retirementHolds := fresh_prior_holds states.retirementFresh states.signatureFresh
    (before.next + 2) execution.runs.signatureRun assignment signatureHolds
  have firstHolds := fresh_prior_holds states.firstFresh states.retirementFresh
    (before.next + 1) execution.runs.retirementRun assignment retirementHolds
  have priorHolds := fresh_prior_holds before states.firstFresh before.next
    execution.runs.firstRun assignment firstHolds
  exact ⟨priorHolds, refreshFacts.2, guardFacts.2, currentFacts.2⟩

theorem retirement_tail_prior_holds {width : PNat} (bootstrap : BitVec width)
    (source : Fin width) (row : NodeRowTerms width) (commit : Expr .int)
    (guards : Expr .int -> List (Expr .bool)) (before after : Encoding width)
    (run : (retirementTail bootstrap source row commit guards).run before =
      .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment) :
    Holds before.assertions.toList assignment := by
  obtain ⟨states, result⟩ :=
    retirement_tail_success bootstrap source row commit guards before after run
  let terms := retirementTailTerms before row commit
  have writerHolds := retirement_writes_prior_holds source terms.values terms.completed
    states.writerBefore after result.runs.writeRun assignment holds
  exact (retirement_tail_constraints bootstrap source row commit guards before after
    states result assignment writerHolds).priorHolds

theorem retirement_tail_bootstrap {width : PNat} (bootstrap : BitVec width)
    (source : Fin width) (row : NodeRowTerms width) (commit : Expr .int)
    (guards : Expr .int -> List (Expr .bool)) (before after : Encoding width)
    (run : (retirementTail bootstrap source row commit guards).run before =
      .ok ((), after)) :
    after.bootstrap = before.bootstrap := by
  obtain ⟨states, result⟩ :=
    retirement_tail_success bootstrap source row commit guards before after run
  exact (retirement_writes_bootstrap source
    (retirementTailTerms before row commit).values
    (retirementTailTerms before row commit).completed states.writerBefore after
    result.runs.writeRun).trans result.writerBootstrap

theorem retirement_tail_references {width : PNat} (bootstrap : BitVec width)
    (source : Fin width) (row : NodeRowTerms width) (commit : Expr .int)
    (guards : Expr .int -> List (Expr .bool)) (before after : Encoding width)
    (run : (retirementTail bootstrap source row commit guards).run before =
      .ok ((), after))
    (valid : ReferencesValid before) : ReferencesValid after := by
  obtain ⟨states, result⟩ :=
    retirement_tail_success bootstrap source row commit guards before after run
  have writerValid : ReferencesValid states.writerBefore := by
    cases valid
    constructor <;> simp_all only [result.writerColumns, result.writerNext] <;> omega
  exact retirement_writes_references source
    (retirementTailTerms before row commit).values
    (retirementTailTerms before row commit).completed states.writerBefore after
    result.runs.writeRun writerValid

theorem retirement_tail_next {width : PNat} (bootstrap : BitVec width)
    (source : Fin width) (row : NodeRowTerms width) (commit : Expr .int)
    (guards : Expr .int -> List (Expr .bool)) (before after : Encoding width)
    (run : (retirementTail bootstrap source row commit guards).run before =
      .ok ((), after)) :
    after.next = before.next + 23 + 3 * width := by
  obtain ⟨_, result⟩ :=
    retirement_tail_success bootstrap source row commit guards before after run
  exact result.finalNext

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
