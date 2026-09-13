-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAdvanceCommit
import Sparse.NativeRetirementCompletedConstraintsEncoding
import Sparse.NativeRetirementWritesEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

structure CommitExecutionTerms (width : PNat) where
  old : NodeRowTerms width
  (current best first retirement signature retired committedCurrent : Expr .int)
  completed : Expr (.bits width)
  values : NodeRowTerms width

def commitExecutionTerms {width : PNat} (before : Encoding width)
    (source : Fin width) : CommitExecutionTerms width :=
  let old := nodeRowSnapshot before.toColumns source
  let current : Expr .int := .free .int before.next
  let best : Expr .int := .free .int (before.next + 1)
  let first : Expr .int := .free .int (before.next + 2)
  let retirement : Expr .int := .free .int (before.next + 3)
  let signature : Expr .int := .free .int (before.next + 4)
  let retired : Expr .int := .free .int (before.next + 5)
  let committedCurrent : Expr .int := .free .int (before.next + 6)
  let completed : Expr (.bits width) := .free _ (before.next + 7)
  { old, current, best, first, retirement, signature, retired, committedCurrent,
    completed
    values := commitRowTerms old best retirement signature retired }

structure CommitPrefixStates (width : PNat) where
  currentFresh : Encoding width
  currentAsserted : Encoding width
  bestFresh : Encoding width
  bestAsserted : Encoding width

structure CommitRefreshStates (width : PNat) where
  firstFresh : Encoding width
  retirementFresh : Encoding width
  signatureFresh : Encoding width
  retiredFresh : Encoding width
  refreshAsserted : Encoding width
  guardsAsserted : Encoding width

structure CommitSuffixStates (width : PNat) where
  committedCurrentFresh : Encoding width
  committedCurrentAsserted : Encoding width
  writerBefore : Encoding width

structure CommitExecutionStates (width : PNat) where
  prefixStates : CommitPrefixStates width
  refreshStates : CommitRefreshStates width
  suffixStates : CommitSuffixStates width

structure CommitExecutionRuns {width : PNat} (source : Fin width)
    (before after : Encoding width) (states : CommitExecutionStates width) : Prop where
  currentRun : fresh.run before = .ok (before.next, states.prefixStates.currentFresh)
  currentAssertionRun :
    let terms := commitExecutionTerms before source
    (assertion (currentConfigurationIndexTerm width terms.old.logLength
      terms.old.logEntries terms.old.commit terms.current)).run
        states.prefixStates.currentFresh = .ok ((), states.prefixStates.currentAsserted)
  bestRun : fresh.run states.prefixStates.currentAsserted =
    .ok (before.next + 1, states.prefixStates.bestFresh)
  bestAssertionRun :
    let terms := commitExecutionTerms before source
    (assertion (highestCommitIndexTerm width before.bootstrap terms.old.logLength
      terms.old.logEntries terms.old.matchIndex source terms.old.commit
      terms.old.currentTerm terms.current terms.best)).run states.prefixStates.bestFresh =
        .ok ((), states.prefixStates.bestAsserted)
  firstRun : fresh.run states.prefixStates.bestAsserted =
    .ok (before.next + 2, states.refreshStates.firstFresh)
  retirementRun : fresh.run states.refreshStates.firstFresh =
    .ok (before.next + 3, states.refreshStates.retirementFresh)
  signatureRun : fresh.run states.refreshStates.retirementFresh =
    .ok (before.next + 4, states.refreshStates.signatureFresh)
  retiredRun : fresh.run states.refreshStates.signatureFresh =
    .ok (before.next + 5, states.refreshStates.retiredFresh)
  refreshRun :
    let terms := commitExecutionTerms before source
    (assertion (retirementRefreshConstraints width before.bootstrap terms.old.logLength
      terms.old.logEntries source terms.first terms.retirement terms.signature
      terms.retired)).run states.refreshStates.retiredFresh =
        .ok ((), states.refreshStates.refreshAsserted)
  guardsRun :
    let terms := commitExecutionTerms before source
    (assertAll (commitGuards before.toColumns source terms.best
      terms.values.membershipState)).run states.refreshStates.refreshAsserted =
        .ok ((), states.refreshStates.guardsAsserted)
  committedCurrentRun : fresh.run states.refreshStates.guardsAsserted =
    .ok (before.next + 6, states.suffixStates.committedCurrentFresh)
  committedCurrentAssertionRun :
    let terms := commitExecutionTerms before source
    (assertion (currentConfigurationIndexTerm width terms.old.logLength
      terms.old.logEntries terms.best terms.committedCurrent)).run
        states.suffixStates.committedCurrentFresh =
          .ok ((), states.suffixStates.committedCurrentAsserted)
  completedRun :
    let terms := commitExecutionTerms before source
    (retirementCompletedConstraints before.bootstrap (.boolean true)
      terms.old.logLength terms.old.logEntries terms.best terms.committedCurrent).run
        states.suffixStates.committedCurrentAsserted =
          .ok (before.next + 7, states.suffixStates.writerBefore)
  writeRun :
    let terms := commitExecutionTerms before source
    (writeRetirementRow source terms.values terms.completed).run
      states.suffixStates.writerBefore = .ok ((), after)

structure CommitPrefixConstraints {width : PNat} (before : Encoding width)
    (source : Fin width) (assignment : Assignment) : Prop where
  priorHolds : Holds before.assertions.toList assignment
  current :
    let terms := commitExecutionTerms before source
    (currentConfigurationIndexTerm width terms.old.logLength terms.old.logEntries
      terms.old.commit terms.current).eval assignment Locals.empty = true
  best :
    let terms := commitExecutionTerms before source
    (highestCommitIndexTerm width before.bootstrap terms.old.logLength
      terms.old.logEntries terms.old.matchIndex source terms.old.commit
      terms.old.currentTerm terms.current terms.best).eval assignment Locals.empty = true
  refresh :
    let terms := commitExecutionTerms before source
    (retirementRefreshConstraints width before.bootstrap terms.old.logLength
      terms.old.logEntries source terms.first terms.retirement terms.signature
      terms.retired).eval assignment Locals.empty = true
  guards :
    let terms := commitExecutionTerms before source
    Holds (commitGuards before.toColumns source terms.best
      terms.values.membershipState) assignment
  committedCurrent :
    let terms := commitExecutionTerms before source
    (currentConfigurationIndexTerm width terms.old.logLength terms.old.logEntries
      terms.best terms.committedCurrent).eval assignment Locals.empty = true

structure CommitExecutionResult {width : PNat} (source : Fin width)
    (before after : Encoding width) (states : CommitExecutionStates width) : Prop where
  runs : CommitExecutionRuns source before after states
  currentAssertedNext :
    states.prefixStates.currentAsserted.next = before.next + 1
  currentAssertedColumns :
    states.prefixStates.currentAsserted.toColumns = before.toColumns
  bestAssertedNext :
    states.prefixStates.bestAsserted.next = before.next + 2
  bestAssertedColumns :
    states.prefixStates.bestAsserted.toColumns = before.toColumns
  guardsAssertedNext :
    states.refreshStates.guardsAsserted.next = before.next + 6
  guardsAssertedColumns :
    states.refreshStates.guardsAsserted.toColumns = before.toColumns
  committedCurrentAssertedNext :
    states.suffixStates.committedCurrentAsserted.next = before.next + 7
  committedCurrentAssertedColumns :
    states.suffixStates.committedCurrentAsserted.toColumns = before.toColumns
  writerNext : states.suffixStates.writerBefore.next = before.next + 8 + 3 * width
  writerBootstrap : states.suffixStates.writerBefore.bootstrap = before.bootstrap
  writerColumns : states.suffixStates.writerBefore.toColumns = before.toColumns
  finalNext : after.next = before.next + 25 + 3 * width

theorem advance_commit_success {width : PNat} (source : Fin width)
    (before after : Encoding width)
    (run : (advanceCommitIndex source).run before = .ok ((), after)) :
    exists states : CommitExecutionStates width,
      CommitExecutionResult source before after states := by
  rw [advanceCommitIndex, get_bind_run] at run
  obtain ⟨current, currentFresh, currentRun, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨currentEq, currentNext, currentBootstrap, currentColumns, _⟩ :=
    fresh_success before currentFresh current currentRun
  subst current
  obtain ⟨⟨⟩, currentAsserted, currentAssertionRun, run⟩ :=
    (bind_run _ _ _ _ _).mp run
  have currentAssertionShape :=
    assertion_success _ currentFresh currentAsserted currentAssertionRun
  obtain ⟨best, bestFresh, bestRun, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨bestEq, bestNext, bestBootstrap, bestColumns, _⟩ :=
    fresh_success currentAsserted bestFresh best bestRun
  have bestId : best = before.next + 1 := by
    rw [bestEq, currentAssertionShape.1.next, currentNext]
  subst best
  obtain ⟨⟨⟩, bestAsserted, bestAssertionRun, run⟩ :=
    (bind_run _ _ _ _ _).mp run
  have bestAssertionShape := assertion_success _ bestFresh bestAsserted bestAssertionRun
  obtain ⟨first, firstFresh, firstRun, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨firstEq, firstNext, firstBootstrap, firstColumns, _⟩ :=
    fresh_success bestAsserted firstFresh first firstRun
  have firstId : first = before.next + 2 := by
    rw [firstEq, bestAssertionShape.1.next, bestNext,
      currentAssertionShape.1.next, currentNext]
  subst first
  obtain ⟨retirement, retirementFresh, retirementRun, run⟩ :=
    (bind_run _ _ _ _ _).mp run
  obtain ⟨retirementEq, retirementNext, retirementBootstrap, retirementColumns, _⟩ :=
    fresh_success firstFresh retirementFresh retirement retirementRun
  have retirementId : retirement = before.next + 3 := by
    rw [retirementEq, firstNext, bestAssertionShape.1.next, bestNext,
      currentAssertionShape.1.next, currentNext]
  subst retirement
  obtain ⟨signature, signatureFresh, signatureRun, run⟩ :=
    (bind_run _ _ _ _ _).mp run
  obtain ⟨signatureEq, signatureNext, signatureBootstrap, signatureColumns, _⟩ :=
    fresh_success retirementFresh signatureFresh signature signatureRun
  have signatureId : signature = before.next + 4 := by
    rw [signatureEq, retirementNext, firstNext, bestAssertionShape.1.next, bestNext,
      currentAssertionShape.1.next, currentNext]
  subst signature
  obtain ⟨retired, retiredFresh, retiredRun, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨retiredEq, retiredNext, retiredBootstrap, retiredColumns, _⟩ :=
    fresh_success signatureFresh retiredFresh retired retiredRun
  have retiredId : retired = before.next + 5 := by
    rw [retiredEq, signatureNext, retirementNext, firstNext,
      bestAssertionShape.1.next, bestNext, currentAssertionShape.1.next, currentNext]
  subst retired
  obtain ⟨⟨⟩, refreshAsserted, refreshRun, run⟩ := (bind_run _ _ _ _ _).mp run
  have refreshShape := assertion_success _ retiredFresh refreshAsserted refreshRun
  obtain ⟨⟨⟩, guardsAsserted, guardsRun, run⟩ := (bind_run _ _ _ _ _).mp run
  have guardsShape := assert_all_success _ refreshAsserted guardsAsserted guardsRun
  obtain ⟨committedCurrent, committedCurrentFresh, committedCurrentRun, run⟩ :=
    (bind_run _ _ _ _ _).mp run
  obtain ⟨committedCurrentEq, committedCurrentNext, committedCurrentBootstrap,
    committedCurrentColumns, _⟩ :=
    fresh_success guardsAsserted committedCurrentFresh committedCurrent committedCurrentRun
  have committedCurrentId : committedCurrent = before.next + 6 := by
    rw [committedCurrentEq, guardsShape.1.next, refreshShape.1.next, retiredNext,
      signatureNext, retirementNext, firstNext, bestAssertionShape.1.next, bestNext,
      currentAssertionShape.1.next, currentNext]
  subst committedCurrent
  obtain ⟨⟨⟩, committedCurrentAsserted, committedCurrentAssertionRun, run⟩ :=
    (bind_run _ _ _ _ _).mp run
  have committedCurrentAssertionShape :=
    assertion_success _ committedCurrentFresh committedCurrentAsserted
      committedCurrentAssertionRun
  obtain ⟨completed, writerBefore, completedRun, writeRun⟩ :=
    (bind_run _ _ _ _ _).mp run
  have completedShape :=
    retirement_completed_constraints_success before.bootstrap (.boolean true)
      (nodeRowSnapshot before.toColumns source).logLength
      (nodeRowSnapshot before.toColumns source).logEntries
      _ _ committedCurrentAsserted writerBefore completed completedRun
  have completedId : completed = before.next + 7 := by
    rw [completedShape.completedId, committedCurrentAssertionShape.1.next,
      committedCurrentNext, guardsShape.1.next, refreshShape.1.next, retiredNext,
      signatureNext, retirementNext, firstNext, bestAssertionShape.1.next, bestNext,
      currentAssertionShape.1.next, currentNext]
  subst completed
  have currentAssertedNext : currentAsserted.next = before.next + 1 := by
    rw [currentAssertionShape.1.next, currentNext]
  have bestFreshNext : bestFresh.next = before.next + 2 := by
    rw [bestNext, currentAssertedNext]
  have bestAssertedNext : bestAsserted.next = before.next + 2 := by
    rw [bestAssertionShape.1.next, bestFreshNext]
  have firstFreshNext : firstFresh.next = before.next + 3 := by
    rw [firstNext, bestAssertedNext]
  have retirementFreshNext : retirementFresh.next = before.next + 4 := by
    rw [retirementNext, firstFreshNext]
  have signatureFreshNext : signatureFresh.next = before.next + 5 := by
    rw [signatureNext, retirementFreshNext]
  have retiredFreshNext : retiredFresh.next = before.next + 6 := by
    rw [retiredNext, signatureFreshNext]
  have refreshAssertedNext : refreshAsserted.next = before.next + 6 := by
    rw [refreshShape.1.next, retiredFreshNext]
  have guardsAssertedNext : guardsAsserted.next = before.next + 6 := by
    rw [guardsShape.1.next, refreshAssertedNext]
  have committedCurrentFreshNext :
      committedCurrentFresh.next = before.next + 7 := by
    rw [committedCurrentNext, guardsAssertedNext]
  have committedCurrentAssertedNext :
      committedCurrentAsserted.next = before.next + 7 := by
    rw [committedCurrentAssertionShape.1.next, committedCurrentFreshNext]
  have currentAssertedColumns : currentAsserted.toColumns = before.toColumns :=
    currentAssertionShape.1.columns.trans currentColumns
  have bestAssertedColumns : bestAsserted.toColumns = before.toColumns :=
    bestAssertionShape.1.columns.trans (bestColumns.trans currentAssertedColumns)
  have guardsAssertedColumns : guardsAsserted.toColumns = before.toColumns :=
    guardsShape.1.columns.trans
      (refreshShape.1.columns.trans
        (retiredColumns.trans
          (signatureColumns.trans
            (retirementColumns.trans (firstColumns.trans bestAssertedColumns)))))
  have committedCurrentAssertedColumns :
      committedCurrentAsserted.toColumns = before.toColumns :=
    committedCurrentAssertionShape.1.columns.trans
      (committedCurrentColumns.trans guardsAssertedColumns)
  let prefixStates : CommitPrefixStates width :=
    { currentFresh, currentAsserted, bestFresh, bestAsserted }
  let refreshStates : CommitRefreshStates width :=
    { firstFresh, retirementFresh, signatureFresh, retiredFresh, refreshAsserted,
      guardsAsserted }
  let suffixStates : CommitSuffixStates width :=
    { committedCurrentFresh, committedCurrentAsserted, writerBefore }
  let states : CommitExecutionStates width :=
    { prefixStates, refreshStates, suffixStates }
  have runs : CommitExecutionRuns source before after states := by
    refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
    · simpa only [states, prefixStates] using currentRun
    · simpa only [states, prefixStates, commitExecutionTerms] using currentAssertionRun
    · simpa only [states, prefixStates, currentAssertedNext] using bestRun
    · simpa only [states, prefixStates, commitExecutionTerms, currentAssertedNext] using
        bestAssertionRun
    · simpa only [states, prefixStates, refreshStates, bestAssertedNext] using firstRun
    · simpa only [states, refreshStates, firstFreshNext] using retirementRun
    · simpa only [states, refreshStates, retirementFreshNext] using signatureRun
    · simpa only [states, refreshStates, signatureFreshNext] using retiredRun
    · simpa only [states, refreshStates, commitExecutionTerms, bestAssertedNext,
        firstFreshNext, retirementFreshNext, signatureFreshNext] using refreshRun
    · simpa only [states, refreshStates, commitExecutionTerms, currentAssertedNext,
        firstFreshNext, retirementFreshNext, signatureFreshNext] using guardsRun
    · simpa only [states, refreshStates, suffixStates, guardsAssertedNext] using
        committedCurrentRun
    · simpa only [states, suffixStates, commitExecutionTerms, currentAssertedNext,
        guardsAssertedNext] using committedCurrentAssertionRun
    · simpa only [states, suffixStates, commitExecutionTerms, currentAssertedNext,
        guardsAssertedNext] using completedRun
    · simpa only [states, suffixStates, commitExecutionTerms, currentAssertedNext,
        firstFreshNext, retirementFreshNext, signatureFreshNext,
        committedCurrentAssertedNext] using writeRun
  have writerNext : writerBefore.next = before.next + 8 + 3 * width := by
    rw [completedShape.next, committedCurrentAssertionShape.1.next, committedCurrentNext,
      guardsShape.1.next, refreshShape.1.next, retiredNext, signatureNext, retirementNext,
      firstNext, bestAssertionShape.1.next, bestNext, currentAssertionShape.1.next,
      currentNext]
  have writerBootstrap : writerBefore.bootstrap = before.bootstrap := by
    exact completedShape.sameBootstrap.trans
      (committedCurrentAssertionShape.1.bootstrap.trans
        (committedCurrentBootstrap.trans
          (guardsShape.1.bootstrap.trans
            (refreshShape.1.bootstrap.trans
              (retiredBootstrap.trans
                (signatureBootstrap.trans
                  (retirementBootstrap.trans
                    (firstBootstrap.trans
                      (bestAssertionShape.1.bootstrap.trans
                        (bestBootstrap.trans
                          (currentAssertionShape.1.bootstrap.trans currentBootstrap)))))))))))
  have writerColumns : writerBefore.toColumns = before.toColumns := by
    exact completedShape.sameColumns.trans committedCurrentAssertedColumns
  have finalNext : after.next = before.next + 25 + 3 * width := by
    rw [retirement_writes_next source (commitExecutionTerms before source).values
      (commitExecutionTerms before source).completed writerBefore after runs.writeRun,
      writerNext]
    omega
  exact ⟨states, runs, currentAssertedNext, currentAssertedColumns,
    bestAssertedNext, bestAssertedColumns, guardsAssertedNext, guardsAssertedColumns,
    committedCurrentAssertedNext, committedCurrentAssertedColumns, writerNext,
    writerBootstrap, writerColumns, finalNext⟩

theorem commit_prefix_constraints {width : PNat} (source : Fin width)
    (before after : Encoding width) (states : CommitExecutionStates width)
    (execution : CommitExecutionResult source before after states)
    (assignment : Assignment)
    (writerHolds : Holds states.suffixStates.writerBefore.assertions.toList assignment) :
    CommitPrefixConstraints before source assignment := by
  let terms := commitExecutionTerms before source
  have completedHolds := retirement_completed_constraints_holds_before before.bootstrap
    (.boolean true) terms.old.logLength terms.old.logEntries terms.best
    terms.committedCurrent states.suffixStates.committedCurrentAsserted
    states.suffixStates.writerBefore (before.next + 7) execution.runs.completedRun
    assignment writerHolds
  have committedCurrentFacts :=
    (assertion_holds _ states.suffixStates.committedCurrentFresh
      states.suffixStates.committedCurrentAsserted
      execution.runs.committedCurrentAssertionRun assignment completedHolds)
  have guardsHolds := fresh_prior_holds states.refreshStates.guardsAsserted
    states.suffixStates.committedCurrentFresh (before.next + 6)
    execution.runs.committedCurrentRun assignment committedCurrentFacts.1
  have guardFacts :=
    (assert_all_holds _ states.refreshStates.refreshAsserted
      states.refreshStates.guardsAsserted execution.runs.guardsRun assignment).mp
      guardsHolds
  have refreshFacts :=
    assertion_holds _ states.refreshStates.retiredFresh
      states.refreshStates.refreshAsserted execution.runs.refreshRun assignment
      guardFacts.1
  have signatureHolds := fresh_prior_holds states.refreshStates.signatureFresh
    states.refreshStates.retiredFresh (before.next + 5) execution.runs.retiredRun
    assignment refreshFacts.1
  have retirementHolds := fresh_prior_holds states.refreshStates.retirementFresh
    states.refreshStates.signatureFresh (before.next + 4) execution.runs.signatureRun
    assignment signatureHolds
  have firstHolds := fresh_prior_holds states.refreshStates.firstFresh
    states.refreshStates.retirementFresh (before.next + 3) execution.runs.retirementRun
    assignment retirementHolds
  have bestAssertedHolds := fresh_prior_holds states.prefixStates.bestAsserted
    states.refreshStates.firstFresh (before.next + 2) execution.runs.firstRun
    assignment firstHolds
  have bestFacts :=
    assertion_holds _ states.prefixStates.bestFresh states.prefixStates.bestAsserted
      execution.runs.bestAssertionRun assignment bestAssertedHolds
  have currentAssertedHolds := fresh_prior_holds states.prefixStates.currentAsserted
    states.prefixStates.bestFresh (before.next + 1) execution.runs.bestRun assignment
    bestFacts.1
  have currentFacts :=
    assertion_holds _ states.prefixStates.currentFresh
      states.prefixStates.currentAsserted execution.runs.currentAssertionRun
      assignment currentAssertedHolds
  have priorHolds := fresh_prior_holds before states.prefixStates.currentFresh before.next
    execution.runs.currentRun assignment currentFacts.1
  exact ⟨priorHolds, currentFacts.2, bestFacts.2, refreshFacts.2, guardFacts.2,
    committedCurrentFacts.2⟩

theorem advance_commit_prior_holds {width : PNat} (source : Fin width)
    (before after : Encoding width)
    (run : (advanceCommitIndex source).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment) :
    Holds before.assertions.toList assignment := by
  obtain ⟨states, result⟩ := advance_commit_success source before after run
  let terms := commitExecutionTerms before source
  have writerHolds := retirement_writes_prior_holds source terms.values terms.completed
    states.suffixStates.writerBefore after result.runs.writeRun assignment holds
  exact (commit_prefix_constraints source before after states result assignment
    writerHolds).priorHolds

theorem advance_commit_bootstrap {width : PNat} (source : Fin width)
    (before after : Encoding width)
    (run : (advanceCommitIndex source).run before = .ok ((), after)) :
    after.bootstrap = before.bootstrap := by
  obtain ⟨states, result⟩ := advance_commit_success source before after run
  exact (retirement_writes_bootstrap source
    (commitExecutionTerms before source).values
    (commitExecutionTerms before source).completed states.suffixStates.writerBefore after
    result.runs.writeRun).trans result.writerBootstrap

theorem advance_commit_references {width : PNat} (source : Fin width)
    (before after : Encoding width)
    (run : (advanceCommitIndex source).run before = .ok ((), after))
    (valid : ReferencesValid before) : ReferencesValid after := by
  obtain ⟨states, result⟩ := advance_commit_success source before after run
  have writerValid : ReferencesValid states.suffixStates.writerBefore := by
    cases valid
    constructor <;> simp_all only [result.writerColumns, result.writerNext] <;> omega
  exact retirement_writes_references source
    (commitExecutionTerms before source).values
    (commitExecutionTerms before source).completed states.suffixStates.writerBefore after
    result.runs.writeRun writerValid

theorem advance_commit_next {width : PNat} (source : Fin width)
    (before after : Encoding width)
    (run : (advanceCommitIndex source).run before = .ok ((), after)) :
    after.next = before.next + 25 + 3 * width := by
  obtain ⟨states, result⟩ := advance_commit_success source before after run
  exact result.finalNext

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
