-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAdvanceCommit
import Sparse.NativeRetirementTailExecution

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

def commitTailStates {width : PNat}
    (states : CommitExecutionStates width) : RetirementTailStates width :=
  { firstFresh := states.refreshStates.firstFresh
    retirementFresh := states.refreshStates.retirementFresh
    signatureFresh := states.refreshStates.signatureFresh
    retiredFresh := states.refreshStates.retiredFresh
    refreshAsserted := states.refreshStates.refreshAsserted
    guardsAsserted := states.refreshStates.guardsAsserted
    currentFresh := states.suffixStates.committedCurrentFresh
    currentAsserted := states.suffixStates.committedCurrentAsserted
    writerBefore := states.suffixStates.writerBefore }

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
  tailRun :
    let terms := commitExecutionTerms before source
    (retirementTail before.bootstrap source terms.old terms.best
      (commitGuards before.toColumns source terms.best)).run
        states.prefixStates.bestAsserted = .ok ((), after)
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
  bestAssertedBootstrap :
    states.prefixStates.bestAsserted.bootstrap = before.bootstrap
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

theorem commit_tail_execution {width : PNat} (source : Fin width)
    (before after : Encoding width) (states : CommitExecutionStates width)
    (execution : CommitExecutionResult source before after states) :
    let terms := commitExecutionTerms before source
    RetirementTailExecutionResult before.bootstrap source terms.old terms.best
      (commitGuards before.toColumns source terms.best)
      states.prefixStates.bestAsserted after (commitTailStates states) := by
  let terms := commitExecutionTerms before source
  have runs :
      RetirementTailRuns before.bootstrap source terms.old terms.best
        (commitGuards before.toColumns source terms.best)
        states.prefixStates.bestAsserted after (commitTailStates states) := by
    refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
    · simpa [terms, commitTailStates, retirementTailTerms, commitExecutionTerms,
        execution.bestAssertedNext] using execution.runs.firstRun
    · simpa [terms, commitTailStates, retirementTailTerms, commitExecutionTerms,
        execution.bestAssertedNext] using execution.runs.retirementRun
    · simpa [terms, commitTailStates, retirementTailTerms, commitExecutionTerms,
        execution.bestAssertedNext] using execution.runs.signatureRun
    · simpa [terms, commitTailStates, retirementTailTerms, commitExecutionTerms,
        execution.bestAssertedNext] using execution.runs.retiredRun
    · simpa [terms, commitTailStates, retirementTailTerms, commitExecutionTerms,
        execution.bestAssertedNext] using execution.runs.refreshRun
    · simpa [terms, commitTailStates, retirementTailTerms, commitExecutionTerms,
        execution.bestAssertedNext] using execution.runs.guardsRun
    · simpa [terms, commitTailStates, retirementTailTerms, commitExecutionTerms,
        execution.bestAssertedNext] using execution.runs.committedCurrentRun
    · simpa [terms, commitTailStates, retirementTailTerms, commitExecutionTerms,
        execution.bestAssertedNext] using execution.runs.committedCurrentAssertionRun
    · simpa [terms, commitTailStates, retirementTailTerms, commitExecutionTerms,
        execution.bestAssertedNext] using execution.runs.completedRun
    · simpa [terms, commitTailStates, retirementTailTerms, commitExecutionTerms,
        execution.bestAssertedNext] using execution.runs.writeRun
  refine ⟨runs, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · rw [commitTailStates, execution.guardsAssertedNext,
      execution.bestAssertedNext]
  · rw [commitTailStates, execution.guardsAssertedColumns,
      execution.bestAssertedColumns]
  · rw [commitTailStates, execution.committedCurrentAssertedNext,
      execution.bestAssertedNext]
  · rw [commitTailStates, execution.committedCurrentAssertedColumns,
      execution.bestAssertedColumns]
  · rw [commitTailStates, execution.writerNext, execution.bestAssertedNext]
  · rw [commitTailStates, execution.writerBootstrap,
      execution.bestAssertedBootstrap]
  · rw [commitTailStates, execution.writerColumns,
      execution.bestAssertedColumns]
  · rw [execution.finalNext, execution.bestAssertedNext]

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
  obtain ⟨⟨⟩, bestAsserted, bestAssertionRun, run⟩ :=
    (bind_run _ _ _ _ _).mp run
  have bestAssertionShape := assertion_success _ bestFresh bestAsserted bestAssertionRun
  have currentAssertedNext : currentAsserted.next = before.next + 1 := by
    rw [currentAssertionShape.1.next, currentNext]
  have bestFreshNext : bestFresh.next = before.next + 2 := by
    rw [bestNext, currentAssertedNext]
  have bestAssertedNext : bestAsserted.next = before.next + 2 := by
    rw [bestAssertionShape.1.next, bestFreshNext]
  have currentAssertedColumns : currentAsserted.toColumns = before.toColumns :=
    currentAssertionShape.1.columns.trans currentColumns
  have bestAssertedColumns : bestAsserted.toColumns = before.toColumns :=
    bestAssertionShape.1.columns.trans (bestColumns.trans currentAssertedColumns)
  have bestAssertedBootstrap : bestAsserted.bootstrap = before.bootstrap :=
    bestAssertionShape.1.bootstrap.trans
      (bestBootstrap.trans
        (currentAssertionShape.1.bootstrap.trans currentBootstrap))
  have tailRun :
      (retirementTail before.bootstrap source
        (nodeRowSnapshot before.toColumns source)
        (.free .int best)
        (commitGuards before.toColumns source
          (.free .int best))).run bestAsserted =
          .ok ((), after) := by
    exact run
  obtain ⟨tailStates, tailExecution⟩ :=
    retirement_tail_success before.bootstrap source
      (nodeRowSnapshot before.toColumns source) (.free .int best)
      (commitGuards before.toColumns source (.free .int best))
      bestAsserted after tailRun
  let terms := commitExecutionTerms before source
  let prefixStates : CommitPrefixStates width :=
    { currentFresh, currentAsserted, bestFresh, bestAsserted }
  let refreshStates : CommitRefreshStates width :=
    { firstFresh := tailStates.firstFresh
      retirementFresh := tailStates.retirementFresh
      signatureFresh := tailStates.signatureFresh
      retiredFresh := tailStates.retiredFresh
      refreshAsserted := tailStates.refreshAsserted
      guardsAsserted := tailStates.guardsAsserted }
  let suffixStates : CommitSuffixStates width :=
    { committedCurrentFresh := tailStates.currentFresh
      committedCurrentAsserted := tailStates.currentAsserted
      writerBefore := tailStates.writerBefore }
  let states : CommitExecutionStates width :=
    { prefixStates, refreshStates, suffixStates }
  have runs : CommitExecutionRuns source before after states := by
    refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
    · simpa only [states, prefixStates] using currentRun
    · simpa only [states, prefixStates, commitExecutionTerms] using currentAssertionRun
    · simpa only [states, prefixStates, currentAssertedNext, bestId] using bestRun
    · simpa only [states, prefixStates, commitExecutionTerms, currentAssertedNext,
        bestId] using
        bestAssertionRun
    · simpa only [states, prefixStates, terms, commitExecutionTerms, bestId] using tailRun
    · simpa [states, refreshStates, terms, retirementTailTerms, commitExecutionTerms,
        bestAssertedNext, bestId] using tailExecution.runs.firstRun
    · simpa [states, refreshStates, terms, retirementTailTerms, commitExecutionTerms,
        bestAssertedNext, bestId] using tailExecution.runs.retirementRun
    · simpa [states, refreshStates, terms, retirementTailTerms, commitExecutionTerms,
        bestAssertedNext, bestId] using tailExecution.runs.signatureRun
    · simpa [states, refreshStates, terms, retirementTailTerms, commitExecutionTerms,
        bestAssertedNext, bestId] using tailExecution.runs.retiredRun
    · simpa [states, refreshStates, terms, retirementTailTerms, commitExecutionTerms,
        bestAssertedNext, bestId] using tailExecution.runs.refreshRun
    · simpa [states, refreshStates, terms, retirementTailTerms, commitExecutionTerms,
        bestAssertedNext, bestId] using tailExecution.runs.guardsRun
    · simpa [states, refreshStates, suffixStates, terms, retirementTailTerms,
        commitExecutionTerms, bestAssertedNext, bestId] using tailExecution.runs.currentRun
    · simpa [states, suffixStates, terms, retirementTailTerms, commitExecutionTerms,
        bestAssertedNext, bestId] using tailExecution.runs.currentAssertionRun
    · simpa [states, suffixStates, terms, retirementTailTerms, commitExecutionTerms,
        bestAssertedNext, bestId] using tailExecution.runs.completedRun
    · simpa [states, suffixStates, terms, retirementTailTerms, commitExecutionTerms,
        bestAssertedNext, bestId] using tailExecution.runs.writeRun
  have guardsAssertedNext :
      tailStates.guardsAsserted.next = before.next + 6 := by
    rw [tailExecution.guardsAssertedNext, bestAssertedNext]
  have guardsAssertedColumns :
      tailStates.guardsAsserted.toColumns = before.toColumns :=
    tailExecution.guardsAssertedColumns.trans bestAssertedColumns
  have committedCurrentAssertedNext :
      tailStates.currentAsserted.next = before.next + 7 := by
    rw [tailExecution.currentAssertedNext, bestAssertedNext]
  have committedCurrentAssertedColumns :
      tailStates.currentAsserted.toColumns = before.toColumns :=
    tailExecution.currentAssertedColumns.trans bestAssertedColumns
  have writerNext :
      tailStates.writerBefore.next = before.next + 8 + 3 * width := by
    rw [tailExecution.writerNext, bestAssertedNext]
  have writerBootstrap :
      tailStates.writerBefore.bootstrap = before.bootstrap :=
    tailExecution.writerBootstrap.trans bestAssertedBootstrap
  have writerColumns :
      tailStates.writerBefore.toColumns = before.toColumns :=
    tailExecution.writerColumns.trans bestAssertedColumns
  have finalNext : after.next = before.next + 25 + 3 * width := by
    rw [tailExecution.finalNext, bestAssertedNext]
  exact ⟨states, runs, currentAssertedNext, currentAssertedColumns,
    bestAssertedNext, bestAssertedColumns, bestAssertedBootstrap,
    guardsAssertedNext, guardsAssertedColumns, committedCurrentAssertedNext,
    committedCurrentAssertedColumns, writerNext, writerBootstrap, writerColumns,
    finalNext⟩

theorem commit_prefix_constraints {width : PNat} (source : Fin width)
    (before after : Encoding width) (states : CommitExecutionStates width)
    (execution : CommitExecutionResult source before after states)
    (assignment : Assignment)
    (writerHolds : Holds states.suffixStates.writerBefore.assertions.toList assignment) :
    CommitPrefixConstraints before source assignment := by
  let terms := commitExecutionTerms before source
  have tailExecution := commit_tail_execution source before after states execution
  have tailConstraints :=
    retirement_tail_constraints before.bootstrap source terms.old terms.best
      (commitGuards before.toColumns source terms.best)
      states.prefixStates.bestAsserted after (commitTailStates states)
      tailExecution assignment writerHolds
  have bestAssertedHolds := tailConstraints.priorHolds
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
  exact ⟨priorHolds, currentFacts.2, bestFacts.2, by
      simpa [terms, commitTailStates, retirementTailTerms, commitExecutionTerms,
        execution.bestAssertedNext] using tailConstraints.refresh,
    by
      simpa [terms, commitTailStates, retirementTailTerms, commitExecutionTerms,
        execution.bestAssertedNext] using tailConstraints.guards,
    by
      simpa [terms, commitTailStates, retirementTailTerms, commitExecutionTerms,
        execution.bestAssertedNext] using tailConstraints.current⟩

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
