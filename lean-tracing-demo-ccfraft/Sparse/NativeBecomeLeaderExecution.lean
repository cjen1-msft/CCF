-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeBecomeLeader
import Sparse.NativeRetirementTailExecution

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

structure BecomeLeaderExecutionTerms (width : PNat) where
  old : NodeRowTerms width
  latest : Expr .int
  current : Expr .int
  latestConstraint : Expr .bool
  currentConstraint : Expr .bool
  prepared : NodeRowTerms width
  guards : Expr .int -> List (Expr .bool)

def becomeLeaderExecutionTerms {width : PNat} (before : Encoding width)
    (source : Fin width) : BecomeLeaderExecutionTerms width :=
  let old := nodeRowSnapshot before.toColumns source
  let latest : Expr .int := .free .int before.next
  let current : Expr .int := .free .int (before.next + 1)
  { old, latest, current
    latestConstraint :=
      boundedSignatureTerm width old.logLength old.logEntries old.logLength latest
    currentConstraint :=
      currentConfigurationIndexTerm width old.logLength old.logEntries old.commit
        current
    prepared := becomeLeaderRowTerms old latest
    guards :=
      becomeLeaderGuards before.bootstrap before.toColumns source current }

structure BecomeLeaderPrefixStates (width : PNat) where
  latestFresh : Encoding width
  latestAsserted : Encoding width
  currentFresh : Encoding width
  currentAsserted : Encoding width

structure BecomeLeaderExecutionStates (width : PNat) where
  prefixStates : BecomeLeaderPrefixStates width
  tailStates : RetirementTailStates width

structure BecomeLeaderExecutionRuns {width : PNat} (source : Fin width)
    (before after : Encoding width) (states : BecomeLeaderExecutionStates width) :
    Prop where
  latestRun :
    fresh.run before = .ok (before.next, states.prefixStates.latestFresh)
  latestAssertionRun :
    let terms := becomeLeaderExecutionTerms before source
    (assertion terms.latestConstraint).run states.prefixStates.latestFresh =
      .ok ((), states.prefixStates.latestAsserted)
  currentRun :
    fresh.run states.prefixStates.latestAsserted =
      .ok (before.next + 1, states.prefixStates.currentFresh)
  currentAssertionRun :
    let terms := becomeLeaderExecutionTerms before source
    (assertion terms.currentConstraint).run states.prefixStates.currentFresh =
      .ok ((), states.prefixStates.currentAsserted)
  tailRun :
    let terms := becomeLeaderExecutionTerms before source
    (retirementTail before.bootstrap source terms.prepared terms.old.commit
      terms.guards).run states.prefixStates.currentAsserted = .ok ((), after)

structure BecomeLeaderExecutionResult {width : PNat} (source : Fin width)
    (before after : Encoding width) (states : BecomeLeaderExecutionStates width) :
    Prop where
  runs : BecomeLeaderExecutionRuns source before after states
  latestAssertedNext : states.prefixStates.latestAsserted.next = before.next + 1
  latestAssertedBootstrap :
    states.prefixStates.latestAsserted.bootstrap = before.bootstrap
  latestAssertedColumns :
    states.prefixStates.latestAsserted.toColumns = before.toColumns
  currentAssertedNext :
    states.prefixStates.currentAsserted.next = before.next + 2
  currentAssertedBootstrap :
    states.prefixStates.currentAsserted.bootstrap = before.bootstrap
  currentAssertedColumns :
    states.prefixStates.currentAsserted.toColumns = before.toColumns
  tailExecution :
    let terms := becomeLeaderExecutionTerms before source
    RetirementTailExecutionResult before.bootstrap source terms.prepared
      terms.old.commit terms.guards states.prefixStates.currentAsserted after
        states.tailStates
  finalNext : after.next = before.next + 25 + 3 * width

theorem become_leader_success {width : PNat} (source : Fin width)
    (before after : Encoding width)
    (run : (becomeLeader source).run before = .ok ((), after)) :
    exists states : BecomeLeaderExecutionStates width,
      BecomeLeaderExecutionResult source before after states := by
  rw [becomeLeader, get_bind_run] at run
  obtain ⟨latest, latestFresh, latestRun, run⟩ :=
    (bind_run _ _ _ _ _).mp run
  obtain ⟨⟨⟩, latestAsserted, latestAssertionRun, run⟩ :=
    (bind_run _ _ _ _ _).mp run
  obtain ⟨current, currentFresh, currentRun, run⟩ :=
    (bind_run _ _ _ _ _).mp run
  obtain ⟨⟨⟩, currentAsserted, currentAssertionRun, tailRun⟩ :=
    (bind_run _ _ _ _ _).mp run
  obtain ⟨latestEq, latestNext, latestBootstrap, latestColumns, _⟩ :=
    fresh_success before latestFresh latest latestRun
  subst latest
  have latestAssertionShape :=
    assertion_success _ latestFresh latestAsserted latestAssertionRun
  obtain ⟨currentEq, currentNext, currentBootstrap, currentColumns, _⟩ :=
    fresh_success latestAsserted currentFresh current currentRun
  have latestAssertedNext : latestAsserted.next = before.next + 1 := by
    rw [latestAssertionShape.1.next, latestNext]
  have currentId : current = before.next + 1 :=
    currentEq.trans latestAssertedNext
  subst current
  simp_rw [latestAssertedNext] at currentAssertionRun tailRun
  have currentAssertionShape :=
    assertion_success _ currentFresh currentAsserted currentAssertionRun
  have currentFreshNext : currentFresh.next = before.next + 2 := by
    rw [currentNext, latestAssertedNext]
  have currentAssertedNext : currentAsserted.next = before.next + 2 :=
    currentAssertionShape.1.next.trans currentFreshNext
  have latestAssertedBootstrap :
      latestAsserted.bootstrap = before.bootstrap :=
    latestAssertionShape.1.bootstrap.trans latestBootstrap
  have latestAssertedColumns :
      latestAsserted.toColumns = before.toColumns :=
    latestAssertionShape.1.columns.trans latestColumns
  have currentAssertedBootstrap :
      currentAsserted.bootstrap = before.bootstrap :=
    currentAssertionShape.1.bootstrap.trans
      (currentBootstrap.trans latestAssertedBootstrap)
  have currentAssertedColumns :
      currentAsserted.toColumns = before.toColumns :=
    currentAssertionShape.1.columns.trans
      (currentColumns.trans latestAssertedColumns)
  simp_rw [latestAssertedNext] at currentRun
  let terms := becomeLeaderExecutionTerms before source
  have normalizedTailRun :
      (retirementTail before.bootstrap source terms.prepared terms.old.commit
        terms.guards).run currentAsserted = .ok ((), after) := by
    simpa only [terms, becomeLeaderExecutionTerms] using tailRun
  obtain ⟨tailStates, tailExecution⟩ :=
    retirement_tail_success before.bootstrap source terms.prepared
      terms.old.commit terms.guards currentAsserted after
      normalizedTailRun
  let prefixStates : BecomeLeaderPrefixStates width :=
    { latestFresh, latestAsserted, currentFresh, currentAsserted }
  let states : BecomeLeaderExecutionStates width := { prefixStates, tailStates }
  have runs : BecomeLeaderExecutionRuns source before after states := by
    refine ⟨?_, ?_, ?_, ?_, ?_⟩
    · simpa only [states, prefixStates] using latestRun
    · simpa [states, prefixStates, becomeLeaderExecutionTerms] using
        latestAssertionRun
    · simpa only [states, prefixStates] using currentRun
    · simpa [states, prefixStates, becomeLeaderExecutionTerms] using
        currentAssertionRun
    · simpa only [states, prefixStates] using normalizedTailRun
  have finalNext : after.next = before.next + 25 + 3 * width := by
    rw [tailExecution.finalNext, currentAssertedNext]
  exact ⟨states, runs, latestAssertedNext, latestAssertedBootstrap,
    latestAssertedColumns, currentAssertedNext, currentAssertedBootstrap,
    currentAssertedColumns, tailExecution, finalNext⟩

theorem become_leader_bootstrap {width : PNat} (source : Fin width)
    (before after : Encoding width)
    (run : (becomeLeader source).run before = .ok ((), after)) :
    after.bootstrap = before.bootstrap := by
  obtain ⟨states, execution⟩ :=
    become_leader_success source before after run
  let terms := becomeLeaderExecutionTerms before source
  exact
    (retirement_tail_bootstrap before.bootstrap source terms.prepared
      terms.old.commit terms.guards states.prefixStates.currentAsserted after
      execution.runs.tailRun).trans execution.currentAssertedBootstrap

theorem become_leader_prior_holds {width : PNat} (source : Fin width)
    (before after : Encoding width)
    (run : (becomeLeader source).run before = .ok ((), after))
    (assignment : Assignment)
    (holds : Holds after.assertions.toList assignment) :
    Holds before.assertions.toList assignment := by
  obtain ⟨states, execution⟩ :=
    become_leader_success source before after run
  let terms := becomeLeaderExecutionTerms before source
  have currentAssertedHolds :=
    retirement_tail_prior_holds before.bootstrap source terms.prepared
      terms.old.commit terms.guards states.prefixStates.currentAsserted after
      execution.runs.tailRun assignment holds
  have currentFacts :=
    assertion_holds terms.currentConstraint states.prefixStates.currentFresh
      states.prefixStates.currentAsserted execution.runs.currentAssertionRun
      assignment currentAssertedHolds
  have latestAssertedHolds :=
    fresh_prior_holds states.prefixStates.latestAsserted
      states.prefixStates.currentFresh
      (before.next + 1) execution.runs.currentRun assignment currentFacts.1
  have latestFacts :=
    assertion_holds terms.latestConstraint states.prefixStates.latestFresh
      states.prefixStates.latestAsserted execution.runs.latestAssertionRun
      assignment latestAssertedHolds
  exact
    fresh_prior_holds before states.prefixStates.latestFresh before.next
      execution.runs.latestRun assignment latestFacts.1

theorem become_leader_references {width : PNat} (source : Fin width)
    (before after : Encoding width)
    (run : (becomeLeader source).run before = .ok ((), after))
    (valid : ReferencesValid before) :
    ReferencesValid after := by
  obtain ⟨states, execution⟩ :=
    become_leader_success source before after run
  have currentAssertedValid :
      ReferencesValid states.prefixStates.currentAsserted := by
    cases valid
    constructor <;>
      simp only [execution.currentAssertedColumns,
        execution.currentAssertedNext] <;>
      omega
  let terms := becomeLeaderExecutionTerms before source
  exact
    retirement_tail_references before.bootstrap source terms.prepared
      terms.old.commit terms.guards states.prefixStates.currentAsserted after
      execution.runs.tailRun currentAssertedValid

theorem become_leader_next {width : PNat} (source : Fin width)
    (before after : Encoding width)
    (run : (becomeLeader source).run before = .ok ((), after)) :
    after.next = before.next + 25 + 3 * width := by
  obtain ⟨_, execution⟩ :=
    become_leader_success source before after run
  exact execution.finalNext

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
