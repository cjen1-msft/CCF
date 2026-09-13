-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeCommitExecution
import Sparse.NativeCommitIndexAssignment
import Sparse.NativeLogSummaryAssignment
import Sparse.NativeCommitTermsEncoding
import Sparse.NativeRetirementTailPrefixAssignment

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem commit_prefix_assignment {width : PNat} [Bootstrap (Fin width)]
    (source : Fin width) (before after : Encoding width)
    (states : CommitExecutionStates width)
    (execution : CommitExecutionResult source before after states)
    (assignment : Assignment)
    (holds : Holds before.assertions.toList assignment)
    (valid : ReferencesValid before)
    (frame : NativeArrayVote.Frame (Fin width) Nat) (state : State (Fin width) Nat)
    (columnsRep : FrameColumnsRep assignment before.toColumns frame)
    (modelRep : frame.Rep state)
    (enabled : CCFRaft.Enabled state (.advanceCommitIndex source))
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION) :
    exists extended : Assignment,
      assignment.AgreesBelow before.next extended /\
      Holds states.refreshStates.guardsAsserted.assertions.toList extended /\
      FrameColumnsRep extended before.toColumns frame /\
      (commitExecutionTerms before source).best.eval extended Locals.empty =
        (highestCommittableIndex state source : Int) /\
      exists output : NativeArrayCheckQuorum.Local (Fin width) Nat,
        (commitExecutionTerms before source).values.Rep extended output /\
        output.toModel =
          refreshRetirementState source
            { (state.nodes source) with
              commitIndex := highestCommittableIndex state source } := by
  let terms := commitExecutionTerms before source
  let runs := execution.runs
  let prefixStates := states.prefixStates
  let refresh := states.refreshStates
  let row := NativeArrayCheckQuorum.get frame.nodes source
  have originalOldRep :=
    node_row_snapshot_rep assignment before.toColumns frame.nodes columnsRep.nodes source
  have originalOldBounded := node_row_snapshot_bounded before source valid
  obtain ⟨currentAssignment, currentAgreement, currentBaseHolds, currentAccepted⟩ :=
    current_configuration_index_assignment before assignment holds terms.old.logLength
      terms.old.logEntries terms.old.commit row.log row.commit
      originalOldBounded.logLength originalOldBounded.logEntries
      originalOldBounded.commit originalOldRep.logLength originalOldRep.commit
      originalOldRep.logEntries
  have currentFreshHolds :=
    fresh_holds before prefixStates.currentFresh before.next runs.currentRun
      currentAssignment currentBaseHolds
  have currentAssertedHolds : Holds prefixStates.currentAsserted.assertions.toList
      currentAssignment :=
    assertion_extension_holds _ prefixStates.currentFresh prefixStates.currentAsserted
      runs.currentAssertionRun currentAssignment currentFreshHolds currentAccepted
  have currentOldBounded : terms.old.Bounded prefixStates.currentAsserted.next := by
    exact originalOldBounded.mono (by rw [execution.currentAssertedNext]; omega)
  have currentRep :=
    columnsRep.agrees_below before assignment currentAssignment frame valid currentAgreement
  have currentOldRep :=
    node_row_snapshot_rep currentAssignment before.toColumns frame.nodes
      currentRep.nodes source
  obtain ⟨currentNat, sameCurrent, _⟩ :=
    current_configuration_index_term_sound currentAssignment Locals.empty
      terms.old.logLength terms.old.logEntries terms.old.commit terms.current row.log
      row.commit currentOldRep.logLength currentOldRep.commit currentOldRep.logEntries
      currentAccepted
  have currentIndex :
      NativeArrayCheckQuorum.CurrentIndex row.log row.commit currentNat :=
    (current_configuration_index_term_native_correct currentAssignment Locals.empty
      terms.old.logLength terms.old.logEntries terms.old.commit terms.current row.log
      row.commit currentNat currentOldRep.logLength currentOldRep.commit sameCurrent
      currentOldRep.logEntries).mp currentAccepted
  let best := highestCommittableIndex state source
  have rowModel : state.nodes source = row.toModel := by
    symm
    simpa [row] using
      NativeArrayCheckQuorum.get_rep frame.nodes state modelRep.nodes source
  have bestSummary :
      NativeArrayCommitIndex.CommitIndex row source currentNat best :=
    (NativeArrayCommitIndex.commit_index_correct row state source currentNat best
      rowModel currentIndex).mpr rfl
  have currentBounded :
      terms.current.symbols.all
        (fun symbol => symbol.2 < prefixStates.currentAsserted.next) = true := by
    simp only [terms, commitExecutionTerms, Term.symbols, List.all_cons,
      List.all_nil, Bool.and_true, decide_eq_true_eq]
    rw [execution.currentAssertedNext]
    omega
  obtain ⟨bestAssignment, bestAgreement, bestBaseHolds, bestValue, bestAccepted⟩ :=
    highest_commit_index_assignment prefixStates.currentAsserted currentAssignment
      currentAssertedHolds before.bootstrap source terms.old row currentOldRep
      currentOldBounded terms.current currentNat best currentBounded sameCurrent
      sameBootstrap bestSummary
  rw [execution.currentAssertedNext] at bestValue bestAccepted
  have actualBestAccepted :
      (highestCommitIndexTerm width before.bootstrap terms.old.logLength
        terms.old.logEntries terms.old.matchIndex source terms.old.commit
        terms.old.currentTerm terms.current terms.best).eval
          bestAssignment Locals.empty = true := by
    simpa [terms, commitExecutionTerms] using bestAccepted
  have bestFreshHolds :=
    fresh_holds prefixStates.currentAsserted prefixStates.bestFresh (before.next + 1)
      runs.bestRun bestAssignment bestBaseHolds
  have bestAssertedHolds : Holds prefixStates.bestAsserted.assertions.toList bestAssignment :=
    assertion_extension_holds _ prefixStates.bestFresh prefixStates.bestAsserted
      runs.bestAssertionRun bestAssignment bestFreshHolds actualBestAccepted
  have bestOldBounded : terms.old.Bounded prefixStates.bestAsserted.next := by
    exact originalOldBounded.mono (by rw [execution.bestAssertedNext]; omega)
  have assignmentToBest : assignment.AgreesBelow before.next bestAssignment :=
    currentAgreement.trans
      (bestAgreement.restrict (by rw [execution.currentAssertedNext]; omega))
  have bestRep :=
    columnsRep.agrees_below before assignment bestAssignment frame valid assignmentToBest
  have bestOldRep :=
    node_row_snapshot_rep bestAssignment before.toColumns frame.nodes bestRep.nodes source
  have bestValue' :
      terms.best.eval bestAssignment Locals.empty = (best : Int) := by
    simpa [terms, commitExecutionTerms] using bestValue
  have bestBounded :
      terms.best.symbols.all
        (fun symbol => symbol.2 < prefixStates.bestAsserted.next) = true := by
    simp only [terms, commitExecutionTerms, Term.symbols, List.all_cons,
      List.all_nil, Bool.and_true, decide_eq_true_eq]
    rw [execution.bestAssertedNext]
    omega
  let tailStates := commitTailStates states
  have tailExecution :=
    commit_tail_execution source before after states execution
  obtain ⟨refreshAssignment, refreshAgreement, refreshAssertedHoldsRaw,
      output, outputRepRaw, outputModel⟩ :=
    retirement_tail_prefix_assignment before.bootstrap source terms.old terms.best
      (commitGuards before.toColumns source terms.best)
      prefixStates.bestAsserted after tailStates tailExecution bestAssignment
      bestAssertedHolds row bestOldRep bestOldBounded best bestValue' bestBounded
      sameBootstrap
  have refreshAssertedHolds :
      Holds refresh.refreshAsserted.assertions.toList refreshAssignment := by
    simpa [tailStates, commitTailStates] using refreshAssertedHoldsRaw
  have outputRep : terms.values.Rep refreshAssignment output := by
    have tailStartNext :
        prefixStates.bestAsserted.next = before.next + 2 := by
      simpa [prefixStates] using execution.bestAssertedNext
    simp only [retirementTailTerms] at outputRepRaw
    rw [tailStartNext] at outputRepRaw
    simpa [terms, retirementTailTerms, commitExecutionTerms, Nat.add_assoc] using
      outputRepRaw
  have assignmentToRefresh : assignment.AgreesBelow before.next refreshAssignment :=
    assignmentToBest.trans
      (refreshAgreement.restrict (by rw [execution.bestAssertedNext]; omega))
  have refreshRep :=
    columnsRep.agrees_below before assignment refreshAssignment frame valid
      assignmentToRefresh
  have refreshBest :
      terms.best.eval refreshAssignment Locals.empty = (best : Int) := by
    have same := refreshAgreement .int (before.next + 1) (by
      rw [execution.bestAssertedNext]
      omega)
    simpa [terms, commitExecutionTerms, Term.eval] using same.symm.trans bestValue'
  have outputState :
      output.toModel =
        refreshRetirementState source
          { state.nodes source with commitIndex := best } := by
    rw [outputModel, <- rowModel]
  have nativeEnabled : NativeArrayAdvanceCommit.enabled frame source best output :=
    (NativeArrayAdvanceCommit.enabled_correct frame state modelRep source best output
      rfl outputState).mpr enabled
  have guardHolds :
      Holds (commitGuards before.toColumns source terms.best
        terms.values.membershipState) refreshAssignment :=
    (commit_guards_correct refreshAssignment before.toColumns frame refreshRep source
      terms.best terms.values.membershipState best output refreshBest
      outputRep.membershipState).mpr nativeEnabled
  have guardsAssertedHolds : Holds refresh.guardsAsserted.assertions.toList
      refreshAssignment :=
    (assert_all_holds _ refresh.refreshAsserted refresh.guardsAsserted
      runs.guardsRun refreshAssignment).mpr ⟨refreshAssertedHolds, guardHolds⟩
  exact ⟨refreshAssignment, assignmentToRefresh, guardsAssertedHolds, refreshRep,
    refreshBest, output, outputRep, outputState⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
