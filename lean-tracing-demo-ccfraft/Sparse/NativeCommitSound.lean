-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeCommitExecution
import Sparse.NativeCommitIndexEncoding
import Sparse.NativeCommitTermsEncoding
import Sparse.NativeRetirementTailSound

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem advance_commit_model_sound {width : PNat} [Bootstrap (Fin width)]
    (source : Fin width) (before after : Encoding width)
    (run : (advanceCommitIndex source).run before = .ok ((), after))
    (assignment : Assignment)
    (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (state : State (Fin width) Nat)
    (columnsRep : FrameColumnsRep assignment before.toColumns frame)
    (modelRep : frame.Rep state)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION) :
    CCFRaft.Enabled state (.advanceCommitIndex source) /\
      exists written : NativeArrayVote.Frame (Fin width) Nat,
        FrameColumnsRep assignment after.toColumns written /\
        written.Rep (CCFRaft.next state (.advanceCommitIndex source)) := by
  obtain ⟨states, execution⟩ := advance_commit_success source before after run
  let terms := commitExecutionTerms before source
  let old := NativeArrayCheckQuorum.get frame.nodes source
  have bestAssertedHolds :=
    retirement_tail_prior_holds before.bootstrap source terms.old terms.best
      (commitGuards before.toColumns source terms.best)
      states.prefixStates.bestAsserted after execution.runs.tailRun assignment holds
  have bestFacts :=
    assertion_holds _ states.prefixStates.bestFresh states.prefixStates.bestAsserted
      execution.runs.bestAssertionRun assignment bestAssertedHolds
  have currentAssertedHolds :=
    fresh_prior_holds states.prefixStates.currentAsserted states.prefixStates.bestFresh
      (before.next + 1) execution.runs.bestRun assignment bestFacts.1
  have currentFacts :=
    assertion_holds _ states.prefixStates.currentFresh
      states.prefixStates.currentAsserted execution.runs.currentAssertionRun
      assignment currentAssertedHolds
  have oldRep :=
    node_row_snapshot_rep assignment before.toColumns frame.nodes columnsRep.nodes source
  have sameRow : state.nodes source = old.toModel :=
    (NativeArrayCheckQuorum.get_rep frame.nodes state modelRep.nodes source).symm
  obtain ⟨currentNat, sameCurrent, currentModel⟩ :=
    current_configuration_index_term_sound assignment Locals.empty
      terms.old.logLength terms.old.logEntries terms.old.commit terms.current
      old.log old.commit
      (by simpa [terms, old] using oldRep.logLength)
      (by simpa [terms, old] using oldRep.commit)
      (by
        intro position live
        simpa [terms, old] using oldRep.logEntries position live)
      (by simpa [terms] using currentFacts.2)
  have currentIndex :
      NativeArrayCheckQuorum.CurrentIndex old.log old.commit currentNat :=
    (NativeArrayCheckQuorum.current_index_correct old.log old.commit currentNat).mpr
      currentModel
  obtain ⟨bestNat, sameBest, bestModel⟩ :=
    highest_commit_index_term_model_sound assignment Locals.empty before.bootstrap
      terms.old.logLength terms.old.logEntries terms.old.matchIndex source
      terms.old.commit terms.old.currentTerm terms.current terms.best old state
      currentNat sameBootstrap
      (by simpa [terms, old] using oldRep.logLength)
      (by
        intro position live
        simpa [terms, old] using oldRep.logEntries position live)
      (by
        intro peer
        simpa [terms, old] using oldRep.matchIndex peer)
      (by simpa [terms, old] using oldRep.commit)
      (by simpa [terms, old] using oldRep.currentTerm)
      sameCurrent sameRow currentIndex
      (by simpa [terms] using bestFacts.2)
  have tailColumnsRep :
      FrameColumnsRep assignment states.prefixStates.bestAsserted.toColumns frame := by
    rw [execution.bestAssertedColumns]
    exact columnsRep
  obtain ⟨output, outputRep, outputModelOld, guardHolds, writtenColumns⟩ :=
    retirement_tail_sound before.bootstrap source terms.old terms.best
      (commitGuards before.toColumns source terms.best)
      states.prefixStates.bestAsserted after execution.runs.tailRun assignment holds
      frame tailColumnsRep old
      (by simpa [terms, old] using oldRep)
      bestNat sameBest sameBootstrap
  have outputModel :
      output.toModel =
        refreshRetirementState source
          { (state.nodes source) with commitIndex := bestNat } := by
    rw [sameRow]
    exact outputModelOld
  let tailTerms :=
    retirementTailTerms states.prefixStates.bestAsserted terms.old terms.best
  have nativeEnabled : NativeArrayAdvanceCommit.enabled frame source bestNat output :=
    (commit_guards_correct assignment before.toColumns frame columnsRep source
      terms.best tailTerms.values.membershipState bestNat output sameBest
      (by simpa [tailTerms] using outputRep.membershipState)).mp
      (by simpa [tailTerms] using guardHolds)
  have enabled : CCFRaft.Enabled state (.advanceCommitIndex source) :=
    (NativeArrayAdvanceCommit.enabled_correct frame state modelRep source bestNat
      output bestModel outputModel).mp nativeEnabled
  let completed := retirementCompletedNodes output.log.decode output.commit
  have outputModelHighest :
      output.toModel =
        refreshRetirementState source
          { (state.nodes source) with
            commitIndex := highestCommittableIndex state source } := by
    rw [bestModel]
    exact outputModel
  have writtenModel :
      (NativeArrayAdvanceCommit.advanceCommit frame source output completed).Rep
        (CCFRaft.next state (.advanceCommitIndex source)) :=
    NativeArrayAdvanceCommit.advance_commit_output_rep frame state modelRep source
      output completed outputModelHighest rfl nativeEnabled.2.2.2
  refine ⟨enabled, NativeArrayAdvanceCommit.advanceCommit frame source output completed, ?_, writtenModel⟩
  simpa [retirementWriteFrame, NativeArrayAdvanceCommit.advanceCommit,
    completed] using writtenColumns

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
