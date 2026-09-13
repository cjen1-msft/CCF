-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeCommitExecution
import Sparse.NativeRetirementTailSuffixAssignment

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem commit_suffix_assignment {width : PNat} [Bootstrap (Fin width)]
    (source : Fin width) (before after : Encoding width)
    (states : CommitExecutionStates width)
    (execution : CommitExecutionResult source before after states)
    (assignment : Assignment)
    (holds : Holds states.refreshStates.guardsAsserted.assertions.toList assignment)
    (valid : ReferencesValid before)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (bestNat : Nat)
    (sameBest :
      (commitExecutionTerms before source).best.eval assignment Locals.empty =
        (bestNat : Int))
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION) :
    exists extended : Assignment,
      assignment.AgreesBelow states.refreshStates.guardsAsserted.next extended /\
        Holds after.assertions.toList extended := by
  let terms := commitExecutionTerms before source
  let tailBefore := states.prefixStates.bestAsserted
  let tailStates := commitTailStates states
  have tailExecution := commit_tail_execution source before after states execution
  let old := NativeArrayCheckQuorum.get frame.nodes source
  have tailValid : ReferencesValid tailBefore := by
    cases valid
    constructor <;>
      simp_all only [tailBefore, execution.bestAssertedColumns,
        execution.bestAssertedNext] <;> omega
  have tailFrameRep : FrameColumnsRep assignment tailBefore.toColumns frame := by
    change FrameColumnsRep assignment
      states.prefixStates.bestAsserted.toColumns frame
    rw [execution.bestAssertedColumns]
    exact rep
  have oldRep : terms.old.Rep assignment old := by
    simpa [terms, commitExecutionTerms] using
      node_row_snapshot_rep assignment before.toColumns frame.nodes rep.nodes source
  have oldBounded : terms.old.Bounded before.next := by
    simpa [terms, commitExecutionTerms] using
      node_row_snapshot_bounded before source valid
  have tailOldBounded : terms.old.Bounded tailBefore.next :=
    oldBounded.mono (by
      change before.next <= states.prefixStates.bestAsserted.next
      rw [execution.bestAssertedNext]
      omega)
  have bestBounded :
      terms.best.symbols.all
        (fun symbol => symbol.2 < tailBefore.next) = true := by
    simp [terms, tailBefore, commitExecutionTerms, Term.symbols,
      execution.bestAssertedNext]
  obtain ⟨extended, agreement, finalHolds⟩ :=
    retirement_tail_suffix_assignment before.bootstrap source terms.old terms.best
      (commitGuards before.toColumns source terms.best) tailBefore after tailStates
      tailExecution assignment (by simpa [tailStates, commitTailStates] using holds)
      tailValid frame tailFrameRep old oldRep tailOldBounded bestBounded bestNat
      sameBest sameBootstrap
  exact ⟨extended, by
    simpa [tailStates, commitTailStates] using agreement, finalHolds⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
