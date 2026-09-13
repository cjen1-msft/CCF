-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeCommitExecution
import Sparse.NativeCommitTermsEncoding
import Sparse.NativeLogSummaryAssignment
import Sparse.NativeRetirementCompletedConstraintsEncoding
import Sparse.NativeRetirementWritesEncoding

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
  let runs := execution.runs
  let refresh := states.refreshStates
  let suffix := states.suffixStates
  let old := NativeArrayCheckQuorum.get frame.nodes source
  have oldBounded := node_row_snapshot_bounded before source valid
  have liftBound {sort : Ty} (value : Expr sort)
      (bounded : value.symbols.all (fun symbol => symbol.2 < before.next) = true) :
      value.symbols.all
        (fun symbol => symbol.2 < refresh.guardsAsserted.next) = true := by
    rw [List.all_eq_true] at bounded ⊢
    intro symbol member
    have within : symbol.2 < before.next := by
      simpa only [decide_eq_true_eq] using bounded symbol member
    rw [execution.guardsAssertedNext]
    simpa only [decide_eq_true_eq] using
      lt_trans within (show before.next < before.next + 6 by omega)
  have lengthBounded :
      terms.old.logLength.symbols.all
        (fun symbol => symbol.2 < refresh.guardsAsserted.next) = true :=
    liftBound terms.old.logLength (by
      simpa [terms, commitExecutionTerms] using oldBounded.logLength)
  have entriesBounded :
      terms.old.logEntries.symbols.all
        (fun symbol => symbol.2 < refresh.guardsAsserted.next) = true :=
    liftBound terms.old.logEntries (by
      simpa [terms, commitExecutionTerms] using oldBounded.logEntries)
  have bestBounded :
      terms.best.symbols.all
        (fun symbol => symbol.2 < refresh.guardsAsserted.next) = true := by
    simp [terms, refresh, commitExecutionTerms, Term.symbols,
      execution.guardsAssertedNext]
  have oldRep :=
    node_row_snapshot_rep assignment before.toColumns frame.nodes rep.nodes source
  obtain ⟨currentAssignment, currentAgreement, currentBaseHolds, currentAccepted⟩ :=
    current_configuration_index_assignment refresh.guardsAsserted assignment holds
      terms.old.logLength terms.old.logEntries terms.best old.log bestNat
      lengthBounded entriesBounded bestBounded oldRep.logLength sameBest
      oldRep.logEntries
  have actualCurrentAccepted :
      (currentConfigurationIndexTerm width terms.old.logLength terms.old.logEntries
        terms.best terms.committedCurrent).eval currentAssignment Locals.empty = true := by
    simpa [terms, refresh, commitExecutionTerms, execution.guardsAssertedNext] using
      currentAccepted
  have committedCurrentFreshHolds :
      Holds suffix.committedCurrentFresh.assertions.toList currentAssignment :=
    fresh_holds refresh.guardsAsserted suffix.committedCurrentFresh
      (before.next + 6) runs.committedCurrentRun currentAssignment currentBaseHolds
  have committedCurrentAssertedHolds :
      Holds suffix.committedCurrentAsserted.assertions.toList currentAssignment :=
    assertion_extension_holds _ suffix.committedCurrentFresh
      suffix.committedCurrentAsserted runs.committedCurrentAssertionRun
      currentAssignment committedCurrentFreshHolds actualCurrentAccepted
  have currentRep : FrameColumnsRep currentAssignment before.toColumns frame :=
    rep.agrees_below before assignment currentAssignment frame valid
      (currentAgreement.restrict (by rw [execution.guardsAssertedNext]; omega))
  have currentOldRep :=
    node_row_snapshot_rep currentAssignment before.toColumns frame.nodes
      currentRep.nodes source
  have sameBestCurrent :
      terms.best.eval currentAssignment Locals.empty = (bestNat : Int) := by
    exact
      (terms.best.eval_agrees_below assignment currentAssignment Locals.empty
        refresh.guardsAsserted.next
        (fun symbol member => by
          simpa using List.all_eq_true.mp bestBounded symbol member)
        currentAgreement).symm.trans sameBest
  obtain ⟨writerAssignment, completedAgreement, writerHolds, _⟩ :=
    retirement_completed_constraints_complete_enabled before.bootstrap (.boolean true)
      terms.old.logLength terms.old.logEntries terms.best terms.committedCurrent
      suffix.committedCurrentAsserted suffix.writerBefore (before.next + 7)
      runs.completedRun currentAssignment committedCurrentAssertedHolds old.log bestNat
      currentOldRep.logLength sameBestCurrent sameBootstrap currentOldRep.logEntries
      (by simp [Term.eval]) actualCurrentAccepted
  have guardToWriter :
      assignment.AgreesBelow refresh.guardsAsserted.next writerAssignment :=
    currentAgreement.trans (completedAgreement.restrict (by
      rw [execution.committedCurrentAssertedNext, execution.guardsAssertedNext]
      omega))
  have originalToWriter : assignment.AgreesBelow before.next writerAssignment :=
    guardToWriter.restrict (by rw [execution.guardsAssertedNext]; omega)
  have writerRepBefore : FrameColumnsRep writerAssignment before.toColumns frame :=
    rep.agrees_below before assignment writerAssignment frame valid originalToWriter
  have writerRep :
      FrameColumnsRep writerAssignment suffix.writerBefore.toColumns frame := by
    rw [execution.writerColumns]
    exact writerRepBefore
  have writerValidFull : ReferencesValid states.suffixStates.writerBefore := by
    cases valid
    constructor <;>
      simp_all only [execution.writerColumns, execution.writerNext] <;> omega
  have writerValid : ReferencesValid suffix.writerBefore := by
    simpa [suffix] using writerValidFull
  have writerOldRep :=
    node_row_snapshot_rep writerAssignment before.toColumns frame.nodes
      writerRepBefore.nodes source
  have sameBestWriter :
      terms.best.eval writerAssignment Locals.empty = (bestNat : Int) := by
    exact
      (terms.best.eval_agrees_below assignment writerAssignment Locals.empty
        refresh.guardsAsserted.next
        (fun symbol member => by
          simpa using List.all_eq_true.mp bestBounded symbol member)
        guardToWriter).symm.trans sameBest
  have constraints :=
    commit_prefix_constraints source before after states execution writerAssignment
      writerHolds
  obtain ⟨output, valuesRep, _⟩ :=
    commit_refresh_constraints_output_sound writerAssignment before.bootstrap
      terms.old source terms.best terms.first terms.retirement terms.signature
      terms.retired old bestNat writerOldRep sameBootstrap sameBestWriter
      constraints.refresh
  obtain ⟨_, extended, writeAgreement, finalHolds, _⟩ :=
    retirement_writes_complete source terms.values terms.completed suffix.writerBefore
      after runs.writeRun writerAssignment writerHolds frame output writerRep valuesRep
      writerValid
  have totalAgreement :
      assignment.AgreesBelow refresh.guardsAsserted.next extended :=
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
