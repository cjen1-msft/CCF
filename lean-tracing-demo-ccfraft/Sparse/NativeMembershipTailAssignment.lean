-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeMembershipExecution
import Sparse.NativeLogSummaryAssignment
import Sparse.NativeRetirementCompletedConstraintsEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem membership_tail_assignment {width : PNat} [Bootstrap (Fin width)]
    (source : Fin width) (configuration : Finset (Fin width))
    (before after : Encoding width)
    (initial : MembershipPrefixStates width) (suffix : MembershipSuffixStates width)
    (execution :
      MembershipChangeExecutionResult source configuration before after initial suffix)
    (assignment : Assignment)
    (holds : Holds suffix.guardsAsserted.assertions.toList assignment)
    (valid : ReferencesValid before)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (sameLength :
      (membershipExecutionTerms before source configuration).length.eval
          assignment Locals.empty = (log.length : Int))
    (sameEntries : forall position, position < log.length ->
      modelEntry
          ((membershipExecutionTerms before source configuration).entries.eval
            assignment Locals.empty (position : Int)) =
        log.entries position)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION) :
    exists extended : Assignment,
      assignment.AgreesBelow suffix.guardsAsserted.next extended /\
        Holds suffix.writerBefore.assertions.toList extended /\
        FrameColumnsRep extended before.toColumns frame := by
  let terms := membershipExecutionTerms before source configuration
  let runs := execution.runs.suffixRuns
  let old := NativeArrayCheckQuorum.get frame.nodes source
  have guardsNext : suffix.guardsAsserted.next = before.next + 9 :=
    (fresh_success suffix.guardsAsserted suffix.committedCurrentFresh
      (before.next + 9) runs.committedCurrentRun).1.symm
  have lengthBounded :
      terms.length.symbols.all
        (fun symbol => symbol.2 < suffix.guardsAsserted.next) = true := by
    simp [terms, membershipExecutionTerms, Term.symbols, guardsNext]
  have entriesBounded :
      terms.entries.symbols.all
        (fun symbol => symbol.2 < suffix.guardsAsserted.next) = true := by
    simp [terms, membershipExecutionTerms, Term.symbols, guardsNext]
  have commitBounded :
      terms.old.commit.symbols.all
        (fun symbol => symbol.2 < suffix.guardsAsserted.next) = true := by
    rw [List.all_eq_true]
    intro symbol member
    simp only [terms, membershipExecutionTerms, nodeRowSnapshot, NativeEncode.commit,
      read, allocated, Term.symbols, List.append_nil, List.mem_append, List.mem_cons,
      List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl
    · rw [guardsNext]
      simpa only [decide_eq_true_eq] using
        lt_trans valid.allocated
          (show before.next < before.next + 9 by omega)
    · rw [guardsNext]
      simpa only [decide_eq_true_eq] using
        lt_trans valid.commit
          (show before.next < before.next + 9 by omega)
  have oldRep :=
    node_row_snapshot_rep assignment before.toColumns frame.nodes rep.nodes source
  obtain ⟨currentAssignment, currentAgreement, currentBaseHolds, currentAccepted⟩ :=
    current_configuration_index_assignment suffix.guardsAsserted assignment holds
      terms.length terms.entries terms.old.commit log old.commit lengthBounded
      entriesBounded commitBounded sameLength oldRep.commit sameEntries
  have actualCurrentAccepted :
      (currentConfigurationIndexTerm width terms.length terms.entries terms.old.commit
        terms.committedCurrent).eval currentAssignment Locals.empty = true := by
    simpa [terms, membershipExecutionTerms, guardsNext] using currentAccepted
  have currentFreshHolds :
      Holds suffix.committedCurrentFresh.assertions.toList currentAssignment :=
    fresh_holds suffix.guardsAsserted suffix.committedCurrentFresh
      (before.next + 9) runs.committedCurrentRun currentAssignment currentBaseHolds
  have currentAssertedHolds :
      Holds suffix.committedCurrentAsserted.assertions.toList currentAssignment :=
    assertion_extension_holds _ suffix.committedCurrentFresh
      suffix.committedCurrentAsserted runs.committedCurrentAssertionRun
      currentAssignment currentFreshHolds actualCurrentAccepted
  have sameLengthCurrent :
      terms.length.eval currentAssignment Locals.empty = (log.length : Int) := by
    exact
      (terms.length.eval_agrees_below assignment currentAssignment Locals.empty
        suffix.guardsAsserted.next
        (fun symbol member => by
          simpa using List.all_eq_true.mp lengthBounded symbol member)
        currentAgreement).symm.trans sameLength
  have sameCommitCurrent :
      terms.old.commit.eval currentAssignment Locals.empty = (old.commit : Int) := by
    exact
      (terms.old.commit.eval_agrees_below assignment currentAssignment Locals.empty
        suffix.guardsAsserted.next
        (fun symbol member => by
          simpa using List.all_eq_true.mp commitBounded symbol member)
        currentAgreement).symm.trans oldRep.commit
  have sameEntriesCurrent : forall position, position < log.length ->
      modelEntry (terms.entries.eval currentAssignment Locals.empty (position : Int)) =
        log.entries position := by
    intro position live
    have same :=
      terms.entries.eval_agrees_below assignment currentAssignment Locals.empty
        suffix.guardsAsserted.next
        (fun symbol member => by
          simpa using List.all_eq_true.mp entriesBounded symbol member)
        currentAgreement
    rw [<- same]
    exact sameEntries position live
  obtain ⟨extended, completedAgreement, completedHolds, _⟩ :=
    retirement_completed_constraints_complete_enabled before.bootstrap (.boolean true)
      terms.length terms.entries terms.old.commit terms.committedCurrent
      suffix.committedCurrentAsserted suffix.writerBefore (before.next + 10)
      runs.completedRun currentAssignment currentAssertedHolds log old.commit
      sameLengthCurrent sameCommitCurrent sameBootstrap sameEntriesCurrent
      (by simp [Term.eval]) actualCurrentAccepted
  have totalAgreement :
      assignment.AgreesBelow suffix.guardsAsserted.next extended :=
    currentAgreement.trans (completedAgreement.restrict (by
      have committedFreshNext :=
        (fresh_success suffix.guardsAsserted suffix.committedCurrentFresh
          (before.next + 9) runs.committedCurrentRun).2.1
      have committedAssertedNext :=
        (assertion_success _ suffix.committedCurrentFresh
          suffix.committedCurrentAsserted runs.committedCurrentAssertionRun).1.next
      omega))
  have originalAgreement : assignment.AgreesBelow before.next extended :=
    totalAgreement.restrict (by rw [guardsNext]; omega)
  exact ⟨extended, totalAgreement, completedHolds,
    rep.agrees_below before assignment extended frame valid originalAgreement⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
