-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeMembershipExecution

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

structure MembershipPrefixConstraints {width : PNat} (source : Fin width)
    (configuration : Finset (Fin width)) (before : Encoding width)
    (terms : MembershipExecutionTerms width) (assignment : Assignment) : Prop where
  beforeHolds : Holds before.assertions.toList assignment
  current :
    (currentConfigurationIndexTerm width terms.old.logLength terms.old.logEntries
      terms.old.logLength terms.current).eval assignment Locals.empty = true
  previous :
    assignment (.bits width) (before.next + 1) =
      (currentConfigurationMembersTerm width before.bootstrap terms.old.logEntries
        terms.current).eval assignment Locals.empty
  added :
    assignment (.bits width) (before.next + 2) =
      (membershipAddedTerm configuration terms.previous).eval assignment Locals.empty
  entries :
    assignment (.array .int (entryTy width)) (before.next + 3) =
      (membershipLogEntriesTerm before.toColumns source configuration).eval
        assignment Locals.empty
  length :
    assignment .int (before.next + 4) =
      (Term.add terms.old.logLength (.integer 1)).eval assignment Locals.empty
  refresh :
    (retirementRefreshConstraints width before.bootstrap terms.length terms.entries source
      terms.first terms.retirement terms.signature terms.retired).eval
        assignment Locals.empty = true
  guards :
    Holds (membershipGuards before.toColumns source configuration terms.previous
      terms.values.membershipState) assignment
  committedCurrent :
    (currentConfigurationIndexTerm width terms.length terms.entries terms.old.commit
      terms.committedCurrent).eval assignment Locals.empty = true
  completed :
    Holds (retirementCompletedClauses before.bootstrap (.boolean true) terms.entries
      (logRangeMinTerm terms.old.commit terms.length) terms.committedCurrent
      (currentConfigurationMembersTerm width before.bootstrap terms.entries
        terms.committedCurrent)
      (before.next + 10) (before.next + 10)) assignment

theorem membership_prefix_constraints {width : PNat} (source : Fin width)
    (configuration : Finset (Fin width)) (before after : Encoding width)
    (initial : MembershipPrefixStates width) (suffix : MembershipSuffixStates width)
    (result :
      MembershipChangeExecutionResult source configuration before after initial suffix)
    (assignment : Assignment)
    (holds : Holds suffix.writerBefore.assertions.toList assignment) :
    MembershipPrefixConstraints source configuration before
      (membershipExecutionTerms before source configuration) assignment := by
  let terms := membershipExecutionTerms before source configuration
  let suffixRuns := result.runs.suffixRuns
  have completedParts :=
    (retirement_completed_constraints_holds before.bootstrap (.boolean true) terms.length
      terms.entries terms.old.commit terms.committedCurrent suffix.committedCurrentAsserted
      suffix.writerBefore (before.next + 10) suffixRuns.completedRun assignment).mp holds
  have completedNext :=
    (retirement_completed_constraints_success before.bootstrap (.boolean true) terms.length
      terms.entries terms.old.commit terms.committedCurrent suffix.committedCurrentAsserted
      suffix.writerBefore (before.next + 10) suffixRuns.completedRun).next
  have writerNext := result.writerNext
  have completedBase : suffix.committedCurrentAsserted.next = before.next + 10 := by
    omega
  have committedParts := assertion_holds _ suffix.committedCurrentFresh
    suffix.committedCurrentAsserted suffixRuns.committedCurrentAssertionRun assignment
    completedParts.1
  have guardsHolds := fresh_prior_holds suffix.guardsAsserted suffix.committedCurrentFresh
    (before.next + 9) suffixRuns.committedCurrentRun assignment committedParts.1
  have guardParts :=
    (assert_all_holds _ suffix.refreshAsserted suffix.guardsAsserted suffixRuns.guardsRun
      assignment).mp guardsHolds
  have refreshParts := assertion_holds _ suffix.retiredFresh suffix.refreshAsserted
    suffixRuns.refreshRun assignment guardParts.1
  have signatureHolds := fresh_prior_holds suffix.signatureFresh suffix.retiredFresh
    (before.next + 8) suffixRuns.retiredRun assignment refreshParts.1
  have retirementHolds := fresh_prior_holds suffix.retirementFresh suffix.signatureFresh
    (before.next + 7) suffixRuns.signatureRun assignment signatureHolds
  have firstHolds := fresh_prior_holds suffix.firstFresh suffix.retirementFresh
    (before.next + 6) suffixRuns.retirementRun assignment retirementHolds
  have lengthHolds := fresh_prior_holds initial.lengthDefined suffix.firstFresh
    (before.next + 5) suffixRuns.firstRun assignment firstHolds
  have lengthParts := define_holds _ initial.entriesDefined initial.lengthDefined
    (before.next + 4) result.runs.lengthRun assignment lengthHolds
  have entriesParts := define_holds _ initial.addedDefined initial.entriesDefined
    (before.next + 3) result.runs.entriesRun assignment lengthParts.1
  have addedParts := define_holds _ initial.previousDefined initial.addedDefined
    (before.next + 2) result.runs.addedRun assignment entriesParts.1
  have previousParts := define_holds _ initial.currentAsserted initial.previousDefined
    (before.next + 1) result.runs.previousRun assignment addedParts.1
  have currentParts := assertion_holds _ initial.currentFresh initial.currentAsserted
    result.runs.currentAssertionRun assignment previousParts.1
  have beforeHolds := fresh_prior_holds before initial.currentFresh before.next
    result.runs.currentRun assignment currentParts.1
  exact
    { beforeHolds
      current := currentParts.2
      previous := previousParts.2
      added := addedParts.2
      entries := entriesParts.2
      length := lengthParts.2
      refresh := refreshParts.2
      guards := guardParts.2
      committedCurrent := committedParts.2
      completed := by simpa [terms, completedBase] using completedParts.2 }

theorem membership_change_constraints {width : PNat} (source : Fin width)
    (configuration : Finset (Fin width)) (before after : Encoding width)
    (run : (membershipChange source configuration).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment) :
    exists initial suffix,
      MembershipChangeExecutionResult source configuration before after initial suffix /\
      Holds suffix.writerBefore.assertions.toList assignment /\
      MembershipPrefixConstraints source configuration before
        (membershipExecutionTerms before source configuration) assignment := by
  obtain ⟨initial, suffix, result⟩ :=
    membership_change_success source configuration before after run
  have writerHolds := membership_writes_prior_holds source
    (membershipExecutionTerms before source configuration).added
    (membershipExecutionTerms before source configuration).values
    (membershipExecutionTerms before source configuration).completed suffix.writerBefore after
    result.runs.suffixRuns.writeRun assignment holds
  exact ⟨initial, suffix, result, writerHolds,
    membership_prefix_constraints source configuration before after initial suffix result
      assignment writerHolds⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
