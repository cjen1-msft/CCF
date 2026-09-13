-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeMembershipExecution
import Sparse.NativeMembershipTermsEncoding
import Sparse.NativeLogSummaryAssignment

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem membership_log_assignment {width : PNat} [Bootstrap (Fin width)]
    (source : Fin width) (configuration : Finset (Fin width))
    (before after : Encoding width) (initial : MembershipPrefixStates width)
    (suffix : MembershipSuffixStates width)
    (execution :
      MembershipChangeExecutionResult source configuration before after initial suffix)
    (assignment : Assignment)
    (holds : Holds before.assertions.toList assignment)
    (valid : ReferencesValid before)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION) :
    exists extended : Assignment,
      assignment.AgreesBelow before.next extended /\
      Holds initial.lengthDefined.assertions.toList extended /\
      FrameColumnsRep extended before.toColumns frame /\
      let terms := membershipExecutionTerms before source configuration
      let old := NativeArrayCheckQuorum.get frame.nodes source
      let previousSet := (currentConfigurationAt old.log.decode old.log.length).nodes
      let appended :=
        NativeArrayChangeConfiguration.appendRow old configuration previousSet
      terms.previous.eval extended Locals.empty = encodeBits previousSet /\
        terms.added.eval extended Locals.empty =
          encodeBits (configuration \ previousSet) /\
        terms.length.eval extended Locals.empty = (appended.log.length : Int) /\
        forall position, position < appended.log.length ->
          modelEntry
              (terms.entries.eval extended Locals.empty (position : Int)) =
            appended.log.entries position := by
  let terms := membershipExecutionTerms before source configuration
  let runs := execution.runs
  let old := NativeArrayCheckQuorum.get frame.nodes source
  let previousSet := (currentConfigurationAt old.log.decode old.log.length).nodes
  let appended := NativeArrayChangeConfiguration.appendRow old configuration previousSet
  have oldRep :=
    node_row_snapshot_rep assignment before.toColumns frame.nodes rep.nodes source
  have oldLength :
      terms.old.logLength.eval assignment Locals.empty = (old.log.length : Int) := by
    simpa [terms, old, membershipExecutionTerms] using oldRep.logLength
  have oldEntries : forall position, position < old.log.length ->
      modelEntry
          (terms.old.logEntries.eval assignment Locals.empty (position : Int)) =
        old.log.entries position := by
    intro position live
    simpa [terms, old, membershipExecutionTerms] using oldRep.logEntries position live
  have oldLengthBounded :
      terms.old.logLength.symbols.all
        (fun symbol => symbol.2 < before.next) = true := by
    rw [List.all_eq_true]
    intro symbol member
    simp only [terms, membershipExecutionTerms, nodeRowSnapshot, NativeEncode.length,
      read, allocated, Term.symbols, List.append_nil, List.mem_append, List.mem_cons,
      List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl
    · simpa only [decide_eq_true_eq] using valid.allocated
    · simpa only [decide_eq_true_eq] using valid.logLength
  have oldEntriesBounded :
      terms.old.logEntries.symbols.all
        (fun symbol => symbol.2 < before.next) = true := by
    rw [List.all_eq_true]
    intro symbol member
    simp only [terms, membershipExecutionTerms, nodeRowSnapshot, Term.symbols,
      List.append_nil, List.mem_cons, List.not_mem_nil, or_false] at member
    subst symbol
    simpa only [decide_eq_true_eq] using valid.logEntries
  obtain ⟨currentAssignment, currentAgreement, currentBaseHolds, currentAccepted⟩ :=
    current_configuration_index_assignment before assignment holds terms.old.logLength
      terms.old.logEntries terms.old.logLength old.log old.log.length oldLengthBounded
      oldEntriesBounded oldLengthBounded oldLength oldLength oldEntries
  have currentFreshHolds :=
    fresh_holds before initial.currentFresh before.next runs.currentRun
      currentAssignment currentBaseHolds
  have currentAssertedHolds : Holds initial.currentAsserted.assertions.toList
      currentAssignment :=
    assertion_extension_holds _ initial.currentFresh initial.currentAsserted
      runs.currentAssertionRun currentAssignment currentFreshHolds currentAccepted
  have currentRep :=
    rep.agrees_below before assignment currentAssignment frame valid currentAgreement
  have currentOldRep :=
    node_row_snapshot_rep currentAssignment before.toColumns frame.nodes currentRep.nodes source
  have currentLength :
      terms.old.logLength.eval currentAssignment Locals.empty =
        (old.log.length : Int) := by
    simpa [terms, old, membershipExecutionTerms] using currentOldRep.logLength
  have currentEntries : forall position, position < old.log.length ->
      modelEntry
          (terms.old.logEntries.eval currentAssignment Locals.empty (position : Int)) =
        old.log.entries position := by
    intro position live
    simpa [terms, old, membershipExecutionTerms] using
      currentOldRep.logEntries position live
  obtain ⟨_, _, _, currentMembers⟩ :=
    current_configuration_terms_sound currentAssignment Locals.empty before.bootstrap
      terms.old.logLength terms.old.logEntries terms.old.logLength terms.current old.log
      old.log.length sameBootstrap currentLength currentLength currentEntries currentAccepted
  obtain ⟨previousAssignment, previousAgreement, previousHolds⟩ :=
    define_extension
      (currentConfigurationMembersTerm width before.bootstrap terms.old.logEntries
        terms.current)
      initial.currentAsserted initial.previousDefined (before.next + 1)
      runs.previousRun currentAssignment currentAssertedHolds
  obtain ⟨addedAssignment, addedAgreement, addedHolds⟩ :=
    define_extension (membershipAddedTerm configuration terms.previous)
      initial.previousDefined initial.addedDefined (before.next + 2)
      runs.addedRun previousAssignment previousHolds
  obtain ⟨entriesAssignment, entriesAgreement, entriesHolds⟩ :=
    define_extension (membershipLogEntriesTerm before.toColumns source configuration)
      initial.addedDefined initial.entriesDefined (before.next + 3)
      runs.entriesRun addedAssignment addedHolds
  obtain ⟨lengthAssignment, lengthAgreement, lengthHolds⟩ :=
    define_extension (.add terms.old.logLength (.integer 1))
      initial.entriesDefined initial.lengthDefined (before.next + 4)
      runs.lengthRun entriesAssignment entriesHolds
  obtain ⟨_, currentFreshNext, _, _, _⟩ :=
    fresh_success before initial.currentFresh before.next runs.currentRun
  obtain ⟨currentFrame, _⟩ :=
    assertion_success _ initial.currentFresh initial.currentAsserted
      runs.currentAssertionRun
  obtain ⟨_, previousNext, _, _, previousClauses⟩ :=
    define_success
      (currentConfigurationMembersTerm width before.bootstrap terms.old.logEntries
        terms.current)
      initial.currentAsserted initial.previousDefined (before.next + 1)
      runs.previousRun
  obtain ⟨_, addedNext, _, _, addedClauses⟩ :=
    define_success (membershipAddedTerm configuration terms.previous)
      initial.previousDefined initial.addedDefined (before.next + 2)
      runs.addedRun
  obtain ⟨_, entriesNext, _, _, entriesClauses⟩ :=
    define_success (membershipLogEntriesTerm before.toColumns source configuration)
      initial.addedDefined initial.entriesDefined (before.next + 3)
      runs.entriesRun
  obtain ⟨_, _, _, _, lengthClauses⟩ :=
    define_success (.add terms.old.logLength (.integer 1))
      initial.entriesDefined initial.lengthDefined (before.next + 4)
      runs.lengthRun
  have currentAssertedNext :
      initial.currentAsserted.next = before.next + 1 := by
    rw [currentFrame.next, currentFreshNext]
  have currentToFinal :
      currentAssignment.AgreesBelow initial.currentAsserted.next lengthAssignment :=
    previousAgreement.trans
      ((addedAgreement.restrict (by rw [previousNext]; omega)).trans
        ((entriesAgreement.restrict (by rw [addedNext, previousNext]; omega)).trans
          (lengthAgreement.restrict (by
            rw [entriesNext, addedNext, previousNext]
            omega))))
  have originalToFinal : assignment.AgreesBelow before.next lengthAssignment :=
    currentAgreement.trans (currentToFinal.restrict (by rw [currentAssertedNext]; omega))
  have finalRep :=
    rep.agrees_below before assignment lengthAssignment frame valid originalToFinal
  have previousBinding :
      terms.previous.eval lengthAssignment Locals.empty =
        (currentConfigurationMembersTerm width before.bootstrap terms.old.logEntries
          terms.current).eval lengthAssignment Locals.empty := by
    apply definition_clause_binding lengthHolds
    rw [lengthClauses, entriesClauses, addedClauses, previousClauses]
    simp [terms, membershipExecutionTerms]
  have previousKnown :=
    define_known
      (currentConfigurationMembersTerm width before.bootstrap terms.old.logEntries
        terms.current)
      initial.currentAsserted initial.previousDefined (before.next + 1)
      runs.previousRun
  have sameMembers :
      (currentConfigurationMembersTerm width before.bootstrap terms.old.logEntries
        terms.current).eval lengthAssignment Locals.empty =
        encodeBits previousSet := by
    have sameEval :=
      (currentConfigurationMembersTerm width before.bootstrap terms.old.logEntries
        terms.current).eval_agrees_below currentAssignment lengthAssignment Locals.empty
        initial.currentAsserted.next
        (fun symbol member => by
          simpa using List.all_eq_true.mp previousKnown symbol member)
        currentToFinal
    exact sameEval.symm.trans (by simpa [previousSet] using currentMembers)
  have finalPrevious :
      terms.previous.eval lengthAssignment Locals.empty =
        encodeBits previousSet :=
    previousBinding.trans sameMembers
  have finalAdded :
      terms.added.eval lengthAssignment Locals.empty =
        encodeBits (configuration \ previousSet) := by
    have addedBinding :
        terms.added.eval lengthAssignment Locals.empty =
          (membershipAddedTerm configuration terms.previous).eval
            lengthAssignment Locals.empty := by
      apply definition_clause_binding lengthHolds
      rw [lengthClauses, entriesClauses, addedClauses]
      simp [terms, membershipExecutionTerms]
    exact addedBinding.trans
      (membership_added_term_correct lengthAssignment configuration previousSet
        terms.previous finalPrevious)
  have entriesBinding :
      terms.entries.eval lengthAssignment Locals.empty =
        (membershipLogEntriesTerm before.toColumns source configuration).eval
          lengthAssignment Locals.empty := by
    apply definition_clause_binding lengthHolds
    rw [lengthClauses, entriesClauses]
    simp [terms, membershipExecutionTerms]
  have lengthBinding :
      terms.length.eval lengthAssignment Locals.empty =
        (.add terms.old.logLength (.integer 1) : Expr .int).eval
          lengthAssignment Locals.empty := by
    apply definition_clause_binding lengthHolds
    rw [lengthClauses]
    simp [terms, membershipExecutionTerms]
  have finalOldRep :=
    node_row_snapshot_rep lengthAssignment before.toColumns frame.nodes finalRep.nodes source
  have finalLength :
      terms.length.eval lengthAssignment Locals.empty =
        (appended.log.length : Int) := by
    rw [lengthBinding]
    have sameOldLength :
        terms.old.logLength.eval lengthAssignment Locals.empty =
          (old.log.length : Int) := by
      simpa [terms, old, membershipExecutionTerms] using finalOldRep.logLength
    simp [Term.eval, sameOldLength, appended, NativeArrayChangeConfiguration.appendRow,
      NativeArrayLogWrite.append, NativeArrayChangeConfiguration.configurationLog,
      NativeArrayCheckQuorum.Log.ofList]
  have finalEntries : forall position, position < appended.log.length ->
      modelEntry
          (terms.entries.eval lengthAssignment Locals.empty (position : Int)) =
        appended.log.entries position := by
    intro position live
    rw [entriesBinding]
    simpa [appended, old, previousSet] using
      membership_log_entries_term_correct lengthAssignment before.toColumns frame.nodes
        finalRep.nodes source configuration previousSet position live
  exact ⟨lengthAssignment, originalToFinal, lengthHolds, finalRep, finalPrevious,
    finalAdded, finalLength, finalEntries⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
