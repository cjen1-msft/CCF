-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeMembershipExecution
import Sparse.NativeMembershipRowEncoding
import Sparse.NativeRetirementRefreshAssignment

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem membership_retirement_assignment {width : PNat}
    [Bootstrap (Fin width)] (source : Fin width)
    (configuration : Finset (Fin width)) (before after : Encoding width)
    (initial : MembershipPrefixStates width) (suffix : MembershipSuffixStates width)
    (execution :
      MembershipChangeExecutionResult source configuration before after initial suffix)
    (assignment : Assignment)
    (holds : Holds initial.lengthDefined.assertions.toList assignment)
    (valid : ReferencesValid before)
    (frame : NativeArrayVote.Frame (Fin width) Nat) (state : State (Fin width) Nat)
    (columnsRep : FrameColumnsRep assignment before.toColumns frame)
    (modelRep : frame.Rep state)
    (enabled : CCFRaft.Enabled state (.changeConfiguration source configuration))
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION)
    (previousSet : Finset (Fin width))
    (previousCorrect : (latestConfiguration (state.nodes source)).nodes = previousSet)
    (samePrevious :
      (membershipExecutionTerms before source configuration).previous.eval
        assignment Locals.empty = encodeBits previousSet)
    (sameAdded :
      (membershipExecutionTerms before source configuration).added.eval
        assignment Locals.empty = encodeBits (configuration \ previousSet))
    (sameLength :
      (membershipExecutionTerms before source configuration).length.eval
          assignment Locals.empty =
        ((NativeArrayChangeConfiguration.appendRow
          (NativeArrayCheckQuorum.get frame.nodes source)
          configuration previousSet).log.length : Int))
    (sameEntries : forall position,
      position <
        (NativeArrayChangeConfiguration.appendRow
          (NativeArrayCheckQuorum.get frame.nodes source)
          configuration previousSet).log.length ->
      modelEntry
          ((membershipExecutionTerms before source configuration).entries.eval
            assignment Locals.empty (position : Int)) =
        (NativeArrayChangeConfiguration.appendRow
          (NativeArrayCheckQuorum.get frame.nodes source)
          configuration previousSet).log.entries position) :
    let terms := membershipExecutionTerms before source configuration
    let old := NativeArrayCheckQuorum.get frame.nodes source
    let appended :=
      NativeArrayChangeConfiguration.appendRow old configuration previousSet
    exists extended : Assignment,
      exists output : NativeArrayCheckQuorum.Local (Fin width) Nat,
        assignment.AgreesBelow initial.lengthDefined.next extended /\
        Holds suffix.guardsAsserted.assertions.toList extended /\
        FrameColumnsRep extended before.toColumns frame /\
        terms.previous.eval extended Locals.empty = encodeBits previousSet /\
        terms.added.eval extended Locals.empty =
          encodeBits (configuration \ previousSet) /\
        terms.length.eval extended Locals.empty = (appended.log.length : Int) /\
        (forall position, position < appended.log.length ->
          modelEntry (terms.entries.eval extended Locals.empty (position : Int)) =
            appended.log.entries position) /\
        terms.values.Rep extended output /\
        output.toModel = refreshRetirementState source appended.toModel /\
        output.log = appended.log /\
        output.commit = old.commit := by
  let terms := membershipExecutionTerms before source configuration
  let old := NativeArrayCheckQuorum.get frame.nodes source
  let appended :=
    NativeArrayChangeConfiguration.appendRow old configuration previousSet
  let suffixRuns := execution.runs.suffixRuns
  have lengthDefinedNext : initial.lengthDefined.next = before.next + 5 :=
    (fresh_success initial.lengthDefined suffix.firstFresh (before.next + 5)
      suffixRuns.firstRun).1.symm
  have lengthBounded :
      terms.length.symbols.all
        (fun symbol => symbol.2 < initial.lengthDefined.next) = true := by
    simp [terms, membershipExecutionTerms, Term.symbols, lengthDefinedNext]
  have entriesBounded :
      terms.entries.symbols.all
        (fun symbol => symbol.2 < initial.lengthDefined.next) = true := by
    simp [terms, membershipExecutionTerms, Term.symbols, lengthDefinedNext]
  obtain ⟨refreshAssignment, refreshAgreement, refreshBaseHolds, refreshAccepted⟩ :=
    retirement_refresh_assignment initial.lengthDefined assignment holds before.bootstrap
      terms.length terms.entries source appended.log sameBootstrap lengthBounded
      entriesBounded sameLength sameEntries
  have actualRefresh :
      (retirementRefreshConstraints width before.bootstrap terms.length terms.entries source
        terms.first terms.retirement terms.signature terms.retired).eval
          refreshAssignment Locals.empty = true := by
    simpa [terms, membershipExecutionTerms, lengthDefinedNext] using refreshAccepted
  have firstHolds := fresh_holds initial.lengthDefined suffix.firstFresh
    (before.next + 5) suffixRuns.firstRun refreshAssignment refreshBaseHolds
  have retirementHolds := fresh_holds suffix.firstFresh suffix.retirementFresh
    (before.next + 6) suffixRuns.retirementRun refreshAssignment firstHolds
  have signatureHolds := fresh_holds suffix.retirementFresh suffix.signatureFresh
    (before.next + 7) suffixRuns.signatureRun refreshAssignment retirementHolds
  have retiredHolds := fresh_holds suffix.signatureFresh suffix.retiredFresh
    (before.next + 8) suffixRuns.retiredRun refreshAssignment signatureHolds
  have refreshAssertedHolds :=
    assertion_extension_holds _ suffix.retiredFresh suffix.refreshAsserted
      suffixRuns.refreshRun refreshAssignment retiredHolds actualRefresh
  have originalAgreement :
      assignment.AgreesBelow before.next refreshAssignment :=
    refreshAgreement.restrict (by rw [lengthDefinedNext]; omega)
  have extendedColumnsRep :=
    columnsRep.agrees_below before assignment refreshAssignment frame valid originalAgreement
  have previousBounded :
      terms.previous.symbols.all
        (fun symbol => symbol.2 < initial.lengthDefined.next) = true := by
    simp [terms, membershipExecutionTerms, Term.symbols, lengthDefinedNext]
  have addedBounded :
      terms.added.symbols.all
        (fun symbol => symbol.2 < initial.lengthDefined.next) = true := by
    simp [terms, membershipExecutionTerms, Term.symbols, lengthDefinedNext]
  have extendedPrevious :
      terms.previous.eval refreshAssignment Locals.empty = encodeBits previousSet := by
    have sameEval := terms.previous.eval_agrees_below assignment refreshAssignment
      Locals.empty initial.lengthDefined.next
      (fun symbol member => by
        simpa using List.all_eq_true.mp previousBounded symbol member)
      refreshAgreement
    exact sameEval.symm.trans samePrevious
  have extendedAdded :
      terms.added.eval refreshAssignment Locals.empty =
        encodeBits (configuration \ previousSet) := by
    have sameEval := terms.added.eval_agrees_below assignment refreshAssignment
      Locals.empty initial.lengthDefined.next
      (fun symbol member => by
        simpa using List.all_eq_true.mp addedBounded symbol member)
      refreshAgreement
    exact sameEval.symm.trans sameAdded
  have extendedLength :
      terms.length.eval refreshAssignment Locals.empty =
        (appended.log.length : Int) := by
    have sameEval := terms.length.eval_agrees_below assignment refreshAssignment
      Locals.empty initial.lengthDefined.next
      (fun symbol member => by
        simpa using List.all_eq_true.mp lengthBounded symbol member)
      refreshAgreement
    exact sameEval.symm.trans sameLength
  have extendedEntries : forall position, position < appended.log.length ->
      modelEntry (terms.entries.eval refreshAssignment Locals.empty (position : Int)) =
        appended.log.entries position := by
    intro position live
    have sameEval := terms.entries.eval_agrees_below assignment refreshAssignment
      Locals.empty initial.lengthDefined.next
      (fun symbol member => by
        simpa using List.all_eq_true.mp entriesBounded symbol member)
      refreshAgreement
    rw [<- sameEval]
    exact sameEntries position live
  have lengthParts := define_holds _ initial.entriesDefined initial.lengthDefined
    (before.next + 4) execution.runs.lengthRun refreshAssignment refreshBaseHolds
  have entriesParts := define_holds _ initial.addedDefined initial.entriesDefined
    (before.next + 3) execution.runs.entriesRun refreshAssignment lengthParts.1
  obtain ⟨output, outputRep, outputModel, outputLog, outputCommit⟩ :=
    membership_row_terms_correct refreshAssignment before.toColumns frame.nodes
      extendedColumnsRep.nodes source configuration previousSet terms.length terms.entries
      terms.added before.bootstrap terms.first terms.retirement terms.signature terms.retired
      lengthParts.2 entriesParts.2 extendedAdded sameBootstrap actualRefresh
  have guardHolds :
      Holds (membershipGuards before.toColumns source configuration terms.previous
        terms.values.membershipState) refreshAssignment :=
    (membership_guards_output_model_correct refreshAssignment before.toColumns frame state
      extendedColumnsRep modelRep source configuration previousSet terms.previous
      terms.values.membershipState output extendedPrevious outputRep.membershipState
      previousCorrect outputModel).mpr enabled
  have guardsAssertedHolds :
      Holds suffix.guardsAsserted.assertions.toList refreshAssignment :=
    (assert_all_holds _ suffix.refreshAsserted suffix.guardsAsserted suffixRuns.guardsRun
      refreshAssignment).mpr ⟨refreshAssertedHolds, guardHolds⟩
  exact ⟨refreshAssignment, output, refreshAgreement, guardsAssertedHolds,
    extendedColumnsRep, extendedPrevious, extendedAdded, extendedLength, extendedEntries,
    outputRep, outputModel, outputLog, outputCommit⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
