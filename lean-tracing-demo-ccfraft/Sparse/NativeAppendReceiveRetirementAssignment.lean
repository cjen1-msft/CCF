-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendReceiveExecution
import Sparse.NativeLogSummaryAssignment
import Sparse.NativeRetirementRefreshAssignment

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem append_receive_retirement_assignment {width : PNat}
    [Bootstrap (Fin width)] (source destination : Fin width)
    (before after : Encoding width) (states : AppendReceivePrefixStates width)
    (execution : AppendReceiveExecutionResult source destination before after states)
    (assignment : Assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (holds : Holds states.middle.commitDefined.assertions.toList assignment)
    (valid : ReferencesValid before)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (request : AppendEntriesRequest (Fin width) Nat)
    (samePacket :
      (appendReceiveExecutionTerms before source destination).packet.eval
          assignment Locals.empty =
        packetValue (.appendEntriesRequest request))
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (sameLength :
      (appendReceiveExecutionTerms before source destination).logLength.eval
          assignment Locals.empty = (log.length : Int))
    (sameEntries : forall position, position < log.length ->
      modelEntry
          ((appendReceiveExecutionTerms before source destination).logEntries.eval
            assignment Locals.empty (position : Int)) =
        log.entries position)
    (commit : Nat)
    (sameCommit :
      (appendReceiveExecutionTerms before source destination).commit.eval
          assignment Locals.empty = (commit : Int))
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION) :
    exists extended : Assignment,
      assignment.AgreesBelow states.middle.commitDefined.next extended /\
        Holds states.middle.suffix.currentAsserted.assertions.toList extended /\
        FrameColumnsRep extended before.toColumns frame /\
        (appendReceiveExecutionTerms before source destination).packet.eval
            extended Locals.empty =
          packetValue (.appendEntriesRequest request) /\
        (appendReceiveExecutionTerms before source destination).logLength.eval
            extended Locals.empty = (log.length : Int) /\
        (forall position, position < log.length ->
          modelEntry
              ((appendReceiveExecutionTerms before source destination).logEntries.eval
                extended Locals.empty (position : Int)) =
            log.entries position) /\
        (appendReceiveExecutionTerms before source destination).commit.eval
            extended Locals.empty = (commit : Int) /\
        (currentConfigurationIndexTerm width
          (appendReceiveExecutionTerms before source destination).logLength
          (appendReceiveExecutionTerms before source destination).logEntries
          (appendReceiveExecutionTerms before source destination).commit
          (appendReceiveExecutionTerms before source destination).current).eval
            extended Locals.empty = true := by
  let terms := appendReceiveExecutionTerms before source destination
  let middle := states.middle
  let suffix := middle.suffix
  let suffixRuns := execution.runs.middleRuns.suffixRuns
  have commitNext : middle.commitDefined.next = before.next + 7 :=
    (fresh_success middle.commitDefined suffix.firstFresh (before.next + 7)
      suffixRuns.firstRun).1.symm
  have lengthBounded :
      terms.logLength.symbols.all
        (fun symbol => symbol.2 < middle.commitDefined.next) = true := by
    simp [terms, appendReceiveExecutionTerms, Term.symbols, commitNext]
  have entriesBounded :
      terms.logEntries.symbols.all
        (fun symbol => symbol.2 < middle.commitDefined.next) = true := by
    simp [terms, appendReceiveExecutionTerms, Term.symbols, commitNext]
  obtain ⟨refreshAssignment, refreshAgreement, refreshBaseHolds, refreshAccepted⟩ :=
    retirement_refresh_assignment middle.commitDefined assignment holds before.bootstrap
      terms.logLength terms.logEntries destination log sameBootstrap lengthBounded
      entriesBounded sameLength sameEntries
  have actualRefresh :
      (retirementRefreshConstraints width before.bootstrap terms.logLength terms.logEntries
        destination terms.first terms.retirement terms.signature terms.retired).eval
          refreshAssignment Locals.empty = true := by
    simpa [terms, middle, appendReceiveExecutionTerms, commitNext] using refreshAccepted
  have firstHolds := fresh_holds middle.commitDefined suffix.firstFresh
    (before.next + 7) suffixRuns.firstRun refreshAssignment refreshBaseHolds
  have retirementHolds := fresh_holds suffix.firstFresh suffix.retirementFresh
    (before.next + 8) suffixRuns.retirementRun refreshAssignment firstHolds
  have signatureHolds := fresh_holds suffix.retirementFresh suffix.signatureFresh
    (before.next + 9) suffixRuns.signatureRun refreshAssignment retirementHolds
  have retiredHolds := fresh_holds suffix.signatureFresh suffix.retiredFresh
    (before.next + 10) suffixRuns.retiredRun refreshAssignment signatureHolds
  have refreshFormula :
      (implies terms.consumes
        (retirementRefreshConstraints width before.bootstrap terms.logLength terms.logEntries
          destination terms.first terms.retirement terms.signature terms.retired)).eval
            refreshAssignment Locals.empty = true :=
    (implies_eval _ _ refreshAssignment Locals.empty).mpr fun _ => actualRefresh
  have refreshAssertedHolds : Holds suffix.refreshAsserted.assertions.toList
      refreshAssignment :=
    assertion_extension_holds _ suffix.retiredFresh suffix.refreshAsserted
      suffixRuns.refreshRun refreshAssignment retiredHolds refreshFormula
  have currentStart : suffix.refreshAsserted.next = before.next + 11 :=
    (fresh_success suffix.refreshAsserted suffix.currentFresh (before.next + 11)
      suffixRuns.currentRun).1.symm
  have currentLengthBounded :
      terms.logLength.symbols.all
        (fun symbol => symbol.2 < suffix.refreshAsserted.next) = true := by
    simp [terms, appendReceiveExecutionTerms, Term.symbols, currentStart]
  have currentEntriesBounded :
      terms.logEntries.symbols.all
        (fun symbol => symbol.2 < suffix.refreshAsserted.next) = true := by
    simp [terms, appendReceiveExecutionTerms, Term.symbols, currentStart]
  have commitBounded :
      terms.commit.symbols.all
        (fun symbol => symbol.2 < suffix.refreshAsserted.next) = true := by
    simp [terms, appendReceiveExecutionTerms, Term.symbols, currentStart]
  have refreshLength :
      terms.logLength.eval refreshAssignment Locals.empty = (log.length : Int) := by
    have sameEval := terms.logLength.eval_agrees_below assignment refreshAssignment
      Locals.empty middle.commitDefined.next
      (fun symbol member => by
        simpa using List.all_eq_true.mp lengthBounded symbol member)
      refreshAgreement
    exact sameEval.symm.trans sameLength
  have refreshEntries : forall position, position < log.length ->
      modelEntry (terms.logEntries.eval refreshAssignment Locals.empty (position : Int)) =
        log.entries position := by
    intro position live
    have sameEval := terms.logEntries.eval_agrees_below assignment refreshAssignment
      Locals.empty middle.commitDefined.next
      (fun symbol member => by
        simpa using List.all_eq_true.mp entriesBounded symbol member)
      refreshAgreement
    rw [<- sameEval]
    exact sameEntries position live
  have refreshCommit :
      terms.commit.eval refreshAssignment Locals.empty = (commit : Int) := by
    have bounded :
        terms.commit.symbols.all
          (fun symbol => symbol.2 < middle.commitDefined.next) = true := by
      simp [terms, appendReceiveExecutionTerms, Term.symbols, commitNext]
    have sameEval := terms.commit.eval_agrees_below assignment refreshAssignment
      Locals.empty middle.commitDefined.next
      (fun symbol member => by
        simpa using List.all_eq_true.mp bounded symbol member)
      refreshAgreement
    exact sameEval.symm.trans sameCommit
  obtain ⟨currentAssignment, currentAgreement, currentBaseHolds, currentAccepted⟩ :=
    current_configuration_index_assignment suffix.refreshAsserted refreshAssignment
      refreshAssertedHolds terms.logLength terms.logEntries terms.commit log commit
      currentLengthBounded currentEntriesBounded commitBounded refreshLength refreshCommit
      refreshEntries
  have actualCurrent :
      (currentConfigurationIndexTerm width terms.logLength terms.logEntries terms.commit
        terms.current).eval currentAssignment Locals.empty = true := by
    simpa [terms, suffix, appendReceiveExecutionTerms, currentStart] using currentAccepted
  have currentFreshHolds := fresh_holds suffix.refreshAsserted suffix.currentFresh
    (before.next + 11) suffixRuns.currentRun currentAssignment currentBaseHolds
  have currentFormula :
      (implies terms.consumes
        (currentConfigurationIndexTerm width terms.logLength terms.logEntries terms.commit
          terms.current)).eval currentAssignment Locals.empty = true :=
    (implies_eval _ _ currentAssignment Locals.empty).mpr fun _ => actualCurrent
  have currentAssertedHolds : Holds suffix.currentAsserted.assertions.toList
      currentAssignment :=
    assertion_extension_holds _ suffix.currentFresh suffix.currentAsserted
      suffixRuns.currentAssertionRun currentAssignment currentFreshHolds currentFormula
  have totalAgreement : assignment.AgreesBelow middle.commitDefined.next currentAssignment :=
    refreshAgreement.trans (currentAgreement.restrict (by omega))
  have originalAgreement : assignment.AgreesBelow before.next currentAssignment :=
    totalAgreement.restrict (by omega)
  have finalRep :=
    rep.agrees_below before assignment currentAssignment frame valid originalAgreement
  have finalPacket :
      terms.packet.eval currentAssignment Locals.empty =
        packetValue (.appendEntriesRequest request) := by
    have same := totalAgreement (packetTy width) before.next (by omega)
    simpa [terms, appendReceiveExecutionTerms, Term.eval] using same.symm.trans samePacket
  have finalLength :
      terms.logLength.eval currentAssignment Locals.empty = (log.length : Int) := by
    have sameEval := terms.logLength.eval_agrees_below assignment currentAssignment
      Locals.empty middle.commitDefined.next
      (fun symbol member => by
        simpa using List.all_eq_true.mp lengthBounded symbol member)
      totalAgreement
    exact sameEval.symm.trans sameLength
  have finalEntries : forall position, position < log.length ->
      modelEntry (terms.logEntries.eval currentAssignment Locals.empty (position : Int)) =
        log.entries position := by
    intro position live
    have sameEval := terms.logEntries.eval_agrees_below assignment currentAssignment
      Locals.empty middle.commitDefined.next
      (fun symbol member => by
        simpa using List.all_eq_true.mp entriesBounded symbol member)
      totalAgreement
    rw [<- sameEval]
    exact sameEntries position live
  have finalCommit :
      terms.commit.eval currentAssignment Locals.empty = (commit : Int) := by
    have bounded :
        terms.commit.symbols.all
          (fun symbol => symbol.2 < middle.commitDefined.next) = true := by
      simp [terms, appendReceiveExecutionTerms, Term.symbols, commitNext]
    have sameEval := terms.commit.eval_agrees_below assignment currentAssignment
      Locals.empty middle.commitDefined.next
      (fun symbol member => by
        simpa using List.all_eq_true.mp bounded symbol member)
      totalAgreement
    exact sameEval.symm.trans sameCommit
  exact ⟨currentAssignment, totalAgreement, currentAssertedHolds, finalRep, finalPacket,
    finalLength, finalEntries, finalCommit, actualCurrent⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
