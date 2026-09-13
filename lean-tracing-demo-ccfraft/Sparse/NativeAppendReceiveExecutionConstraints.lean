-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendReceiveExecution

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

private theorem assertion_holds {width : PNat} (formula : Expr .bool)
    (before after : Encoding width)
    (run : (assertion formula).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment) :
    Holds before.assertions.toList assignment /\
      formula.eval assignment Locals.empty = true := by
  rw [(assertion_success formula before after run).2] at holds
  constructor
  · exact fun item member => holds item (by simp [member])
  · exact holds formula (by simp)

private theorem fresh_prior_holds {width : PNat} (before after : Encoding width) (id : Nat)
    (run : fresh.run before = .ok (id, after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment) :
    Holds before.assertions.toList assignment := by
  rw [(fresh_success before after id run).2.2.2.2] at holds
  exact holds

private theorem define_holds {width : PNat} {sort : Ty} (value : Expr sort)
    (before after : Encoding width) (id : Nat)
    (run : (define value).run before = .ok (id, after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment) :
    Holds before.assertions.toList assignment /\
      assignment sort id = value.eval assignment Locals.empty := by
  rw [(define_success value before after id run).2.2.2.2] at holds
  constructor
  · exact fun item member => holds item (by simp [member])
  · simpa [Term.eval] using
      holds (.equal (.free sort id) value) (by simp)

theorem append_receive_prefix_constraints {width : PNat} (source destination : Fin width)
    (before after : Encoding width)
    (states : AppendReceivePrefixStates width)
    (result : AppendReceiveExecutionResult source destination before after states)
    (assignment : Assignment)
    (writerHolds : Holds states.middle.suffix.writerBefore.assertions.toList assignment) :
    AppendReceivePrefixConstraints before source destination
      (appendReceiveExecutionTerms before source destination) assignment := by
  let terms := appendReceiveExecutionTerms before source destination
  let middle := states.middle
  let suffix := middle.suffix
  let runs := result.runs
  let middleRuns := runs.middleRuns
  let suffixRuns := middleRuns.suffixRuns
  obtain ⟨bestHolds, nackHolds⟩ := assertion_holds _ suffix.bestFresh
    suffix.writerBefore suffixRuns.nackRun assignment writerHolds
  have completedHolds := fresh_prior_holds suffix.completedState suffix.bestFresh
    (before.next + 13 + 3 * width) suffixRuns.bestRun assignment bestHolds
  have completedParts :=
    (retirement_completed_constraints_holds before.bootstrap terms.consumes terms.logLength
      terms.logEntries terms.commit terms.current states.middle.suffix.currentAsserted
      suffix.completedState (before.next + 12) suffixRuns.completedRun assignment).mp
      completedHolds
  have completedShape :=
    retirement_completed_constraints_success before.bootstrap terms.consumes terms.logLength
      terms.logEntries terms.commit terms.current suffix.currentAsserted suffix.completedState
      (before.next + 12) suffixRuns.completedRun
  have currentAssertedHolds := completedParts.1
  obtain ⟨currentFreshHolds, currentHolds⟩ := assertion_holds _ suffix.currentFresh
    suffix.currentAsserted suffixRuns.currentAssertionRun assignment currentAssertedHolds
  have refreshAssertedHolds := fresh_prior_holds suffix.refreshAsserted suffix.currentFresh
    (before.next + 11) suffixRuns.currentRun assignment currentFreshHolds
  obtain ⟨retiredFreshHolds, refreshHolds⟩ := assertion_holds _ suffix.retiredFresh
    suffix.refreshAsserted suffixRuns.refreshRun assignment refreshAssertedHolds
  have signatureFreshHolds := fresh_prior_holds suffix.signatureFresh suffix.retiredFresh
    (before.next + 10) suffixRuns.retiredRun assignment retiredFreshHolds
  have retirementFreshHolds := fresh_prior_holds suffix.retirementFresh suffix.signatureFresh
    (before.next + 9) suffixRuns.signatureRun assignment signatureFreshHolds
  have firstFreshHolds := fresh_prior_holds suffix.firstFresh suffix.retirementFresh
    (before.next + 8) suffixRuns.retirementRun assignment retirementFreshHolds
  have commitDefinedHolds := fresh_prior_holds middle.commitDefined suffix.firstFresh
    (before.next + 7) suffixRuns.firstRun assignment firstFreshHolds
  obtain ⟨signatureAssertedHolds, commitHolds⟩ := define_holds _ middle.signatureAsserted
    middle.commitDefined (before.next + 6) middleRuns.commitRun assignment commitDefinedHolds
  obtain ⟨commitSignatureFreshHolds, boundedSignatureHolds⟩ :=
    assertion_holds _ middle.commitSignatureFresh middle.signatureAsserted
      middleRuns.signatureRun assignment signatureAssertedHolds
  have entriesDefinedHolds := fresh_prior_holds middle.entriesDefined
    middle.commitSignatureFresh (before.next + 5) middleRuns.commitSignatureRun assignment
    commitSignatureFreshHolds
  obtain ⟨lengthDefinedHolds, entriesHolds⟩ := define_holds _ middle.lengthDefined
    middle.entriesDefined (before.next + 4) middleRuns.entriesRun assignment entriesDefinedHolds
  obtain ⟨spliceAssertedHolds, lengthHolds⟩ := define_holds _ states.spliceAsserted
    middle.lengthDefined (before.next + 3) middleRuns.lengthRun assignment lengthDefinedHolds
  obtain ⟨growsDefinedHolds, spliceHolds⟩ := assertion_holds _ states.growsDefined
    states.spliceAsserted runs.spliceRun assignment spliceAssertedHolds
  obtain ⟨splicedFreshHolds, growsHolds⟩ := define_holds _ states.splicedFresh
    states.growsDefined (before.next + 2) runs.growsRun assignment growsDefinedHolds
  have packetDefinedHolds := fresh_prior_holds states.packetDefined states.splicedFresh
    (before.next + 1) runs.splicedRun assignment splicedFreshHolds
  obtain ⟨guardedHolds, packetHolds⟩ := define_holds _ states.guarded states.packetDefined
    before.next runs.packetRun assignment packetDefinedHolds
  have guardParts :=
    (assert_all_holds (appendReceiveGuards before.toColumns source destination) before
      states.guarded runs.guardsRun assignment).mp guardedHolds
  refine
    { beforeHolds := guardParts.1
      guards := guardParts.2
      packet := packetHolds
      grows := growsHolds
      splice := spliceHolds
      length := lengthHolds
      entries := entriesHolds
      boundedSignature := boundedSignatureHolds
      commit := commitHolds
      refresh := refreshHolds
      current := currentHolds
      completed := ?_
      nack := nackHolds }
  simpa [completedShape.completedId] using completedParts.2

theorem receive_append_constraints {width : PNat} (source destination : Fin width)
    (before after : Encoding width)
    (run : (receiveAppend source destination).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment) :
    AppendReceivePrefixConstraints before source destination
      (appendReceiveExecutionTerms before source destination) assignment := by
  obtain ⟨states, result⟩ := receive_append_success source destination before after run
  let terms := appendReceiveExecutionTerms before source destination
  have writerHolds := append_receive_writes_holds_before source destination
    terms.branches.stepDown terms.values terms.response terms.completed
    states.middle.suffix.writerBefore after result.runs.middleRuns.suffixRuns.writeRun
    assignment holds
  exact append_receive_prefix_constraints source destination before after states result
    assignment writerHolds

theorem receive_append_prior_holds {width : PNat} (source destination : Fin width)
    (before after : Encoding width)
    (run : (receiveAppend source destination).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment) :
    Holds before.assertions.toList assignment :=
  (receive_append_constraints source destination before after run assignment holds).beforeHolds

theorem receive_append_references {width : PNat} (source destination : Fin width)
    (before after : Encoding width)
    (run : (receiveAppend source destination).run before = .ok ((), after))
    (valid : ReferencesValid before) : ReferencesValid after := by
  obtain ⟨states, result⟩ := receive_append_success source destination before after run
  have writerValid : ReferencesValid states.middle.suffix.writerBefore := by
    cases valid
    constructor <;> simp_all only [result.writerColumns, result.writerNext] <;> omega
  exact append_receive_writes_references source destination
    (appendReceiveExecutionTerms before source destination).branches.stepDown
    (appendReceiveExecutionTerms before source destination).values
    (appendReceiveExecutionTerms before source destination).response
    (appendReceiveExecutionTerms before source destination).completed
    states.middle.suffix.writerBefore after result.runs.middleRuns.suffixRuns.writeRun writerValid

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
