-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeBecomeLeaderExecution
import Sparse.NativeBecomeLeaderRowEncoding
import Sparse.NativeLogSummaryAssignment

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem become_leader_prefix_assignment {width : PNat} [Bootstrap (Fin width)]
    (source : Fin width) (before after : Encoding width)
    (states : BecomeLeaderExecutionStates width)
    (execution : BecomeLeaderExecutionResult source before after states)
    (assignment : Assignment)
    (holds : Holds before.assertions.toList assignment)
    (valid : ReferencesValid before)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame) :
    exists extended : Assignment,
      assignment.AgreesBelow before.next extended /\
      Holds states.prefixStates.currentAsserted.assertions.toList extended /\
      FrameColumnsRep extended before.toColumns frame /\
      let terms := becomeLeaderExecutionTerms before source
      let row := NativeArrayCheckQuorum.get frame.nodes source
      let latestNat := maxCommittableIndex row.log.decode
      let currentNat := (currentConfigurationAt row.log.decode row.commit).index
      terms.latest.eval extended Locals.empty = (latestNat : Int) /\
        terms.current.eval extended Locals.empty = (currentNat : Int) /\
        NativeArrayVote.SignatureIndex row.log latestNat /\
        NativeArrayCheckQuorum.CurrentIndex row.log row.commit currentNat /\
        terms.prepared.Rep extended
          (NativeArrayBecomeLeader.prepareRow row latestNat) /\
        terms.prepared.Bounded states.prefixStates.currentAsserted.next := by
  let terms := becomeLeaderExecutionTerms before source
  let runs := execution.runs
  let prefixStates := states.prefixStates
  let row := NativeArrayCheckQuorum.get frame.nodes source
  have originalOldRep :=
    node_row_snapshot_rep assignment before.toColumns frame.nodes rep.nodes source
  have originalOldBounded := node_row_snapshot_bounded before source valid
  have oldLength :
      terms.old.logLength.eval assignment Locals.empty = (row.log.length : Int) := by
    simpa [terms, row, becomeLeaderExecutionTerms] using originalOldRep.logLength
  have oldEntries : forall position, position < row.log.length ->
      modelEntry
          (terms.old.logEntries.eval assignment Locals.empty (position : Int)) =
        row.log.entries position := by
    intro position live
    simpa [terms, row, becomeLeaderExecutionTerms] using
      originalOldRep.logEntries position live
  have oldLengthBounded :
      terms.old.logLength.symbols.all
        (fun symbol => symbol.2 < before.next) = true := by
    simpa [terms, becomeLeaderExecutionTerms] using originalOldBounded.logLength
  have oldEntriesBounded :
      terms.old.logEntries.symbols.all
        (fun symbol => symbol.2 < before.next) = true := by
    simpa [terms, becomeLeaderExecutionTerms] using originalOldBounded.logEntries
  obtain ⟨latestAssignment, latestAgreement, latestBaseHolds,
      latestAcceptedRaw⟩ :=
    bounded_signature_assignment before assignment holds terms.old.logLength
      terms.old.logEntries terms.old.logLength row.log row.log.length
      oldLengthBounded oldEntriesBounded oldLengthBounded oldLength oldLength
      oldEntries
  have latestAccepted :
      terms.latestConstraint.eval latestAssignment Locals.empty = true := by
    simpa [terms, becomeLeaderExecutionTerms] using latestAcceptedRaw
  have latestFreshHolds :=
    fresh_holds before prefixStates.latestFresh before.next runs.latestRun
      latestAssignment latestBaseHolds
  have latestAssertedHolds :
      Holds prefixStates.latestAsserted.assertions.toList latestAssignment :=
    assertion_extension_holds terms.latestConstraint prefixStates.latestFresh
      prefixStates.latestAsserted runs.latestAssertionRun latestAssignment
      latestFreshHolds latestAccepted
  have assignmentToLatest : assignment.AgreesBelow before.next latestAssignment :=
    latestAgreement
  have latestRep :=
    rep.agrees_below before assignment latestAssignment frame valid
      assignmentToLatest
  have latestOldRep :=
    node_row_snapshot_rep latestAssignment before.toColumns frame.nodes
      latestRep.nodes source
  obtain ⟨latestWitness, latestValueRaw, latestMaximum⟩ :=
    bounded_signature_term_sound latestAssignment Locals.empty
      terms.old.logLength terms.old.logEntries terms.old.logLength terms.latest
      row.log row.log.length latestOldRep.logLength latestOldRep.logLength
      latestOldRep.logEntries latestAccepted
  have latestWitnessEq :
      latestWitness = maxCommittableIndex row.log.decode := by
    rw [maxCommittableIndexUpTo] at latestMaximum
    have full : row.log.decode.take row.log.length = row.log.decode := by
      rw [<- row.log.decode_length, List.take_length]
    rw [full] at latestMaximum
    exact latestMaximum.symm
  subst latestWitness
  have latestIndex :
      NativeArrayVote.SignatureIndex row.log
        (maxCommittableIndex row.log.decode) :=
    (NativeArrayVote.signature_index_correct row.log
      (maxCommittableIndex row.log.decode)).mpr rfl
  have latestOldBounded : terms.old.Bounded prefixStates.latestAsserted.next :=
    originalOldBounded.mono (by rw [execution.latestAssertedNext]; omega)
  obtain ⟨currentAssignment, currentAgreement, currentBaseHolds,
      currentAcceptedRaw⟩ :=
    current_configuration_index_assignment prefixStates.latestAsserted latestAssignment
      latestAssertedHolds terms.old.logLength terms.old.logEntries terms.old.commit
      row.log row.commit latestOldBounded.logLength latestOldBounded.logEntries
      latestOldBounded.commit latestOldRep.logLength latestOldRep.commit
      latestOldRep.logEntries
  rw [execution.latestAssertedNext] at currentAcceptedRaw
  have currentAccepted :
      terms.currentConstraint.eval currentAssignment Locals.empty = true := by
    simpa [terms, becomeLeaderExecutionTerms] using currentAcceptedRaw
  have currentFreshHolds :=
    fresh_holds prefixStates.latestAsserted prefixStates.currentFresh (before.next + 1)
      runs.currentRun currentAssignment currentBaseHolds
  have currentAssertedHolds :
      Holds prefixStates.currentAsserted.assertions.toList currentAssignment :=
    assertion_extension_holds terms.currentConstraint prefixStates.currentFresh
      prefixStates.currentAsserted runs.currentAssertionRun currentAssignment
      currentFreshHolds currentAccepted
  have agreement : assignment.AgreesBelow before.next currentAssignment :=
    assignmentToLatest.trans
      (currentAgreement.restrict (by rw [execution.latestAssertedNext]; omega))
  have currentRep :=
    rep.agrees_below before assignment currentAssignment frame valid agreement
  have currentOldRep :=
    node_row_snapshot_rep currentAssignment before.toColumns frame.nodes
      currentRep.nodes source
  obtain ⟨currentWitness, currentValueRaw, currentMaximum⟩ :=
    current_configuration_index_term_sound currentAssignment Locals.empty
      terms.old.logLength terms.old.logEntries terms.old.commit terms.current
      row.log row.commit currentOldRep.logLength currentOldRep.commit
      currentOldRep.logEntries currentAccepted
  have currentWitnessEq :
      currentWitness = (currentConfigurationAt row.log.decode row.commit).index :=
    currentMaximum.symm
  subst currentWitness
  have currentIndex :
      NativeArrayCheckQuorum.CurrentIndex row.log row.commit
        (currentConfigurationAt row.log.decode row.commit).index :=
    (NativeArrayCheckQuorum.current_index_correct row.log row.commit
      (currentConfigurationAt row.log.decode row.commit).index).mpr rfl
  have latestValue :
      terms.latest.eval currentAssignment Locals.empty =
        (maxCommittableIndex row.log.decode : Int) := by
    rw [latestWitnessEq] at latestValueRaw
    have same := currentAgreement .int before.next (by
      rw [execution.latestAssertedNext]
      omega)
    simpa [terms, becomeLeaderExecutionTerms, Term.eval] using
      same.symm.trans latestValueRaw
  have preparedRep :
      terms.prepared.Rep currentAssignment
        (NativeArrayBecomeLeader.prepareRow row
          (maxCommittableIndex row.log.decode)) := by
    exact become_leader_row_terms_rep currentAssignment terms.old row terms.latest
      (maxCommittableIndex row.log.decode) currentOldRep latestValue
  have currentOldBounded : terms.old.Bounded prefixStates.currentAsserted.next :=
    originalOldBounded.mono (by rw [execution.currentAssertedNext]; omega)
  have latestBounded :
      terms.latest.symbols.all
        (fun symbol => symbol.2 < prefixStates.currentAsserted.next) = true := by
    simp [terms, becomeLeaderExecutionTerms, Term.symbols]
    rw [execution.currentAssertedNext]
    omega
  have preparedBounded : terms.prepared.Bounded prefixStates.currentAsserted.next :=
    become_leader_row_terms_bounded terms.old terms.latest
      prefixStates.currentAsserted.next currentOldBounded latestBounded
  exact ⟨currentAssignment, agreement, currentAssertedHolds, currentRep,
    latestValue, currentValueRaw, latestIndex, currentIndex, preparedRep,
    preparedBounded⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
