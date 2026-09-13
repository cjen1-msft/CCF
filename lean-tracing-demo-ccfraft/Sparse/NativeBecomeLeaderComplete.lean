-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeBecomeLeaderPrefixAssignment
import Sparse.NativeBecomeLeaderGuardsEncoding
import Sparse.NativeBecomeLeaderSound
import Sparse.NativeRetirementTailComplete
import Sparse.NativeArrayBecomeLeaderTransition

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem become_leader_assignment {width : PNat} [Bootstrap (Fin width)]
    (source : Fin width) (before after : Encoding width)
    (run : (becomeLeader source).run before = .ok ((), after))
    (assignment : Assignment)
    (holds : Holds before.assertions.toList assignment)
    (valid : ReferencesValid before)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (state : State (Fin width) Nat)
    (columnsRep : FrameColumnsRep assignment before.toColumns frame)
    (modelRep : frame.Rep state)
    (enabled : CCFRaft.Enabled state (.becomeLeader source))
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION) :
    exists extended : Assignment,
      assignment.AgreesBelow before.next extended /\
        Holds after.assertions.toList extended := by
  obtain ⟨states, execution⟩ :=
    become_leader_success source before after run
  let terms := becomeLeaderExecutionTerms before source
  let row := NativeArrayCheckQuorum.get frame.nodes source
  let latestNat := maxCommittableIndex row.log.decode
  let currentNat := (currentConfigurationAt row.log.decode row.commit).index
  let prepared := NativeArrayBecomeLeader.prepareRow row latestNat
  obtain ⟨prefixAssignment, prefixAgreement, prefixHolds, prefixFrameRep,
      latestValue, currentValue, latestCorrect, currentCorrect, preparedRep,
      preparedBounded⟩ :=
    become_leader_prefix_assignment source before after states execution
      assignment holds valid frame columnsRep
  have tailValid : ReferencesValid states.prefixStates.currentAsserted := by
    cases valid
    constructor <;>
      simp_all only [execution.currentAssertedColumns,
        execution.currentAssertedNext] <;>
      omega
  have sameCommit :
      terms.old.commit.eval prefixAssignment Locals.empty = (row.commit : Int) := by
    simpa [terms, row, latestNat, prepared, becomeLeaderExecutionTerms,
      NativeArrayBecomeLeader.prepareRow] using preparedRep.commit
  have commitBounded :
      terms.old.commit.symbols.all
        (fun symbol => symbol.2 < states.prefixStates.currentAsserted.next) =
          true := by
    simpa [terms, becomeLeaderExecutionTerms, becomeLeaderRowTerms] using
      preparedBounded.commit
  obtain ⟨extended, tailAgreement, finalHolds⟩ :=
    retirement_tail_complete before.bootstrap source terms.prepared
      terms.old.commit terms.guards states.prefixStates.currentAsserted after
      execution.runs.tailRun prefixAssignment prefixHolds tailValid frame
      (by simpa only [execution.currentAssertedColumns] using prefixFrameRep)
      prepared preparedRep preparedBounded row.commit sameCommit commitBounded
      sameBootstrap (by
        intro candidateAssignment candidateAgreement output outputRep outputModel
        have prefixToCandidate :
            prefixAssignment.AgreesBelow before.next candidateAssignment :=
          candidateAgreement.restrict (by
            rw [execution.currentAssertedNext]
            omega)
        have candidateFrameRep :
            FrameColumnsRep candidateAssignment before.toColumns frame :=
          prefixFrameRep.agrees_below before prefixAssignment
            candidateAssignment frame valid prefixToCandidate
        have sameCurrent :
            terms.current.eval candidateAssignment Locals.empty =
              (currentNat : Int) := by
          have currentBounded :
              forall symbol, symbol ∈ terms.current.symbols ->
                symbol.2 < states.prefixStates.currentAsserted.next := by
            intro symbol member
            simp [terms, becomeLeaderExecutionTerms, Term.symbols] at member
            rcases member with ⟨_, rfl⟩
            rw [execution.currentAssertedNext]
            omega
          exact
            (terms.current.eval_agrees_below prefixAssignment candidateAssignment
              Locals.empty states.prefixStates.currentAsserted.next
              currentBounded candidateAgreement).symm.trans currentValue
        have outputModelPrepared :
            output.toModel =
              refreshRetirementState source prepared.toModel := by
          simpa [prepared, row, latestNat,
            NativeArrayBecomeLeader.prepareRow,
            NativeArrayCheckQuorum.Local.toModel] using outputModel
        have nativeEnabled :
            NativeArrayBecomeLeader.enabled frame source currentNat output :=
          (NativeArrayBecomeLeader.enabled_correct frame state modelRep source
            currentNat latestNat output currentCorrect latestCorrect
            outputModelPrepared).mpr enabled
        let tailTerms :=
          retirementTailTerms states.prefixStates.currentAsserted
            terms.prepared terms.old.commit
        have sameBits :
            before.bootstrap = encodeBits INITIAL_CONFIGURATION := by
          rw [<- sameBootstrap, encode_decode_bits]
        exact
          (become_leader_guards_correct candidateAssignment before.bootstrap
            before.toColumns frame candidateFrameRep source terms.current
            tailTerms.values.membershipState currentNat output sameBits
            sameCurrent (by
              simpa only [tailTerms] using outputRep.membershipState)).mpr
            nativeEnabled)
  have prefixToExtended :
      prefixAssignment.AgreesBelow before.next extended :=
    tailAgreement.restrict (by
      rw [execution.currentAssertedNext]
      omega)
  exact ⟨extended, prefixAgreement.trans prefixToExtended, finalHolds⟩

theorem become_leader_complete {width : PNat} [Bootstrap (Fin width)]
    (source : Fin width) (before after : Encoding width)
    (run : (becomeLeader source).run before = .ok ((), after))
    (assignment : Assignment)
    (holds : Holds before.assertions.toList assignment)
    (frame nextFrame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (valid : ReferencesValid before)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION)
    (step : NativeArrayBecomeLeader.BecomeLeader frame source nextFrame) :
    exists extended : Assignment,
      assignment.AgreesBelow before.next extended /\
        Holds after.assertions.toList extended /\
        FrameColumnsRep extended after.toColumns nextFrame := by
  let state := frame.realize
  have modelRep : frame.Rep state :=
    NativeArrayVote.realize_rep frame rep.valid
  obtain ⟨enabled, nextModel⟩ :=
    NativeArrayBecomeLeader.BecomeLeader.model_correct frame nextFrame state
      modelRep source step
  obtain ⟨extended, agreement, afterHolds⟩ :=
    become_leader_assignment source before after run assignment holds valid frame
      state rep modelRep enabled sameBootstrap
  have originalRep : FrameColumnsRep extended before.toColumns frame :=
    rep.agrees_below before assignment extended frame valid agreement
  obtain ⟨_, written, writtenRep, writtenModel⟩ :=
    become_leader_model_sound source before after run extended afterHolds frame
      state originalRep modelRep sameBootstrap
  exact ⟨extended, agreement, afterHolds,
    FrameColumnsRep.of_model_rep extended after.toColumns written nextFrame
      (CCFRaft.next state (.becomeLeader source))
      writtenRep writtenModel nextModel⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
