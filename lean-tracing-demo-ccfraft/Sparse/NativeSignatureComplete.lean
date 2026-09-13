-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeRetirementTailComplete
import Sparse.NativeSignaturePrefix
import Sparse.NativeSignatureTermsEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem signature_assignment {width : PNat} [Bootstrap (Fin width)]
    (source : Fin width) (before after : Encoding width)
    (run : (signCommittableMessages source).run before = .ok ((), after))
    (assignment : Assignment)
    (holds : Holds before.assertions.toList assignment)
    (valid : ReferencesValid before)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (state : State (Fin width) Nat)
    (columnsRep : FrameColumnsRep assignment before.toColumns frame)
    (modelRep : frame.Rep state)
    (enabled : CCFRaft.Enabled state (.signCommittableMessages source))
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION) :
    exists extended : Assignment,
      assignment.AgreesBelow before.next extended /\
        Holds after.assertions.toList extended := by
  obtain ⟨states, prefixResult⟩ :=
    sign_committable_messages_prefix source before after run
  let terms := signaturePrefixTerms before source
  let old := NativeArrayCheckQuorum.get frame.nodes source
  let appended := NativeArrayLeaderLogWrite.appendRow old .signature
  obtain ⟨prefixAssignment, prefixAgreement, prefixHolds, prefixFrameRep,
      appendedRep, appendedBounded⟩ :=
    signature_prefix_assignment source before after states prefixResult assignment
      holds valid frame columnsRep
  have tailValid : ReferencesValid states.tailBefore := by
    cases valid
    constructor <;>
      simp_all only [prefixResult.tailBeforeColumns, prefixResult.tailBeforeNext] <;>
        omega
  have tailFrameRep :
      FrameColumnsRep prefixAssignment states.tailBefore.toColumns frame := by
    rw [prefixResult.tailBeforeColumns]
    exact prefixFrameRep
  have sameCommit :
      terms.old.commit.eval prefixAssignment Locals.empty = (old.commit : Int) := by
    simpa [terms, old, appended, signaturePrefixTerms,
      NativeArrayLeaderLogWrite.appendRow] using appendedRep.commit
  have commitBounded :
      terms.old.commit.symbols.all
        (fun symbol => symbol.2 < states.tailBefore.next) = true := by
    simpa [terms, signaturePrefixTerms, leaderLogRowTerms] using
      appendedBounded.commit
  obtain ⟨extended, tailAgreement, finalHolds⟩ :=
    retirement_tail_complete before.bootstrap source terms.appended terms.old.commit
      (signatureGuards before.toColumns source) states.tailBefore after
      prefixResult.runs.tailRun prefixAssignment prefixHolds tailValid frame
      tailFrameRep appended appendedRep appendedBounded old.commit sameCommit
      commitBounded sameBootstrap (by
        intro candidateAssignment candidateAgreement output outputRep outputModel
        have prefixToCandidate :
            prefixAssignment.AgreesBelow before.next candidateAssignment :=
          candidateAgreement.restrict (by
            rw [prefixResult.tailBeforeNext]
            omega)
        have candidateFrameRep :
            FrameColumnsRep candidateAssignment before.toColumns frame :=
          prefixFrameRep.agrees_below before prefixAssignment candidateAssignment
            frame valid prefixToCandidate
        have outputModelAppended :
            output.toModel = refreshRetirementState source appended.toModel := by
          simpa [appended, NativeArrayLeaderLogWrite.appendRow,
            NativeArrayCheckQuorum.Local.toModel] using outputModel
        have sameRow : state.nodes source = old.toModel :=
          (NativeArrayCheckQuorum.get_rep frame.nodes state modelRep.nodes source).symm
        have appendedModel :
            appended.toModel =
              { (state.nodes source) with
                log := (state.nodes source).log ++
                  [{ term := (state.nodes source).currentTerm, content := .signature }] } := by
          change (NativeArrayLeaderLogWrite.appendRow old .signature).toModel = _
          rw [NativeArrayLeaderLogWrite.append_row_correct, sameRow]
        have outputModelActual :
            output.toModel =
              refreshRetirementState source
                { (state.nodes source) with
                  log := (state.nodes source).log ++
                    [{ term := (state.nodes source).currentTerm, content := .signature }] } := by
          rw [outputModelAppended, appendedModel]
        have nativeEnabled : NativeArraySignature.enabled frame source output :=
          (NativeArraySignature.enabled_correct frame state modelRep source output
            outputModelActual).mpr enabled
        let tailTerms :=
          retirementTailTerms states.tailBefore terms.appended terms.old.commit
        exact
          (signature_guards_correct candidateAssignment before.toColumns frame
            candidateFrameRep source tailTerms.values.membershipState output
            (by simpa [tailTerms] using outputRep.membershipState)).mpr
            nativeEnabled)
  have prefixToExtended :
      prefixAssignment.AgreesBelow before.next extended :=
    tailAgreement.restrict (by
      rw [prefixResult.tailBeforeNext]
      omega)
  exact ⟨extended, prefixAgreement.trans prefixToExtended, finalHolds⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
