-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeRetirementTailSound
import Sparse.NativeSignaturePrefix

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem signature_model_sound {width : PNat} [Bootstrap (Fin width)]
    (source : Fin width) (before after : Encoding width)
    (run : (signCommittableMessages source).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (state : State (Fin width) Nat)
    (columnsRep : FrameColumnsRep assignment before.toColumns frame)
    (modelRep : frame.Rep state)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION) :
    CCFRaft.Enabled state (.signCommittableMessages source) /\
      exists written : NativeArrayVote.Frame (Fin width) Nat,
        FrameColumnsRep assignment after.toColumns written /\
        written.Rep (CCFRaft.next state (.signCommittableMessages source)) := by
  obtain ⟨states, prefixResult⟩ :=
    sign_committable_messages_prefix source before after run
  let terms := signaturePrefixTerms before source
  let old := NativeArrayCheckQuorum.get frame.nodes source
  let appended := NativeArrayLeaderLogWrite.appendRow old .signature
  have prefixHolds :=
    retirement_tail_prior_holds before.bootstrap source terms.appended terms.old.commit
      (signatureGuards before.toColumns source) states.tailBefore after
      prefixResult.runs.tailRun assignment holds
  have facts :=
    signature_prefix_facts source before after states prefixResult assignment prefixHolds
  have oldRep :=
    node_row_snapshot_rep assignment before.toColumns frame.nodes columnsRep.nodes source
  have appendedRep : terms.appended.Rep assignment appended :=
    signature_prefix_row_rep source before assignment frame columnsRep facts
  have tailColumnsRep :
      FrameColumnsRep assignment states.tailBefore.toColumns frame := by
    rw [prefixResult.tailBeforeColumns]
    exact columnsRep
  obtain ⟨output, outputRep, outputModelRaw, guardHolds, writtenColumns⟩ :=
    retirement_tail_sound before.bootstrap source terms.appended terms.old.commit
      (signatureGuards before.toColumns source) states.tailBefore after
      prefixResult.runs.tailRun assignment holds frame tailColumnsRep appended appendedRep
      old.commit
      (by simpa [terms, old, signaturePrefixTerms] using oldRep.commit)
      sameBootstrap
  have outputModelAppended :
      output.toModel = refreshRetirementState source appended.toModel := by
    simpa [appended, NativeArrayLeaderLogWrite.appendRow,
      NativeArrayCheckQuorum.Local.toModel] using outputModelRaw
  have sameRow : state.nodes source = old.toModel :=
    (NativeArrayCheckQuorum.get_rep frame.nodes state modelRep.nodes source).symm
  have appendedModel :
      appended.toModel =
        { (state.nodes source) with
          log := (state.nodes source).log ++
            [{ term := (state.nodes source).currentTerm, content := .signature }] } := by
    change (NativeArrayLeaderLogWrite.appendRow old .signature).toModel = _
    rw [NativeArrayLeaderLogWrite.append_row_correct, sameRow]
  have outputModel :
      output.toModel =
        refreshRetirementState source
          { (state.nodes source) with
            log := (state.nodes source).log ++
              [{ term := (state.nodes source).currentTerm, content := .signature }] } := by
    rw [outputModelAppended, appendedModel]
  let tailTerms := retirementTailTerms states.tailBefore terms.appended terms.old.commit
  have nativeEnabled : NativeArraySignature.enabled frame source output :=
    (signature_guards_correct assignment before.toColumns frame columnsRep source
      tailTerms.values.membershipState output
      (by simpa [tailTerms] using outputRep.membershipState)).mp
      (by simpa [tailTerms] using guardHolds)
  have enabled : CCFRaft.Enabled state (.signCommittableMessages source) :=
    (NativeArraySignature.enabled_correct frame state modelRep source output
      outputModel).mp nativeEnabled
  let completed := retirementCompletedNodes output.log.decode output.commit
  have writtenModel :
      (NativeArraySignature.sign frame source output completed).Rep
        (CCFRaft.next state (.signCommittableMessages source)) :=
    NativeArraySignature.sign_output_rep frame state modelRep source output completed
      outputModel rfl
  refine ⟨enabled, NativeArraySignature.sign frame source output completed, ?_,
    writtenModel⟩
  simpa [retirementWriteFrame, NativeArraySignature.sign] using writtenColumns

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
