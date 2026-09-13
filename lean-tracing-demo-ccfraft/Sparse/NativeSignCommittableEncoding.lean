-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeSignatureSound
import Sparse.NativeSignatureComplete
import Sparse.NativeArraySignatureTransition
import Sparse.NativeNodeRowModelEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem signature_bootstrap {width : PNat} (source : Fin width)
    (before after : Encoding width)
    (run : (signCommittableMessages source).run before = .ok ((), after)) :
    after.bootstrap = before.bootstrap := by
  obtain ⟨states, result⟩ := sign_committable_messages_prefix source before after run
  let terms := signaturePrefixTerms before source
  exact (retirement_tail_bootstrap before.bootstrap source terms.appended terms.old.commit
    (signatureGuards before.toColumns source) states.tailBefore after
    result.runs.tailRun).trans result.tailBeforeBootstrap

theorem signature_prior_holds {width : PNat} (source : Fin width)
    (before after : Encoding width)
    (run : (signCommittableMessages source).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment) :
    Holds before.assertions.toList assignment := by
  obtain ⟨states, result⟩ := sign_committable_messages_prefix source before after run
  let terms := signaturePrefixTerms before source
  have prefixHolds := retirement_tail_prior_holds before.bootstrap source terms.appended
    terms.old.commit (signatureGuards before.toColumns source) states.tailBefore after
    result.runs.tailRun assignment holds
  exact (signature_prefix_facts source before after states result assignment prefixHolds).priorHolds

theorem signature_references {width : PNat} (source : Fin width)
    (before after : Encoding width)
    (run : (signCommittableMessages source).run before = .ok ((), after))
    (valid : ReferencesValid before) : ReferencesValid after := by
  obtain ⟨states, result⟩ := sign_committable_messages_prefix source before after run
  let terms := signaturePrefixTerms before source
  have tailValid : ReferencesValid states.tailBefore := by
    cases valid
    constructor <;> simp_all only [result.tailBeforeColumns, result.tailBeforeNext] <;> omega
  exact retirement_tail_references before.bootstrap source terms.appended terms.old.commit
    (signatureGuards before.toColumns source) states.tailBefore after
    result.runs.tailRun tailValid

theorem signature_frame_success {width : PNat} [Bootstrap (Fin width)]
    (source : Fin width) (before after : Encoding width)
    (run : (signCommittableMessages source).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION) :
    exists nextFrame : NativeArrayVote.Frame (Fin width) Nat,
      NativeArraySignature.Sign frame source nextFrame /\
        FrameColumnsRep assignment after.toColumns nextFrame := by
  let state := frame.realize
  have modelRep : frame.Rep state := NativeArrayVote.realize_rep frame rep.valid
  obtain ⟨allowed, written, writtenRep, writtenModel⟩ :=
    signature_model_sound source before after run assignment holds
      frame state rep modelRep sameBootstrap
  obtain ⟨nextFrame, step⟩ :=
    NativeArraySignature.Sign.exists_of_enabled frame state modelRep source allowed
  have nextModel :=
    (NativeArraySignature.Sign.model_correct frame nextFrame state modelRep source step).2
  exact ⟨nextFrame, step, FrameColumnsRep.of_model_rep assignment after.toColumns
    written nextFrame (CCFRaft.next state (.signCommittableMessages source))
    writtenRep writtenModel nextModel⟩

theorem signature_complete {width : PNat} [Bootstrap (Fin width)]
    (source : Fin width) (before after : Encoding width)
    (run : (signCommittableMessages source).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds before.assertions.toList assignment)
    (frame nextFrame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (valid : ReferencesValid before)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION)
    (step : NativeArraySignature.Sign frame source nextFrame) :
    exists extended : Assignment,
      assignment.AgreesBelow before.next extended /\
        Holds after.assertions.toList extended /\
        FrameColumnsRep extended after.toColumns nextFrame := by
  let state := frame.realize
  have modelRep : frame.Rep state := NativeArrayVote.realize_rep frame rep.valid
  obtain ⟨allowed, nextModel⟩ :=
    NativeArraySignature.Sign.model_correct frame nextFrame state modelRep source step
  obtain ⟨extended, agreement, afterHolds⟩ :=
    signature_assignment source before after run assignment holds valid
      frame state rep modelRep allowed sameBootstrap
  have originalRep : FrameColumnsRep extended before.toColumns frame :=
    rep.agrees_below before assignment extended frame valid agreement
  obtain ⟨_, written, writtenRep, writtenModel⟩ :=
    signature_model_sound source before after run extended afterHolds
      frame state originalRep modelRep sameBootstrap
  exact ⟨extended, agreement, afterHolds,
    FrameColumnsRep.of_model_rep extended after.toColumns written nextFrame
      (CCFRaft.next state (.signCommittableMessages source))
      writtenRep writtenModel nextModel⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
