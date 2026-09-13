-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeCommitComplete
import Sparse.NativeArrayCommitTransition
import Sparse.NativeNodeRowModelEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem advance_commit_frame_success {width : PNat} [Bootstrap (Fin width)]
    (source : Fin width) (before after : Encoding width)
    (run : (advanceCommitIndex source).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION) :
    exists nextFrame : NativeArrayVote.Frame (Fin width) Nat,
      NativeArrayAdvanceCommit.AdvanceCommit frame source nextFrame /\
        FrameColumnsRep assignment after.toColumns nextFrame := by
  let state := frame.realize
  have modelRep : frame.Rep state := NativeArrayVote.realize_rep frame rep.valid
  obtain ⟨allowed, written, writtenRep, writtenModel⟩ :=
    advance_commit_model_sound source before after run assignment holds
      frame state rep modelRep sameBootstrap
  obtain ⟨nextFrame, step⟩ :=
    NativeArrayAdvanceCommit.AdvanceCommit.exists_of_enabled frame state modelRep source allowed
  have nextModel :=
    (NativeArrayAdvanceCommit.AdvanceCommit.model_correct frame nextFrame state modelRep source step).2
  exact ⟨nextFrame, step, FrameColumnsRep.of_model_rep assignment after.toColumns
    written nextFrame (CCFRaft.next state (.advanceCommitIndex source))
    writtenRep writtenModel nextModel⟩

theorem advance_commit_complete {width : PNat} [Bootstrap (Fin width)]
    (source : Fin width) (before after : Encoding width)
    (run : (advanceCommitIndex source).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds before.assertions.toList assignment)
    (frame nextFrame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (valid : ReferencesValid before)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION)
    (step : NativeArrayAdvanceCommit.AdvanceCommit frame source nextFrame) :
    exists extended : Assignment,
      assignment.AgreesBelow before.next extended /\
        Holds after.assertions.toList extended /\
        FrameColumnsRep extended after.toColumns nextFrame := by
  let state := frame.realize
  have modelRep : frame.Rep state := NativeArrayVote.realize_rep frame rep.valid
  obtain ⟨allowed, nextModel⟩ :=
    NativeArrayAdvanceCommit.AdvanceCommit.model_correct
      frame nextFrame state modelRep source step
  obtain ⟨extended, agreement, afterHolds, written, writtenRep, writtenModel⟩ :=
    advance_commit_model_complete source before after run assignment holds
      valid frame state rep modelRep allowed sameBootstrap
  exact ⟨extended, agreement, afterHolds,
    FrameColumnsRep.of_model_rep extended after.toColumns written nextFrame
      (CCFRaft.next state (.advanceCommitIndex source))
      writtenRep writtenModel nextModel⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
