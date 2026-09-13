-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendReceiveComplete
import Sparse.NativeNodeRowModelEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem receive_append_frame_success {width : PNat} [Bootstrap (Fin width)]
    (source destination : Fin width) (before after : Encoding width)
    (run : (receiveAppend source destination).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION) :
    exists nextFrame : NativeArrayVote.Frame (Fin width) Nat,
      NativeArrayAppendNetwork.ReceiveAppend frame source destination nextFrame /\
      FrameColumnsRep assignment after.toColumns nextFrame := by
  let state := frame.realize
  have modelRep : frame.Rep state := NativeArrayVote.realize_rep frame rep.valid
  obtain ⟨request, selected, allowed, written, writtenRep, writtenModel⟩ :=
    receive_append_model_sound source destination before after run assignment holds
      frame state rep modelRep sameBootstrap
  obtain ⟨nextFrame, step⟩ :=
    NativeArrayAppendNetwork.receive_append_exists frame state modelRep
      source destination request selected allowed
  have nextModel :=
    NativeArrayAppendNetwork.receive_append_rep frame state modelRep
      source destination nextFrame step
  exact ⟨nextFrame, step, FrameColumnsRep.of_model_rep assignment after.toColumns
    written nextFrame (CCFRaft.next state (.receive source destination))
    writtenRep writtenModel nextModel⟩

theorem receive_append_complete {width : PNat} [Bootstrap (Fin width)]
    (source destination : Fin width) (before after : Encoding width)
    (run : (receiveAppend source destination).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds before.assertions.toList assignment)
    (frame nextFrame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (valid : ReferencesValid before)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION)
    (step : NativeArrayAppendNetwork.ReceiveAppend frame source destination nextFrame) :
    exists extended : Assignment,
      assignment.AgreesBelow before.next extended /\
      Holds after.assertions.toList extended /\
      FrameColumnsRep extended after.toColumns nextFrame := by
  let state := frame.realize
  have modelRep : frame.Rep state := NativeArrayVote.realize_rep frame rep.valid
  have allowed :=
    NativeArrayAppendNetwork.receive_append_enabled frame state modelRep
      source destination nextFrame step
  have nextModel :=
    NativeArrayAppendNetwork.receive_append_rep frame state modelRep
      source destination nextFrame step
  have selected : exists request,
      NativeArrayAppendNetwork.SelectedAppend frame source destination request := by
    cases step <;> exact ⟨_, by assumption⟩
  obtain ⟨request, selected⟩ := selected
  obtain ⟨extended, agreement, afterHolds, written, writtenRep, writtenModel⟩ :=
    receive_append_model_complete source destination before after run assignment holds
      valid frame state rep modelRep request selected allowed sameBootstrap
  exact ⟨extended, agreement, afterHolds,
    FrameColumnsRep.of_model_rep extended after.toColumns written nextFrame
      (CCFRaft.next state (.receive source destination)) writtenRep writtenModel nextModel⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
