-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeMembershipComplete
import Sparse.NativeArrayMembershipTransition
import Sparse.NativeNodeRowModelEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem membership_change_bootstrap {width : PNat}
    (source : Fin width) (configuration : Finset (Fin width))
    (before after : Encoding width)
    (run : (membershipChange source configuration).run before = .ok ((), after)) :
    after.bootstrap = before.bootstrap := by
  obtain ⟨initial, suffix, execution⟩ :=
    membership_change_success source configuration before after run
  let terms := membershipExecutionTerms before source configuration
  obtain ⟨allocated, written, joinedDefined, completedDefined, joined, retiredNodes, result⟩ :=
    membership_writes_success source terms.added terms.values terms.completed
      suffix.writerBefore after execution.runs.suffixRuns.writeRun
  have shape := membership_writes_shape source terms.added terms.values terms.completed
    suffix.writerBefore allocated written joinedDefined completedDefined after joined retiredNodes result
  exact shape.2.1.trans execution.writerBootstrap

theorem membership_change_frame_success {width : PNat} [Bootstrap (Fin width)]
    (source : Fin width) (configuration : Finset (Fin width))
    (before after : Encoding width)
    (run : (membershipChange source configuration).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION) :
    exists nextFrame : NativeArrayVote.Frame (Fin width) Nat,
      NativeArrayChangeConfiguration.ChangeConfiguration frame source configuration nextFrame /\
      FrameColumnsRep assignment after.toColumns nextFrame := by
  let state := frame.realize
  have modelRep : frame.Rep state := NativeArrayVote.realize_rep frame rep.valid
  obtain ⟨allowed, written, writtenRep, writtenModel⟩ :=
    membership_change_model_sound source configuration before after run assignment holds
      frame state rep modelRep sameBootstrap
  obtain ⟨nextFrame, step⟩ :=
    NativeArrayChangeConfiguration.ChangeConfiguration.exists_of_enabled
      frame state modelRep source configuration allowed
  have nextModel :=
    (NativeArrayChangeConfiguration.ChangeConfiguration.model_correct
      frame nextFrame state modelRep source configuration step).2
  exact ⟨nextFrame, step, FrameColumnsRep.of_model_rep assignment after.toColumns
    written nextFrame (CCFRaft.next state (.changeConfiguration source configuration))
    writtenRep writtenModel nextModel⟩

theorem membership_change_complete {width : PNat} [Bootstrap (Fin width)]
    (source : Fin width) (configuration : Finset (Fin width))
    (before after : Encoding width)
    (run : (membershipChange source configuration).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds before.assertions.toList assignment)
    (frame nextFrame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (valid : ReferencesValid before)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION)
    (step :
      NativeArrayChangeConfiguration.ChangeConfiguration frame source configuration nextFrame) :
    exists extended : Assignment,
      assignment.AgreesBelow before.next extended /\
      Holds after.assertions.toList extended /\
      FrameColumnsRep extended after.toColumns nextFrame := by
  let state := frame.realize
  have modelRep : frame.Rep state := NativeArrayVote.realize_rep frame rep.valid
  obtain ⟨allowed, nextModel⟩ :=
    NativeArrayChangeConfiguration.ChangeConfiguration.model_correct
      frame nextFrame state modelRep source configuration step
  obtain ⟨extended, agreement, afterHolds, written, writtenRep, writtenModel⟩ :=
    membership_change_model_complete source configuration before after run assignment holds
      valid frame state rep modelRep allowed sameBootstrap
  exact ⟨extended, agreement, afterHolds,
    FrameColumnsRep.of_model_rep extended after.toColumns written nextFrame
      (CCFRaft.next state (.changeConfiguration source configuration))
      writtenRep writtenModel nextModel⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
