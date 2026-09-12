-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeMembershipWritesEncoding
import Sparse.NativeArrayChangeConfiguration

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem membership_writes_model_sound {width : PNat} [Bootstrap (Fin width)]
    (source : Fin width) (added : Expr (.bits width))
    (values : NodeRowTerms width)
    (output : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (completedTerm : Expr (.bits width)) (completed : Finset (Fin width))
    (newConfiguration previousConfiguration : Finset (Fin width))
    (before after : Encoding width)
    (run : (membershipWrites source added values completedTerm).run before =
      .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat) (state : State (Fin width) Nat)
    (columnsRep : FrameColumnsRep assignment before.toColumns frame)
    (modelRep : frame.Rep state)
    (valuesRep : values.Rep assignment output)
    (sameAdded : added.eval assignment Locals.empty =
      encodeBits (newConfiguration \ previousConfiguration))
    (sameCompleted : completedTerm.eval assignment Locals.empty =
      encodeBits completed)
    (previousCorrect :
      (latestConfiguration (state.nodes source)).nodes = previousConfiguration)
    (rowCorrect :
      output.toModel =
        refreshRetirementState source
          (NativeArrayChangeConfiguration.appendRow
            (NativeArrayCheckQuorum.get frame.nodes source)
            newConfiguration previousConfiguration).toModel)
    (completedCorrect :
      completed = retirementCompletedNodes
        (NativeArrayChangeConfiguration.appendRow
          (NativeArrayCheckQuorum.get frame.nodes source)
          newConfiguration previousConfiguration).log.decode
        (NativeArrayCheckQuorum.get frame.nodes source).commit) :
    let written :=
      membershipWriteFrame frame source
        (newConfiguration \ previousConfiguration) completed output
    FrameColumnsRep assignment after.toColumns written /\
      written.Rep (CCFRaft.next state (.changeConfiguration source newConfiguration)) := by
  let written :=
    membershipWriteFrame frame source
      (newConfiguration \ previousConfiguration) completed output
  have writtenRep : FrameColumnsRep assignment after.toColumns written := by
    simpa [written, sameAdded, sameCompleted] using
      membership_writes_frame_sound source added values completedTerm before after run
        assignment holds frame output columnsRep valuesRep
  refine ⟨writtenRep, ?_⟩
  simpa [written, membershipWriteFrame] using
    NativeArrayChangeConfiguration.change_configuration_output_rep
      frame state modelRep source newConfiguration previousConfiguration output completed
      previousCorrect rowCorrect completedCorrect

theorem membership_writes_model_complete {width : PNat} [Bootstrap (Fin width)]
    (source : Fin width) (added : Expr (.bits width))
    (values : NodeRowTerms width)
    (output : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (completedTerm : Expr (.bits width)) (completed : Finset (Fin width))
    (newConfiguration previousConfiguration : Finset (Fin width))
    (before after : Encoding width)
    (run : (membershipWrites source added values completedTerm).run before =
      .ok ((), after))
    (assignment : Assignment) (holds : Holds before.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat) (state : State (Fin width) Nat)
    (columnsRep : FrameColumnsRep assignment before.toColumns frame)
    (modelRep : frame.Rep state)
    (valuesRep : values.Rep assignment output)
    (valid : ReferencesValid before)
    (sameAdded : added.eval assignment Locals.empty =
      encodeBits (newConfiguration \ previousConfiguration))
    (sameCompleted : completedTerm.eval assignment Locals.empty =
      encodeBits completed)
    (previousCorrect :
      (latestConfiguration (state.nodes source)).nodes = previousConfiguration)
    (rowCorrect :
      output.toModel =
        refreshRetirementState source
          (NativeArrayChangeConfiguration.appendRow
            (NativeArrayCheckQuorum.get frame.nodes source)
            newConfiguration previousConfiguration).toModel)
    (completedCorrect :
      completed = retirementCompletedNodes
        (NativeArrayChangeConfiguration.appendRow
          (NativeArrayCheckQuorum.get frame.nodes source)
          newConfiguration previousConfiguration).log.decode
        (NativeArrayCheckQuorum.get frame.nodes source).commit) :
    after.next = before.next + 17 * width + 18 /\
      exists extended : Assignment,
        assignment.AgreesBelow before.next extended /\
        Holds after.assertions.toList extended /\
        let written :=
          membershipWriteFrame frame source
            (newConfiguration \ previousConfiguration) completed output
        FrameColumnsRep extended after.toColumns written /\
          written.Rep
            (CCFRaft.next state (.changeConfiguration source newConfiguration)) := by
  obtain ⟨next, extended, agreement, afterHolds, writtenRep⟩ :=
    membership_writes_complete source added values completedTerm before after run
      assignment holds frame output columnsRep valuesRep valid
  let written :=
    membershipWriteFrame frame source
      (newConfiguration \ previousConfiguration) completed output
  have exactWrittenRep : FrameColumnsRep extended after.toColumns written := by
    simpa [written, sameAdded, sameCompleted] using writtenRep
  refine ⟨next, extended, agreement, afterHolds, exactWrittenRep, ?_⟩
  simpa [written, membershipWriteFrame] using
    NativeArrayChangeConfiguration.change_configuration_output_rep
      frame state modelRep source newConfiguration previousConfiguration output completed
      previousCorrect rowCorrect completedCorrect

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
