-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendReceiveWritesEncoding
import Sparse.NativeArrayAppendNetwork

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem append_receive_write_frame_rep {width : PNat} [Bootstrap (Fin width)]
    (frame : NativeArrayVote.Frame (Fin width) Nat) (state : State (Fin width) Nat)
    (rep : frame.Rep state) (source destination : Fin width)
    (request : AppendEntriesRequest (Fin width) Nat)
    (selected : NativeArrayAppendNetwork.SelectedAppend frame source destination request)
    (step : Bool) (output candidate : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (response : AppendEntriesResponse (Fin width)) (completed : Finset (Fin width))
    (stepDownCorrect : step = true ->
      request.term = (NativeArrayCheckQuorum.get frame.nodes destination).currentTerm /\
      ((NativeArrayCheckQuorum.get frame.nodes destination).role = .candidate \/
        (NativeArrayCheckQuorum.get frame.nodes destination).role = .preVoteCandidate) /\
      output =
        { NativeArrayCheckQuorum.get frame.nodes destination with
          role := .follower, isNewFollower := true })
    (consumeCorrect : step = false ->
      handleAppendEntriesRequest?
          (NativeArrayCheckQuorum.get frame.nodes destination).toModel request =
        some (candidate.toModel, response) /\
      output.toModel = refreshRetirementState destination candidate.toModel /\
      completed = retirementCompletedNodes candidate.log.decode candidate.commit) :
    (appendReceiveWriteFrame frame source destination step output response completed).Rep
      (CCFRaft.next state (.receive source destination)) := by
  cases step with
  | false =>
    obtain ⟨handled, refreshed, completedCorrect⟩ := consumeCorrect rfl
    simpa [appendReceiveWriteFrame, NativeArrayAppendNetwork.consumeAppend] using
      NativeArrayAppendNetwork.consume_append_rep frame state rep source destination request
        selected candidate.toModel response handled output refreshed completed completedCorrect
  | true =>
    obtain ⟨sameTerm, candidateRole, sameOutput⟩ := stepDownCorrect rfl
    subst output
    simpa [appendReceiveWriteFrame, NativeArrayAppendNetwork.stepDownAppend] using
      NativeArrayAppendNetwork.step_down_append_rep frame state rep source destination request
        selected sameTerm candidateRole

theorem append_receive_writes_model_sound {width : PNat} [Bootstrap (Fin width)]
    (source destination : Fin width) (stepDown : Expr .bool)
    (values : NodeRowTerms width) (output : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (responseTerm : Expr (packetTy width)) (response : AppendEntriesResponse (Fin width))
    (completedTerm : Expr (.bits width)) (completed : Finset (Fin width))
    (before after : Encoding width)
    (run : (appendReceiveWrites source destination stepDown values responseTerm completedTerm).run
      before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat) (state : State (Fin width) Nat)
    (columnsRep : FrameColumnsRep assignment before.toColumns frame)
    (modelRep : frame.Rep state) (valuesRep : values.Rep assignment output)
    (step : Bool) (sameStep : stepDown.eval assignment Locals.empty = step)
    (sameResponse : responseTerm.eval assignment Locals.empty =
      packetValue (.appendEntriesResponse response))
    (responseSource : response.source = destination)
    (responseDestination : response.destination = source)
    (sameCompleted : completedTerm.eval assignment Locals.empty = encodeBits completed)
    (request : AppendEntriesRequest (Fin width) Nat)
    (selected : NativeArrayAppendNetwork.SelectedAppend frame source destination request)
    (candidate : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (stepDownCorrect : step = true ->
      request.term = (NativeArrayCheckQuorum.get frame.nodes destination).currentTerm /\
      ((NativeArrayCheckQuorum.get frame.nodes destination).role = .candidate \/
        (NativeArrayCheckQuorum.get frame.nodes destination).role = .preVoteCandidate) /\
      output =
        { NativeArrayCheckQuorum.get frame.nodes destination with
          role := .follower, isNewFollower := true })
    (consumeCorrect : step = false ->
      handleAppendEntriesRequest?
          (NativeArrayCheckQuorum.get frame.nodes destination).toModel request =
        some (candidate.toModel, response) /\
      output.toModel = refreshRetirementState destination candidate.toModel /\
      completed = retirementCompletedNodes candidate.log.decode candidate.commit) :
    let written :=
      appendReceiveWriteFrame frame source destination step output response completed
    FrameColumnsRep assignment after.toColumns written /\
      written.Rep (CCFRaft.next state (.receive source destination)) := by
  refine ⟨append_receive_writes_frame_sound source destination stepDown values output
    responseTerm response completedTerm completed before after run assignment holds frame
    columnsRep valuesRep step sameStep sameResponse responseSource responseDestination
    sameCompleted, ?_⟩
  exact append_receive_write_frame_rep frame state modelRep source destination request selected
    step output candidate response completed stepDownCorrect consumeCorrect

theorem append_receive_writes_model_complete {width : PNat} [Bootstrap (Fin width)]
    (source destination : Fin width) (stepDown : Expr .bool)
    (values : NodeRowTerms width) (output : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (responseTerm : Expr (packetTy width)) (response : AppendEntriesResponse (Fin width))
    (completedTerm : Expr (.bits width)) (completed : Finset (Fin width))
    (before after : Encoding width)
    (run : (appendReceiveWrites source destination stepDown values responseTerm completedTerm).run
      before = .ok ((), after))
    (assignment : Assignment) (holds : Holds before.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat) (state : State (Fin width) Nat)
    (columnsRep : FrameColumnsRep assignment before.toColumns frame)
    (modelRep : frame.Rep state) (valuesRep : values.Rep assignment output)
    (valid : ReferencesValid before)
    (step : Bool) (sameStep : stepDown.eval assignment Locals.empty = step)
    (sameResponse : responseTerm.eval assignment Locals.empty =
      packetValue (.appendEntriesResponse response))
    (responseSource : response.source = destination)
    (responseDestination : response.destination = source)
    (sameCompleted : completedTerm.eval assignment Locals.empty = encodeBits completed)
    (request : AppendEntriesRequest (Fin width) Nat)
    (selected : NativeArrayAppendNetwork.SelectedAppend frame source destination request)
    (candidate : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (stepDownCorrect : step = true ->
      request.term = (NativeArrayCheckQuorum.get frame.nodes destination).currentTerm /\
      ((NativeArrayCheckQuorum.get frame.nodes destination).role = .candidate \/
        (NativeArrayCheckQuorum.get frame.nodes destination).role = .preVoteCandidate) /\
      output =
        { NativeArrayCheckQuorum.get frame.nodes destination with
          role := .follower, isNewFollower := true })
    (consumeCorrect : step = false ->
      handleAppendEntriesRequest?
          (NativeArrayCheckQuorum.get frame.nodes destination).toModel request =
        some (candidate.toModel, response) /\
      output.toModel = refreshRetirementState destination candidate.toModel /\
      completed = retirementCompletedNodes candidate.log.decode candidate.commit) :
    exists extended : Assignment,
      assignment.AgreesBelow before.next extended /\
      Holds after.assertions.toList extended /\
      let written :=
        appendReceiveWriteFrame frame source destination step output response completed
      FrameColumnsRep extended after.toColumns written /\
        written.Rep (CCFRaft.next state (.receive source destination)) := by
  obtain ⟨extended, agreement, afterHolds, writtenRep⟩ :=
    append_receive_writes_complete source destination stepDown values output responseTerm response
      completedTerm completed before after run assignment holds frame columnsRep valuesRep valid
      step sameStep sameResponse responseSource responseDestination sameCompleted
  refine ⟨extended, agreement, afterHolds, writtenRep, ?_⟩
  exact append_receive_write_frame_rep frame state modelRep source destination request selected
    step output candidate response completed stepDownCorrect consumeCorrect

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
