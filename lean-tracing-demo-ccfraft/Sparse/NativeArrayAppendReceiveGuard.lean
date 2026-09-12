-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayAppendHandlerCases
import Sparse.NativeArrayVoteReceive

set_option autoImplicit false

namespace CCFRaft.NativeArrayAppendReceiveGuard

open NativeArrayCheckQuorum NativeArrayVote

variable {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]

omit [DecidableEq N] [DecidableEq T] [Bootstrap N] in
theorem return_to_follower_is_some_iff (row : Local N T)
    (request : AppendEntriesRequest N T) :
    (returnToFollowerState? row.toModel request).isSome = true <->
      request.term = row.currentTerm /\
        (row.role = .candidate \/ row.role = .preVoteCandidate) := by
  simp [returnToFollowerState?, Local.toModel]

omit [Bootstrap N] in
theorem selected_append_source (frame : Frame N T) (state : State N T)
    (rep : frame.Rep state) (source destination : N)
    (request : AppendEntriesRequest N T)
    (selected : (frame.queues destination source).peek =
      some (.appendEntriesRequest request)) :
    request.source = source := by
  obtain ⟨remaining, taken⟩ :=
    NativeArrayVoteReceive.selected_model_take frame state rep source destination
      (.appendEntriesRequest request) selected
  exact (takeFirstFromSound taken).1

theorem append_request_receive_is_some (state : State N T) (source destination : N)
    (request : AppendEntriesRequest N T) (remaining : List (Message N T))
    (taken : takeFirstFrom source (state.network destination) =
      some (.appendEntriesRequest request, remaining)) :
    (handleReceive? state source destination).isSome = true <->
      request.destination = destination /\
        ((returnToFollowerState? (state.nodes destination) request).isSome = true \/
          (handleAppendEntriesRequest? (state.nodes destination) request).isSome = true) := by
  by_cases recipient : request.destination = destination
  · simp only [handleReceive?, taken, Message.destination, recipient, true_and]
    cases returned : returnToFollowerState? (state.nodes destination) request <;>
      cases handled : handleAppendEntriesRequest? (state.nodes destination) request <;>
      simp
  · simp [handleReceive?, taken, Message.destination, recipient]

theorem enabled_correct (frame : Frame N T) (state : State N T) (rep : frame.Rep state)
    (source destination : N) (request : AppendEntriesRequest N T)
    (payload : Log N T)
    (selected : (frame.queues destination source).peek =
      some (.appendEntriesRequest request))
    (samePayload : request.entries = payload.decode) :
    CCFRaft.Enabled state (.receive source destination) <->
      (frame.nodes destination).isSome = true /\
        request.destination = destination /\
          ((request.term = (get frame.nodes destination).currentTerm /\
              ((get frame.nodes destination).role = .candidate \/
                (get frame.nodes destination).role = .preVoteCandidate)) \/
            NativeArrayAppendHandlerCases.Handles
              (get frame.nodes destination) request payload) := by
  obtain ⟨remaining, taken⟩ :=
    NativeArrayVoteReceive.selected_model_take frame state rep source destination
      (.appendEntriesRequest request) selected
  have allocation := allocated_rep frame.nodes state rep.nodes destination
  have fields := get_rep frame.nodes state rep.nodes destination
  have stepDown :
      (returnToFollowerState? (state.nodes destination) request).isSome = true <->
        request.term = (get frame.nodes destination).currentTerm /\
          ((get frame.nodes destination).role = .candidate \/
            (get frame.nodes destination).role = .preVoteCandidate) := by
    rw [<- fields]
    exact return_to_follower_is_some_iff (get frame.nodes destination) request
  have handles :
      (handleAppendEntriesRequest? (state.nodes destination) request).isSome = true <->
        NativeArrayAppendHandlerCases.Handles
          (get frame.nodes destination) request payload := by
    rw [<- fields]
    exact (NativeArrayAppendHandlerCases.handles_iff
      (get frame.nodes destination) request payload samePayload).symm
  simp only [CCFRaft.Enabled]
  rw [<- allocation,
    append_request_receive_is_some state source destination request remaining taken,
    stepDown, handles]

end CCFRaft.NativeArrayAppendReceiveGuard

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayAppendReceiveGuard).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
