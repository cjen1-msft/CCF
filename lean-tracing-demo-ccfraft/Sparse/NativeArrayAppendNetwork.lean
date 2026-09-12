-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayAppendHandlerCases
import Sparse.NativeArrayVoteReceive

set_option autoImplicit false

namespace CCFRaft.NativeArrayAppendNetwork

open NativeArrayAppendReceive NativeArrayCheckQuorum NativeArrayVote

variable {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]

structure SelectedAppend (frame : Frame N T) (source destination : N)
    (request : AppendEntriesRequest N T) : Prop where
  head : (frame.queues destination source).peek = some (.appendEntriesRequest request)
  destinationAllocated : (frame.nodes destination).isSome = true
  sourceHeader : request.source = source
  destinationHeader : request.destination = destination

def stepDownAppend (frame : Frame N T) (destination : N) : Frame N T :=
  { frame with
    nodes := Function.update frame.nodes destination
      (some { get frame.nodes destination with role := .follower, isNewFollower := true }) }

def consumeAppend (frame : Frame N T) (source destination : N)
    (refreshed : Local N T) (response : AppendEntriesResponse N) (completed : Finset N) :
    Frame N T :=
  { frame with
    nodes := Function.update frame.nodes destination (some refreshed)
    queues := NativeArrayQueue.send
      (NativeArrayQueue.popSource frame.queues destination source)
      (.appendEntriesResponse response)
    globals :=
      { frame.globals with
        retirementCompleted :=
          Function.update frame.globals.retirementCompleted destination completed } }

omit [Bootstrap N] in
theorem successful_handler_excludes_stepdown (row : Local N T)
    (request : AppendEntriesRequest N T) (nextNode : NodeState N T)
    (response : AppendEntriesResponse N)
    (handled : handleAppendEntriesRequest? row.toModel request = some (nextNode, response)) :
    returnToFollowerState? row.toModel request = none := by
  by_cases stepsDown :
      request.term = row.currentTerm /\
        (row.role = .candidate \/ row.role = .preVoteCandidate)
  · rcases stepsDown with ⟨sameTerm, candidate⟩
    have notFollower : row.role ≠ .follower := by
      rcases candidate with candidate | candidate <;> simp [candidate]
    simp [handleAppendEntriesRequest?, rejectAppendEntriesRequest?,
      acceptAppendEntriesRequest?, Local.toModel, sameTerm, notFollower] at handled
  · simp [returnToFollowerState?, Local.toModel, stepsDown]

theorem step_down_append_rep (frame : Frame N T) (state : State N T)
    (rep : frame.Rep state) (source destination : N)
    (request : AppendEntriesRequest N T)
    (selected : SelectedAppend frame source destination request)
    (sameTerm : request.term = (get frame.nodes destination).currentTerm)
    (candidate : (get frame.nodes destination).role = .candidate \/
      (get frame.nodes destination).role = .preVoteCandidate) :
    (stepDownAppend frame destination).Rep
      (CCFRaft.next state (.receive source destination)) := by
  obtain ⟨remaining, taken⟩ :=
    NativeArrayVoteReceive.selected_model_take frame state rep source destination
      (.appendEntriesRequest request) selected.head
  have fields := get_rep frame.nodes state rep.nodes destination
  have modelTerm : request.term = (state.nodes destination).currentTerm := by
    rw [<- fields]
    exact sameTerm
  have modelCandidate :
      (state.nodes destination).role = .candidate \/
        (state.nodes destination).role = .preVoteCandidate := by
    rw [<- fields]
    exact candidate
  have steppedFields :
      ({ get frame.nodes destination with
          role := .follower
          isNewFollower := true } : Local N T).toModel =
        { state.nodes destination with
          role := .follower
          isNewFollower := true } := by
    change
      { (get frame.nodes destination).toModel with
          role := .follower
          isNewFollower := true } =
        { state.nodes destination with
          role := .follower
          isNewFollower := true }
    exact congrArg
      (fun row : NodeState N T => { row with role := .follower, isNewFollower := true })
      fields
  have nextState :
      CCFRaft.next state (.receive source destination) =
        { state with
          nodes := updateNode state.nodes destination
            ({ state.nodes destination with
              role := .follower
              isNewFollower := true }) } := by
    simp [CCFRaft.next, handleReceive?, taken, Message.destination, selected.destinationHeader,
      returnToFollowerState?, modelTerm, modelCandidate]
  rw [nextState]
  constructor
  · intro peer
    by_cases same : peer = destination
    · subst peer
      simpa [stepDownAppend, NativeArrayCheckQuorum.Local.Rep, State.node?,
        updateNode] using steppedFields
    · simpa [stepDownAppend, State.node?, updateNode, same] using rep.nodes peer
  · exact rep.queues
  · exact rep.globals

theorem consume_append_rep (frame : Frame N T) (state : State N T)
    (rep : frame.Rep state) (source destination : N)
    (request : AppendEntriesRequest N T)
    (selected : SelectedAppend frame source destination request)
    (nextNode : NodeState N T) (response : AppendEntriesResponse N)
    (handled : handleAppendEntriesRequest? (get frame.nodes destination).toModel request =
      some (nextNode, response))
    (refreshed : Local N T)
    (refreshedCorrect :
      refreshed.toModel = refreshRetirementState destination nextNode)
    (completed : Finset N)
    (completedCorrect :
      completed = retirementCompletedNodes nextNode.log nextNode.commitIndex) :
    (consumeAppend frame source destination refreshed response completed).Rep
      (CCFRaft.next state (.receive source destination)) := by
  obtain ⟨remaining, taken⟩ :=
    NativeArrayVoteReceive.selected_model_take frame state rep source destination
      (.appendEntriesRequest request) selected.head
  have fields := get_rep frame.nodes state rep.nodes destination
  have handledModel :
      handleAppendEntriesRequest? (state.nodes destination) request =
        some (nextNode, response) := by
    rw [<- fields]
    exact handled
  have noStepdown :
      returnToFollowerState? (state.nodes destination) request = none := by
    rw [<- fields]
    exact successful_handler_excludes_stepdown
      (get frame.nodes destination) request nextNode response handled
  let refreshedNode := refreshRetirementState destination nextNode
  have nextState :
      CCFRaft.next state (.receive source destination) =
        { state with
          nodes := updateNode state.nodes destination refreshedNode
          network := reply state.network destination remaining response
          retirementCompleted :=
            refreshRetirementCompleted state.retirementCompleted destination refreshedNode } := by
    simp [CCFRaft.next, handleReceive?, taken, Message.destination, selected.destinationHeader,
      noStepdown, handledModel, refreshedNode]
  rw [nextState]
  constructor
  · intro peer
    by_cases same : peer = destination
    · subst peer
      simp [consumeAppend, NativeArrayCheckQuorum.Local.Rep, State.node?, updateNode,
        refreshedNode, refreshedCorrect]
    · simpa [consumeAppend, State.node?, updateNode, same] using rep.nodes peer
  · change NativeArrayQueue.decodeNetwork
      (NativeArrayQueue.send
        (NativeArrayQueue.popSource frame.queues destination source)
        (.appendEntriesResponse response)) = _
    rw [NativeArrayQueue.model_send_correct _ _
      (NativeArrayQueue.model_pop_correct frame.queues state.network rep.queues
        source destination (.appendEntriesRequest request) remaining taken)]
    rfl
  · simp only [consumeAppend]
    rw [rep.globals]
    simp [NativeArrayVote.Globals.ofModel, refreshRetirementCompleted,
      refreshedNode, completedCorrect]

end CCFRaft.NativeArrayAppendNetwork

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayAppendNetwork).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
