-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayVoteState

set_option autoImplicit false

namespace CCFRaft.NativeArrayAppendResponse

open NativeArrayCheckQuorum NativeArrayVote

variable {N T : Type} [DecidableEq N]

def handlerEnabled (row : Local N T) (response : AppendEntriesResponse N) : Prop :=
  response.success = false \/ response.term <= row.currentTerm \/ row.role ≠ .leader

def nextRow (row : Local N T) (response : AppendEntriesResponse N) : Local N T :=
  if response.success = true /\ response.term = row.currentTerm /\ row.role = .leader then
    { row with
      matchIndex := Function.update row.matchIndex response.source
        (max (row.matchIndex response.source) response.lastLogIndex) }
  else if response.success = false then
    let possible := findHighestPossibleMatch row.log.decode response.lastLogIndex response.term
    { row with
      sentIndex := Function.update row.sentIndex response.source
        (max (min possible (row.sentIndex response.source)) (row.matchIndex response.source)) }
  else row

def enabled (frame : Frame N T) (destination : N)
    (response : AppendEntriesResponse N) : Prop :=
  (frame.nodes destination).isSome = true /\
    response.destination = destination /\
    ((frame.nodes response.source).isSome = true ->
      handlerEnabled (get frame.nodes destination) response)

def receive (frame : Frame N T) (destination : N)
    (response : AppendEntriesResponse N) : Frame N T :=
  { frame with
    nodes := if (frame.nodes response.source).isSome then
      Function.update frame.nodes destination
        (some (nextRow (get frame.nodes destination) response))
      else frame.nodes
    queues := NativeArrayQueue.popSource frame.queues destination response.source }

theorem receive_eq_write_pop (frame : Frame N T) (destination : N)
    (response : AppendEntriesResponse N)
    (destinationPresent : (frame.nodes destination).isSome = true) :
    receive frame destination response =
      { frame with
        nodes := Function.update frame.nodes destination
          (some (if (frame.nodes response.source).isSome then
            nextRow (get frame.nodes destination) response
          else get frame.nodes destination))
        queues :=
          NativeArrayQueue.popSource frame.queues destination response.source } := by
  by_cases sourcePresent : (frame.nodes response.source).isSome = true
  · simp [receive, sourcePresent]
  · have destinationValue :
        frame.nodes destination = some (get frame.nodes destination) := by
      cases destinationSlot : frame.nodes destination with
      | none =>
          simp [destinationSlot] at destinationPresent
      | some row =>
          simp [NativeArrayCheckQuorum.get, destinationSlot]
    have nodesUnchanged :
        Function.update frame.nodes destination
            (some (get frame.nodes destination)) =
          frame.nodes := by
      funext node
      by_cases same : node = destination
      · subst node
        simp [destinationValue]
      · simp [Function.update, same]
    simp [receive, sourcePresent, nodesUnchanged]

omit [DecidableEq N] in
@[simp]
theorem packet_source (response : AppendEntriesResponse N) :
    (Message.appendEntriesResponse response : Message N T).source =
      response.source := by
  rfl

omit [DecidableEq N] in
@[simp]
theorem packet_destination (response : AppendEntriesResponse N) :
    (Message.appendEntriesResponse response : Message N T).destination =
      response.destination := by
  rfl

theorem handler_enabled_correct (row : Local N T)
    (response : AppendEntriesResponse N) :
    handlerEnabled row response <->
      (handleAppendEntriesResponse? row.toModel response).isSome := by
  cases success : response.success
  · simp [handlerEnabled, handleAppendEntriesResponse?, Local.toModel, success]
  · simp [handlerEnabled, success]
    by_cases expected : row.role = .leader
    · by_cases stale : response.term < row.currentTerm
      · have bounded := Nat.le_of_lt stale
        have different : response.term ≠ row.currentTerm := by omega
        simp [handleAppendEntriesResponse?, Local.toModel, success, expected,
          stale, bounded, different]
      · have bound :
          response.term <= row.currentTerm <->
            response.term = row.currentTerm := by
          omega
        rw [bound]
        by_cases same : response.term = row.currentTerm <;>
          simp [handleAppendEntriesResponse?, Local.toModel, success, expected,
            stale, same]
    · simp [handleAppendEntriesResponse?, Local.toModel, success, expected]

theorem handler_correct (row : Local N T)
    (response : AppendEntriesResponse N)
    (allowed : handlerEnabled row response) :
    handleAppendEntriesResponse? row.toModel response =
      some (nextRow row response).toModel := by
  cases success : response.success
  · simp [handlerEnabled, success] at allowed
    simp [handleAppendEntriesResponse?, nextRow, Local.toModel, updateIndex,
      success]
  · simp [handlerEnabled, success] at allowed
    by_cases same : response.term = row.currentTerm
    · by_cases expected : row.role = .leader <;>
        simp [handleAppendEntriesResponse?, nextRow, Local.toModel, updateIndex,
          success, same, expected]
    · by_cases expected : row.role = .leader
      · have stale : response.term < row.currentTerm := by
          rcases allowed with bounded | wrong
          · omega
          · exact False.elim (wrong expected)
        simp [handleAppendEntriesResponse?, nextRow, Local.toModel, success,
          same, expected, stale]
      · simp [handleAppendEntriesResponse?, nextRow, Local.toModel, success,
          same, expected]

variable [DecidableEq T] [Bootstrap N]

theorem enabled_correct (frame : Frame N T) (state : State N T)
    (rep : frame.Rep state) (destination : N)
    (response : AppendEntriesResponse N) (remaining : List (Message N T))
    (taken : takeFirstFrom response.source (state.network destination) =
      some (.appendEntriesResponse response, remaining)) :
    enabled frame destination response <->
      CCFRaft.Enabled state (.receive response.source destination) := by
  have destinationAllocation :=
    allocated_rep frame.nodes state rep.nodes destination
  have sourceAllocation :=
    allocated_rep frame.nodes state rep.nodes response.source
  have fields := get_rep frame.nodes state rep.nodes destination
  have handler :
      handlerEnabled (get frame.nodes destination) response <->
        (handleAppendEntriesResponse? (state.nodes destination) response).isSome := by
    rw [<- fields]
    exact handler_enabled_correct (get frame.nodes destination) response
  simp only [enabled]
  rw [destinationAllocation, sourceAllocation, handler]
  have recipient :
      (Message.appendEntriesResponse response : Message N T).destination =
        response.destination :=
    packet_destination response
  cases handlerResult :
      handleAppendEntriesResponse? (state.nodes destination) response <;>
    simp only [CCFRaft.Enabled, handleReceive?, taken] <;>
    rw [recipient] <;>
    (by_cases destinationPresent : state.allocated destination <;>
      by_cases packetRecipient : response.destination = destination <;>
      by_cases sourcePresent : state.allocated response.source <;>
      simp [handlerResult, destinationPresent, packetRecipient, sourcePresent])

theorem receive_rep (frame : Frame N T) (state : State N T)
    (rep : frame.Rep state) (destination : N)
    (response : AppendEntriesResponse N) (remaining : List (Message N T))
    (taken : takeFirstFrom response.source (state.network destination) =
      some (.appendEntriesResponse response, remaining))
    (allowed : enabled frame destination response) :
    (receive frame destination response).Rep
      (CCFRaft.next state (.receive response.source destination)) := by
  obtain ⟨_, recipient, sourceHandler⟩ := allowed
  subst destination
  have packetRecipient :
      (Message.appendEntriesResponse response : Message N T).destination =
        response.destination :=
    packet_destination response
  have sourceAllocation :=
    allocated_rep frame.nodes state rep.nodes response.source
  cases sourceSlot : frame.nodes response.source with
  | none =>
      have sourceAbsent : Not (state.allocated response.source) := by
        intro present
        have nativePresent := sourceAllocation.mpr present
        simp [sourceSlot] at nativePresent
      have nextState :
          CCFRaft.next state (.receive response.source response.destination) =
            { state with
              network :=
                updateQueue state.network response.destination remaining } := by
        simp only [CCFRaft.next, handleReceive?, taken]
        rw [packetRecipient]
        simp [sourceAbsent]
      rw [nextState]
      constructor
      · intro peer
        simpa [receive, sourceSlot] using rep.nodes peer
      · exact NativeArrayQueue.model_pop_correct frame.queues state.network
          rep.queues response.source response.destination
          (.appendEntriesResponse response) remaining taken
      · exact rep.globals
  | some sourceRow =>
      have sourcePresentNative :
          (frame.nodes response.source).isSome = true := by
        simp [sourceSlot]
      have sourcePresent : state.allocated response.source :=
        sourceAllocation.mp sourcePresentNative
      have fields :=
        get_rep frame.nodes state rep.nodes response.destination
      have handled :=
        handler_correct (get frame.nodes response.destination) response
          (sourceHandler sourcePresentNative)
      rw [fields] at handled
      have nextState :
          CCFRaft.next state (.receive response.source response.destination) =
            { state with
              nodes := updateNode state.nodes response.destination
                (nextRow (get frame.nodes response.destination) response).toModel
              network :=
                updateQueue state.network response.destination remaining } := by
        simp only [CCFRaft.next, handleReceive?, taken]
        rw [packetRecipient]
        simp [sourcePresent, handled]
      rw [nextState]
      constructor
      · intro peer
        by_cases same : peer = response.destination
        · subst peer
          simp [receive, sourceSlot, NativeArrayCheckQuorum.Local.Rep,
            State.node?, updateNode]
        · simpa [receive, sourceSlot, State.node?, updateNode, same] using
            rep.nodes peer
      · exact NativeArrayQueue.model_pop_correct frame.queues state.network
          rep.queues response.source response.destination
          (.appendEntriesResponse response) remaining taken
      · exact rep.globals

end CCFRaft.NativeArrayAppendResponse

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayAppendResponse).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
