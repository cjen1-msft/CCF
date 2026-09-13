-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayVoteState

set_option autoImplicit false

namespace CCFRaft.NativeArrayVoteResponse

open NativeArrayCheckQuorum NativeArrayVote

variable {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]

def packet (preVote : Bool) (response : RequestVoteResponse N) : Message N T :=
  if preVote then
    .requestPreVoteResponse {
      term := response.term, voteGranted := response.voteGranted
      source := response.source, destination := response.destination }
  else .requestVoteResponse response

def handlerEnabled (row : Local N T) (preVote : Bool)
    (response : RequestVoteResponse N) : Prop :=
  response.term <= row.currentTerm \/
    row.role ≠ (if preVote then .preVoteCandidate else .candidate)

def nextRow (row : Local N T) (preVote : Bool)
    (response : RequestVoteResponse N) : Local N T :=
  if response.term = row.currentTerm /\
      row.role = (if preVote then .preVoteCandidate else .candidate) /\
      response.voteGranted = true then
    if preVote then { row with preVotesGranted := insert response.source row.preVotesGranted }
    else { row with votesGranted := insert response.source row.votesGranted }
  else row

def enabled (frame : Frame N T) (preVote : Bool) (destination : N)
    (response : RequestVoteResponse N) : Prop :=
  (frame.nodes destination).isSome = true /\
    response.destination = destination /\
    ((frame.nodes response.source).isSome = true ->
      handlerEnabled (get frame.nodes destination) preVote response)

def receive (frame : Frame N T) (preVote : Bool) (destination : N)
    (response : RequestVoteResponse N) : Frame N T :=
  { frame with
    nodes := if (frame.nodes response.source).isSome then
      Function.update frame.nodes destination
        (some (nextRow (get frame.nodes destination) preVote response))
      else frame.nodes
    queues := NativeArrayQueue.popSource frame.queues destination response.source }

omit [DecidableEq N] [DecidableEq T] [Bootstrap N] in
@[simp]
theorem packet_source (preVote : Bool) (response : RequestVoteResponse N) :
    (packet (T := T) preVote response).source = response.source := by
  cases preVote <;> rfl

omit [DecidableEq N] [DecidableEq T] [Bootstrap N] in
@[simp]
theorem packet_destination (preVote : Bool) (response : RequestVoteResponse N) :
    (packet (T := T) preVote response).destination = response.destination := by
  cases preVote <;> rfl

omit [DecidableEq T] [Bootstrap N] in
theorem handler_enabled_correct (row : Local N T) (preVote : Bool)
    (response : RequestVoteResponse N) :
    handlerEnabled row preVote response <->
      (match packet (T := T) preVote response with
        | .requestVoteResponse vote =>
            handleRequestVoteResponse? row.toModel vote
        | .requestPreVoteResponse vote =>
            handleRequestPreVoteResponse? row.toModel vote
        | _ => none).isSome := by
  cases preVote
  · simp [handlerEnabled, packet]
    by_cases stale : response.term < row.currentTerm
    · have bounded := Nat.le_of_lt stale
      simp [handleRequestVoteResponse?, Local.toModel, stale, bounded]
    · by_cases expected : row.role = .candidate
      · have bound :
          response.term <= row.currentTerm <-> response.term = row.currentTerm := by
          omega
        rw [bound]
        by_cases same : response.term = row.currentTerm <;>
          by_cases granted : response.voteGranted = true <;>
            simp [handleRequestVoteResponse?, Local.toModel, stale, expected, same,
              granted]
      · simp [handleRequestVoteResponse?, Local.toModel, stale, expected]
  · simp [handlerEnabled, packet]
    by_cases stale : response.term < row.currentTerm
    · have bounded := Nat.le_of_lt stale
      simp [handleRequestPreVoteResponse?, Local.toModel, stale, bounded]
    · by_cases expected : row.role = .preVoteCandidate
      · have bound :
          response.term <= row.currentTerm <-> response.term = row.currentTerm := by
          omega
        rw [bound]
        by_cases same : response.term = row.currentTerm <;>
          by_cases granted : response.voteGranted = true <;>
            simp [handleRequestPreVoteResponse?, Local.toModel, stale, expected,
              same, granted]
      · simp [handleRequestPreVoteResponse?, Local.toModel, stale, expected]

omit [DecidableEq T] [Bootstrap N] in
theorem handler_correct (row : Local N T) (preVote : Bool)
    (response : RequestVoteResponse N)
    (allowed : handlerEnabled row preVote response) :
    (match packet (T := T) preVote response with
      | .requestVoteResponse vote =>
          handleRequestVoteResponse? row.toModel vote
      | .requestPreVoteResponse vote =>
          handleRequestPreVoteResponse? row.toModel vote
      | _ => none) =
        some ((nextRow row preVote response).toModel) := by
  cases preVote
  · simp [handlerEnabled] at allowed
    simp [packet]
    by_cases stale : response.term < row.currentTerm
    · have different : response.term ≠ row.currentTerm := by omega
      simp [handleRequestVoteResponse?, nextRow, Local.toModel, stale, different]
    · by_cases expected : row.role = .candidate
      · have same : response.term = row.currentTerm := by
          rcases allowed with bounded | wrong
          · omega
          · exact False.elim (wrong expected)
        by_cases granted : response.voteGranted = true <;>
          simp [handleRequestVoteResponse?, nextRow, Local.toModel, expected, same,
            granted]
      · simp [handleRequestVoteResponse?, nextRow, Local.toModel, stale, expected]
  · simp [handlerEnabled] at allowed
    simp [packet]
    by_cases stale : response.term < row.currentTerm
    · have different : response.term ≠ row.currentTerm := by omega
      simp [handleRequestPreVoteResponse?, nextRow, Local.toModel, stale, different]
    · by_cases expected : row.role = .preVoteCandidate
      · have same : response.term = row.currentTerm := by
          rcases allowed with bounded | wrong
          · omega
          · exact False.elim (wrong expected)
        by_cases granted : response.voteGranted = true <;>
          simp [handleRequestPreVoteResponse?, nextRow, Local.toModel, expected,
            same, granted]
      · simp [handleRequestPreVoteResponse?, nextRow, Local.toModel, stale, expected]

theorem enabled_correct (frame : Frame N T) (state : State N T)
    (rep : frame.Rep state) (preVote : Bool) (destination : N)
    (response : RequestVoteResponse N) (remaining : List (Message N T))
    (taken : takeFirstFrom response.source (state.network destination) =
      some (packet preVote response, remaining)) :
    enabled frame preVote destination response <->
      CCFRaft.Enabled state (.receive response.source destination) := by
  have destinationAllocation :=
    allocated_rep frame.nodes state rep.nodes destination
  have sourceAllocation :=
    allocated_rep frame.nodes state rep.nodes response.source
  have fields := get_rep frame.nodes state rep.nodes destination
  have handler :
      handlerEnabled (get frame.nodes destination) preVote response <->
        (match packet (T := T) preVote response with
          | .requestVoteResponse vote =>
              handleRequestVoteResponse? (state.nodes destination) vote
          | .requestPreVoteResponse vote =>
              handleRequestPreVoteResponse? (state.nodes destination) vote
          | _ => none).isSome := by
    rw [<- fields]
    exact handler_enabled_correct (get frame.nodes destination) preVote response
  simp only [enabled]
  rw [destinationAllocation, sourceAllocation, handler]
  cases preVote
  · have voteRecipient :
        (packet (T := T) false response).destination = response.destination :=
      packet_destination false response
    cases handlerResult :
        handleRequestVoteResponse? (state.nodes destination) response <;>
      simp only [CCFRaft.Enabled, handleReceive?, taken] <;>
      rw [voteRecipient] <;>
      (by_cases destinationPresent : state.allocated destination <;>
        by_cases recipient : response.destination = destination <;>
        by_cases sourcePresent : state.allocated response.source <;>
        simp [packet, handlerResult, destinationPresent, recipient, sourcePresent])
  · have preVoteRecipient :
        (packet (T := T) true response).destination = response.destination :=
      packet_destination true response
    cases handlerResult :
        handleRequestPreVoteResponse? (state.nodes destination)
          { term := response.term
            voteGranted := response.voteGranted
            source := response.source
            destination := response.destination } <;>
      simp only [CCFRaft.Enabled, handleReceive?, taken] <;>
      rw [preVoteRecipient] <;>
      (by_cases destinationPresent : state.allocated destination <;>
        by_cases recipient : response.destination = destination <;>
        by_cases sourcePresent : state.allocated response.source <;>
        simp [packet, handlerResult, destinationPresent, recipient, sourcePresent]) <;>
      cases
          handleRequestPreVoteResponse? (state.nodes destination)
            { term := response.term
              voteGranted := response.voteGranted
              source := response.source
              destination := destination } <;>
      simp

theorem receive_rep (frame : Frame N T) (state : State N T)
    (rep : frame.Rep state) (preVote : Bool) (destination : N)
    (response : RequestVoteResponse N) (remaining : List (Message N T))
    (taken : takeFirstFrom response.source (state.network destination) =
      some (packet preVote response, remaining))
    (allowed : enabled frame preVote destination response) :
    (receive frame preVote destination response).Rep
      (CCFRaft.next state (.receive response.source destination)) := by
  obtain ⟨_, recipient, sourceHandler⟩ := allowed
  subst destination
  have packetRecipient :
      (packet (T := T) preVote response).destination = response.destination :=
    packet_destination preVote response
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
        cases preVote <;>
          simp [packet, sourceAbsent]
      rw [nextState]
      constructor
      · intro peer
        simpa [receive, sourceSlot] using rep.nodes peer
      · exact NativeArrayQueue.model_pop_correct frame.queues state.network
          rep.queues response.source response.destination (packet preVote response)
          remaining taken
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
        handler_correct (get frame.nodes response.destination) preVote response
          (sourceHandler sourcePresentNative)
      rw [fields] at handled
      have nextState :
          CCFRaft.next state (.receive response.source response.destination) =
            { state with
              nodes := updateNode state.nodes response.destination
                (nextRow (get frame.nodes response.destination)
                  preVote response).toModel
              network :=
                updateQueue state.network response.destination remaining } := by
        cases preVote
        · have handledVote :
              handleRequestVoteResponse?
                  (state.nodes response.destination) response =
                some
                  (nextRow (get frame.nodes response.destination)
                    false response).toModel := by
            simpa [packet] using handled
          simp only [CCFRaft.next, handleReceive?, taken]
          rw [packetRecipient]
          simp [packet, sourcePresent, handledVote]
        · have handledPreVote :
              handleRequestPreVoteResponse?
                  (state.nodes response.destination)
                  { term := response.term
                    voteGranted := response.voteGranted
                    source := response.source
                    destination := response.destination } =
                some
                  (nextRow (get frame.nodes response.destination)
                    true response).toModel := by
            simpa [packet] using handled
          simp only [CCFRaft.next, handleReceive?, taken]
          rw [packetRecipient]
          simp [packet, sourcePresent, handledPreVote]
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
          rep.queues response.source response.destination (packet preVote response)
          remaining taken
      · exact rep.globals

end CCFRaft.NativeArrayVoteResponse

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayVoteResponse).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
