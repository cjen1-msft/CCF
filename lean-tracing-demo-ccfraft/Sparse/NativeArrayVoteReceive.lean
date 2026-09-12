-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayVote

set_option autoImplicit false

namespace CCFRaft.NativeArrayVoteReceive

open NativeArrayCheckQuorum NativeArrayVote

variable {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]

def logUpToDate (row : Local N T) (request : RequestVoteRequest N) (signature : Nat) : Prop :=
  NativeArrayVote.termAt row.log signature < request.lastCommittableTerm \/
    (request.lastCommittableTerm = NativeArrayVote.termAt row.log signature /\ signature <= request.lastCommittableIndex)

instance (row : Local N T) (request : RequestVoteRequest N) (signature : Nat) :
    Decidable (logUpToDate row request signature) := by
  unfold logUpToDate
  infer_instance

def grant (row : Local N T) (request : RequestVoteRequest N) (signature : Nat) : Bool :=
  decide (request.term = row.currentTerm /\ logUpToDate row request signature /\
    (row.votedFor = none \/ row.votedFor = some request.source))

def nextRow (row : Local N T) (request : RequestVoteRequest N) (signature : Nat) : Local N T :=
  if grant row request signature then { row with votedFor := some request.source } else row

def response (row : Local N T) (request : RequestVoteRequest N) (signature : Nat) : RequestVoteResponse N :=
  { term := row.currentTerm, voteGranted := grant row request signature,
    source := request.destination, destination := request.source }

theorem log_up_to_date_correct (row : Local N T) (request : RequestVoteRequest N) (signature : Nat)
    (latest : SignatureIndex row.log signature) :
    logUpToDate row request signature <-> voteLogUpToDate row.toModel request := by
  have same := (signature_index_correct row.log signature).mp latest
  simp only [logUpToDate, voteLogUpToDate, maxCommittableTerm, Local.toModel, same,
    NativeArrayVote.term_at_correct]

theorem handler_correct (row : Local N T) (request : RequestVoteRequest N) (signature : Nat)
    (latest : SignatureIndex row.log signature) (notNewer : request.term <= row.currentTerm) :
    handleRequestVoteRequest? row.toModel request =
      some ((nextRow row request signature).toModel, response row request signature) := by
  have freshness := log_up_to_date_correct row request signature latest
  have sameGrant : grant row request signature =
      decide (request.term = row.toModel.currentTerm /\ voteLogUpToDate row.toModel request /\
        (row.toModel.votedFor = none \/ row.toModel.votedFor = some request.source)) := by
    simp only [grant, freshness, Local.toModel]
  simp only [handleRequestVoteRequest?, nextRow, response, sameGrant]
  have bound : request.term <= row.toModel.currentTerm := notNewer
  rw [if_pos bound]
  split <;> rfl

def receive (frame : Frame N T) (destination : N) (request : RequestVoteRequest N) (signature : Nat) : Frame N T :=
  let row := get frame.nodes destination
  { frame with
    nodes := Function.update frame.nodes destination (some (nextRow row request signature))
    queues := NativeArrayQueue.send
      (NativeArrayQueue.popSource frame.queues destination request.source)
      (.requestVoteResponse (response row request signature)) }

theorem enabled_correct (frame : Frame N T) (state : State N T) (rep : frame.Rep state)
    (destination : N) (request : RequestVoteRequest N) (remaining : List (Message N T))
    (taken : takeFirstFrom request.source (state.network destination) =
      some (.requestVoteRequest request, remaining)) :
    CCFRaft.Enabled state (.receive request.source destination) <->
      (frame.nodes destination).isSome = true /\ request.destination = destination /\
        request.term <= (get frame.nodes destination).currentTerm := by
  have allocation := allocated_rep frame.nodes state rep.nodes destination
  have fields := get_rep frame.nodes state rep.nodes destination
  have term : (get frame.nodes destination).currentTerm = (state.nodes destination).currentTerm :=
    congrArg NodeState.currentTerm fields
  by_cases recipient : request.destination = destination
  · by_cases notNewer : request.term <= (state.nodes destination).currentTerm
    all_goals simp [CCFRaft.Enabled, handleReceive?, taken, Message.destination,
      recipient, handleRequestVoteRequest?, notNewer, allocation, term]
  · simp [CCFRaft.Enabled, handleReceive?, taken, Message.destination, recipient]

omit [Bootstrap N] in
theorem selected_model_take (frame : Frame N T) (state : State N T) (rep : frame.Rep state)
    (source destination : N) (message : Message N T)
    (selected : (frame.queues destination source).peek = some message) :
    exists remaining, takeFirstFrom source (state.network destination) = some (message, remaining) := by
  rw [NativeArrayQueue.model_peek_correct frame.queues state.network rep.queues source destination] at selected
  cases taken : takeFirstFrom source (state.network destination) with
  | none => simp [taken] at selected
  | some pair =>
    rcases pair with ⟨packet, remaining⟩
    have same : packet = message := by simpa [taken] using selected
    subst packet
    exact ⟨remaining, rfl⟩

theorem receive_rep (frame : Frame N T) (state : State N T) (rep : frame.Rep state)
    (destination : N) (request : RequestVoteRequest N) (signature : Nat)
    (latest : SignatureIndex (get frame.nodes destination).log signature)
    (notNewer : request.term <= (get frame.nodes destination).currentTerm)
    (recipient : request.destination = destination)
    (remaining : List (Message N T))
    (taken : takeFirstFrom request.source (state.network destination) =
      some (.requestVoteRequest request, remaining)) :
    (receive frame destination request signature).Rep
      (CCFRaft.next state (.receive request.source destination)) := by
  have fields := get_rep frame.nodes state rep.nodes destination
  have handled := handler_correct (get frame.nodes destination) request signature latest notNewer
  rw [fields] at handled
  have nextState :
      CCFRaft.next state (.receive request.source destination) =
        { state with
          nodes := updateNode state.nodes destination
            (nextRow (get frame.nodes destination) request signature).toModel
          network := enqueue (updateQueue state.network destination remaining)
            (.requestVoteResponse (response (get frame.nodes destination) request signature)) } := by
    simp [CCFRaft.next, handleReceive?, taken, Message.destination, recipient, handled]
  rw [nextState]
  constructor
  · intro peer
    by_cases same : peer = destination
    · subst peer
      simp [receive, NativeArrayCheckQuorum.Local.Rep, State.node?, updateNode]
    · simpa [receive, State.node?, updateNode, same] using rep.nodes peer
  · exact NativeArrayQueue.model_send_correct _ _
      (NativeArrayQueue.model_pop_correct frame.queues state.network rep.queues
        request.source destination (.requestVoteRequest request) remaining taken) _
  · exact rep.globals

end CCFRaft.NativeArrayVoteReceive

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayVoteReceive).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
