-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayVoteState

set_option autoImplicit false

namespace CCFRaft.NativeArrayAppend

open NativeArrayCheckQuorum NativeArrayVote

variable {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]

def batchEntries (log : Log N T) (previous : Nat) : List (Entry N T) :=
  if previous < log.length then [log.entries previous] else []

theorem batch_entries_correct (log : Log N T) (previous : Nat) :
    batchEntries log previous = messageEntries log.decode previous (min (previous + 1) log.length) := by
  by_cases live : previous < log.length
  · have frontier : min (previous + 1) log.length = previous + 1 := Nat.min_eq_left (by omega)
    simp only [batchEntries, if_pos live, messageEntries, frontier, Nat.add_sub_cancel_left]
    apply List.ext_getElem
    · simp [List.length_take, List.length_drop, Log.decode_length, show log.length - previous >= 1 by omega]
    · intro index leftBound rightBound
      have zero : index = 0 := by simpa using leftBound
      subst index
      simp [Log.decode]
  · have frontier : min (previous + 1) log.length = log.length := Nat.min_eq_right (by omega)
    have zero : log.length - previous = 0 := by omega
    simp [batchEntries, live, messageEntries, frontier, zero]

def request (row : Local N T) (source destination : N) : AppendEntriesRequest N T :=
  { term := row.currentTerm
    prevLogIndex := row.sentIndex destination
    prevLogTerm := NativeArrayVote.termAt row.log (row.sentIndex destination)
    entries := batchEntries row.log (row.sentIndex destination)
    leaderCommit := row.commit
    source, destination }

theorem request_correct (arrays : Arrays N T) (state : State N T) (rep : NativeArrayCheckQuorum.Rep arrays state)
    (source destination : N) (batchEnd : Nat)
    (frontier : batchEnd = min ((get arrays source).sentIndex destination + 1) (get arrays source).log.length) :
    request (get arrays source) source destination = makeAppendEntriesRequest state source destination batchEnd := by
  have fields := get_rep arrays state rep source
  rw [frontier]
  simp only [request, makeAppendEntriesRequest, <- fields, Local.toModel,
    batch_entries_correct, NativeArrayVote.term_at_correct]

def enabled (frame : Frame N T) (source destination : N) (batchEnd : Nat) : Prop :=
  let row := get frame.nodes source
  (frame.nodes source).isSome = true /\ (frame.nodes destination).isSome = true /\
    row.role = .leader /\ source ≠ destination /\
    ((exists current, CurrentIndex row.log row.commit current /\ MemberAt row.log current destination) \/
      destination ∈ frame.globals.retirementCompleted source) /\
    batchEnd = min (row.sentIndex destination + 1) row.log.length /\
    (row.membershipState ≠ .retiredCommitted \/ row.sentIndex destination < batchEnd)

theorem enabled_correct (frame : Frame N T) (state : State N T) (rep : frame.Rep state)
    (source destination : N) (batchEnd : Nat) :
    enabled frame source destination batchEnd <-> Enabled state (.appendEntries source destination batchEnd) := by
  have fields := get_rep frame.nodes state rep.nodes source
  have membership := member_at_correct (get frame.nodes source).log
    (get frame.nodes source).toModel destination rfl
  simp only [enabled, Enabled, <- fields, Local.toModel, Log.decode_length,
    <- allocated_rep frame.nodes state rep.nodes, rep.globals, Globals.ofModel]
  simp only [current_index_correct, exists_eq_left', currentConfiguration, Local.toModel] at membership ⊢
  rw [membership]

def send (frame : Frame N T) (source destination : N) (batchEnd : Nat) : Frame N T :=
  { frame with
    nodes := Function.update frame.nodes source (some
      { get frame.nodes source with
        sentIndex := updateIndex (get frame.nodes source).sentIndex destination batchEnd })
    queues := NativeArrayQueue.send frame.queues
      (.appendEntriesRequest (request (get frame.nodes source) source destination)) }

theorem send_rep (frame : Frame N T) (state : State N T) (rep : frame.Rep state)
    (source destination : N) (batchEnd : Nat)
    (frontier : batchEnd = min ((get frame.nodes source).sentIndex destination + 1)
      (get frame.nodes source).log.length) :
    (send frame source destination batchEnd).Rep (CCFRaft.next state (.appendEntries source destination batchEnd)) := by
  constructor
  · intro peer
    by_cases same : peer = source
    · subst peer
      have fields := get_rep frame.nodes state rep.nodes source
      simp [send, CCFRaft.next, State.node?, updateNode, Local.Rep, <- fields, Local.toModel]
    · simpa [send, CCFRaft.next, State.node?, updateNode, same] using rep.nodes peer
  · change NativeArrayQueue.decodeNetwork (NativeArrayQueue.send frame.queues
      (.appendEntriesRequest (request (get frame.nodes source) source destination))) = _
    rw [NativeArrayQueue.model_send_correct frame.queues state.network rep.queues,
      request_correct frame.nodes state rep.nodes source destination batchEnd frontier]
    rfl
  · exact rep.globals

end CCFRaft.NativeArrayAppend

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayAppend).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
