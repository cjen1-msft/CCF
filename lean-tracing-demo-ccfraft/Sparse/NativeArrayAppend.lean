-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayVoteState
import Sparse.TraceEnabled

set_option autoImplicit false

namespace CCFRaft.NativeArrayAppend

open NativeArrayCheckQuorum NativeArrayVote

variable {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]

def batchEntries (log : Log N T) (previous batchEnd : Nat) : List (Entry N T) :=
  if previous < log.length /\ previous < batchEnd then [log.entries previous] else []

theorem batch_entries_correct (log : Log N T) (previous batchEnd : Nat)
    (allowed : appendBatchAllowed previous log.length batchEnd) :
    batchEntries log previous batchEnd = messageEntries log.decode previous batchEnd := by
  have cap := allowed.2.trans (Nat.min_le_left (previous + 1) log.length)
  have within := allowed.2.trans (Nat.min_le_right (previous + 1) log.length)
  by_cases live : previous < batchEnd
  · have frontier : batchEnd = previous + 1 := by omega
    have physical : previous < log.length := by omega
    rw [batchEntries, if_pos (And.intro physical live)]
    simp only [messageEntries, frontier, Nat.add_sub_cancel_left]
    apply List.ext_getElem
    · simp [List.length_take, List.length_drop, Log.decode_length, show log.length - previous >= 1 by omega]
    · intro index leftBound rightBound
      have zero : index = 0 := by simpa using leftBound
      subst index
      simp [Log.decode]
  · have zero : batchEnd - previous = 0 := by omega
    simp [batchEntries, live, messageEntries, zero]

def request (row : Local N T) (source destination : N) (batchEnd : Nat) :
    AppendEntriesRequest N T :=
  { term := row.currentTerm
    prevLogIndex := row.sentIndex destination
    prevLogTerm := NativeArrayVote.termAt row.log (row.sentIndex destination)
    entries := batchEntries row.log (row.sentIndex destination) batchEnd
    leaderCommit := row.commit
    source, destination }

theorem request_correct (arrays : Arrays N T) (state : State N T) (rep : NativeArrayCheckQuorum.Rep arrays state)
    (source destination : N) (batchEnd : Nat)
    (allowed : appendBatchAllowed ((get arrays source).sentIndex destination)
      (get arrays source).log.length batchEnd) :
    request (get arrays source) source destination batchEnd =
      makeAppendEntriesRequest state source destination batchEnd := by
  have fields := get_rep arrays state rep source
  simp only [request, makeAppendEntriesRequest, <- fields, Local.toModel,
    batch_entries_correct _ _ _ allowed, NativeArrayVote.term_at_correct]

def enabled (frame : Frame N T) (source destination : N) (batchEnd : Nat) : Prop :=
  let row := get frame.nodes source
  (frame.nodes source).isSome = true /\ (frame.nodes destination).isSome = true /\
    row.role = .leader /\ source ≠ destination /\
    ((exists current, CurrentIndex row.log row.commit current /\ MemberAt row.log current destination) \/
      destination ∈ frame.globals.retirementCompleted source) /\
    appendBatchAllowed (row.sentIndex destination) row.log.length batchEnd /\
    (row.membershipState ≠ .retiredCommitted \/ row.sentIndex destination < batchEnd)

theorem enabled_correct (frame : Frame N T) (state : State N T) (rep : frame.Rep state)
    (source destination : N) (batchEnd : Nat) :
    enabled frame source destination batchEnd <-> TraceEnabled state (.appendEntries source destination batchEnd) := by
  have fields := get_rep frame.nodes state rep.nodes source
  have membership := member_at_correct (get frame.nodes source).log
    (get frame.nodes source).toModel destination rfl
  simp only [enabled, TraceEnabled, <- fields, Local.toModel, Log.decode_length,
    <- allocated_rep frame.nodes state rep.nodes, rep.globals, Globals.ofModel]
  simp only [current_index_correct, exists_eq_left', currentConfiguration, Local.toModel] at membership ⊢
  rw [membership]

def send (frame : Frame N T) (source destination : N) (batchEnd : Nat) : Frame N T :=
  { frame with
    nodes := Function.update frame.nodes source (some
      { get frame.nodes source with
        sentIndex := updateIndex (get frame.nodes source).sentIndex destination batchEnd })
    queues := NativeArrayQueue.send frame.queues
      (.appendEntriesRequest (request (get frame.nodes source) source destination batchEnd)) }

theorem send_rep (frame : Frame N T) (state : State N T) (rep : frame.Rep state)
    (source destination : N) (batchEnd : Nat)
    (allowed : appendBatchAllowed ((get frame.nodes source).sentIndex destination)
      (get frame.nodes source).log.length batchEnd) :
    (send frame source destination batchEnd).Rep (CCFRaft.next state (.appendEntries source destination batchEnd)) := by
  constructor
  · intro peer
    by_cases same : peer = source
    · subst peer
      have fields := get_rep frame.nodes state rep.nodes source
      simp [send, CCFRaft.next, State.node?, updateNode, Local.Rep, <- fields, Local.toModel]
    · simpa [send, CCFRaft.next, State.node?, updateNode, same] using rep.nodes peer
  · change NativeArrayQueue.decodeNetwork (NativeArrayQueue.send frame.queues
      (.appendEntriesRequest (request (get frame.nodes source) source destination batchEnd))) = _
    rw [NativeArrayQueue.model_send_correct frame.queues state.network rep.queues,
      request_correct frame.nodes state rep.nodes source destination batchEnd allowed]
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
