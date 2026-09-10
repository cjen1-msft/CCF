-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Model

set_option autoImplicit false

namespace CCFRaft.Sparse.AppendEntriesRanges

variable {N T : Type}

theorem message_entry_at (log : List (Entry N T)) (previous batchEnd index : Nat)
    (positive : 0 < index) (within : index <= batchEnd - previous) :
    entryAt? (messageEntries log previous batchEnd) index =
      entryAt? log (previous + index) := by
  have relative_nonzero : Not (index = 0) := by omega
  have absolute_nonzero : Not (previous + index = 0) := by omega
  have take_bound : index - 1 < batchEnd - previous := by omega
  have position : previous + (index - 1) = previous + index - 1 := by omega
  simp only [entryAt?, if_neg relative_nonzero, if_neg absolute_nonzero,
    messageEntries, List.getElem?_take, if_pos take_bound, List.getElem?_drop, position]

theorem splice_entry_at (log payload : List (Entry N T)) (previous index : Nat)
    (kept : previous <= log.length) (positive : 0 < index) :
    entryAt? (log.take previous ++ payload) (previous + index) =
      entryAt? payload index := by
  have relative_nonzero : Not (index = 0) := by omega
  have absolute_nonzero : Not (previous + index = 0) := by omega
  have kept_length : (log.take previous).length = previous := by
    simp only [List.length_take, Nat.min_eq_left kept]
  have after_length : (log.take previous).length <= previous + index - 1 := by
    rw [kept_length]
    omega
  have position : previous + index - 1 - previous = index - 1 := by omega
  simp only [entryAt?, if_neg absolute_nonzero, if_neg relative_nonzero]
  rw [List.getElem?_append_right after_length, kept_length, position]

theorem accepted_entry_at [DecidableEq N] [DecidableEq T]
    (state : NodeState N T) (request : AppendEntriesRequest N T)
    (allowed : noConflictExtension state request) (index : Nat) (positive : 0 < index) :
    (noConflictAppendEntriesRequest? state request).map
        (fun result => entryAt? result.1.log (request.prevLogIndex + index)) =
      some (entryAt? request.entries index) := by
  have copied := splice_entry_at state.log request.entries request.prevLogIndex index
    allowed.2.1 positive
  simpa only [noConflictAppendEntriesRequest?, if_pos allowed, Option.map_some] using
    congrArg some copied

theorem sent_payload_length_le_one [DecidableEq N] [DecidableEq T] [Bootstrap N]
    (state : State N T) (source destination : N) (batchEnd : Nat)
    (enabled : Enabled state (.appendEntries source destination batchEnd)) :
    (makeAppendEntriesRequest state source destination batchEnd).entries.length <= 1 := by
  have batch := enabled.2.2.2.2.2.1
  have cap : batchEnd <= (state.nodes source).sentIndex destination + 1 := by
    rw [batch]
    exact Nat.min_le_left _ _
  change (messageEntries (state.nodes source).log
    ((state.nodes source).sentIndex destination) batchEnd).length <= 1
  simp only [messageEntries, List.length_take, List.length_drop]
  have bound := Nat.min_le_left
    (batchEnd - (state.nodes source).sentIndex destination)
    ((state.nodes source).log.length - (state.nodes source).sentIndex destination)
  omega

-- The send guard does not constrain packets already present in an arbitrary state.
theorem initial_payload_length (source destination : N) (length : Nat) :
    exists request : AppendEntriesRequest N T,
      request.source = source /\ request.destination = destination /\
        request.entries.length = length := by
  refine Exists.intro
    { term := 0, prevLogIndex := 0, prevLogTerm := 0,
      entries := List.replicate length { term := 0, content := .signature },
      leaderCommit := 0, source, destination } ?_
  simp

end CCFRaft.Sparse.AppendEntriesRanges

run_cmd do
  for theoremName in [
      ``CCFRaft.Sparse.AppendEntriesRanges.message_entry_at,
      ``CCFRaft.Sparse.AppendEntriesRanges.splice_entry_at,
      ``CCFRaft.Sparse.AppendEntriesRanges.accepted_entry_at,
      ``CCFRaft.Sparse.AppendEntriesRanges.sent_payload_length_le_one,
      ``CCFRaft.Sparse.AppendEntriesRanges.initial_payload_length] do
    let axioms <- Lean.collectAxioms theoremName
    for name in axioms do
      unless name == ``propext || name == ``Classical.choice || name == ``Quot.sound do
        throwError "unexpected axiom in {theoremName}: {name}"
  Lean.logInfo "AppendEntries range alignment audit passed."
