-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayLogRanges

set_option autoImplicit false

namespace CCFRaft.NativeArrayLogWrite

open NativeArrayCheckQuorum

variable {N T : Type}

def take (log : Log N T) (count : Nat) : Log N T :=
  { log with length := min count log.length }

def append (left right : Log N T) : Log N T :=
  { length := left.length + right.length
    entries := fun index => if index < left.length then left.entries index else right.entries (index - left.length) }

def splice (log payload : Log N T) (previous : Nat) : Log N T :=
  append (take log previous) payload

theorem take_correct (log : Log N T) (count : Nat) :
    (take log count).decode = log.decode.take count := by
  apply List.ext_getElem
  · simp [take, Log.decode]
  · intro index within otherWithin
    simp [take, Log.decode]

theorem append_correct (left right : Log N T) :
    (append left right).decode = left.decode ++ right.decode := by
  apply List.ext_getElem
  · simp [append, Log.decode]
  · intro index within otherWithin
    by_cases inLeft : index < left.length
    · have live : index < left.decode.length := by simpa [Log.decode] using inLeft
      rw [List.getElem_append_left live]
      simp [append, Log.decode, inLeft]
    · have afterLeft : left.decode.length <= index := by simpa [Log.decode] using (by omega : left.length <= index)
      rw [List.getElem_append_right afterLeft]
      simp [append, Log.decode, inLeft]

theorem splice_correct (log payload : Log N T) (previous : Nat) :
    (splice log payload previous).decode = log.decode.take previous ++ payload.decode := by
  rw [splice, append_correct, take_correct]

theorem splice_prefix (log payload : Log N T) (previous index : Nat)
    (within : index < min previous log.length) :
    (splice log payload previous).entries index = log.entries index := by
  simp only [splice, append, take, if_pos within]

theorem splice_payload (log payload : Log N T) (previous index : Nat) :
    (splice log payload previous).entries (min previous log.length + index) = payload.entries index := by
  simp only [splice, append, take,
    if_neg (by omega : Not (min previous log.length + index < min previous log.length)),
    Nat.add_sub_cancel_left]

theorem conflict_truncation_correct [DecidableEq N] [DecidableEq T]
    (row : Local N T) (request : AppendEntriesRequest N T) (payload : Log N T)
    (samePayload : request.entries = payload.decode)
    (conflict : NativeArrayLogRanges.HasTermConflict row.log payload request.prevLogIndex)
    (newFollower : row.isNewFollower = true) :
    conflictAppendEntriesRequest? row.toModel request =
      some ({ row with log := take row.log request.prevLogIndex, isNewFollower := false }.toModel) := by
  have conflictModel := (NativeArrayLogRanges.term_conflict_correct row request payload samePayload).mp conflict
  rw [conflictAppendEntriesRequest?, if_pos ⟨conflictModel, newFollower⟩]
  simp [Local.toModel, take_correct]

end CCFRaft.NativeArrayLogWrite

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayLogWrite).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
