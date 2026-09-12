-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayAppendReceive

set_option autoImplicit false

namespace CCFRaft.NativeArrayAppendHandler

open NativeArrayAppendReceive NativeArrayCheckQuorum NativeArrayLogWrite NativeArrayVote

variable {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]

def Acceptable (row : Local N T) (request : AppendEntriesRequest N T) : Prop :=
  request.term = row.currentTerm /\
    row.role = .follower /\
    NativeArrayAppendReceive.LogOk row.log request.prevLogIndex request.prevLogTerm /\
    row.commit <= request.prevLogIndex

theorem acceptable_model (row : Local N T) (request : AppendEntriesRequest N T)
    (acceptable : Acceptable row request) :
    request.term = row.toModel.currentTerm /\
      row.toModel.role = .follower /\
      CCFRaft.logOk row.toModel request /\
      request.prevLogIndex >= row.toModel.commitIndex := by
  have logOk := (NativeArrayAppendReceive.log_ok_correct row request).mp acceptable.2.2.1
  simpa only [Local.toModel] using
    And.intro acceptable.1
      (And.intro acceptable.2.1 (And.intro logOk acceptable.2.2.2))

theorem acceptable_not_rejected (row : Local N T) (request : AppendEntriesRequest N T)
    (acceptable : Acceptable row request) :
    Not (request.term < row.toModel.currentTerm \/
      (request.term = row.toModel.currentTerm /\ row.toModel.role = .follower /\
        Not (CCFRaft.logOk row.toModel request))) := by
  have accepted := acceptable_model row request acceptable
  rintro (stale | ⟨_, _, badLog⟩)
  · omega
  · exact badLog accepted.2.2.1

theorem rejected (row : Local N T) (request : AppendEntriesRequest N T) (best : Nat)
    (bestMatch : Sparse.LogMatchSummary.StorageSummary row.log.length request.prevLogIndex best
      (fun position => (row.log.entries position).term <= request.prevLogTerm))
    (rejects : request.term < row.currentTerm \/
      (request.term = row.currentTerm /\ row.role = .follower /\
        Not (NativeArrayAppendReceive.LogOk row.log request.prevLogIndex request.prevLogTerm))) :
    handleAppendEntriesRequest? row.toModel request =
      some (row.toModel, NativeArrayAppendReceive.nackResponse row request best) := by
  rw [handleAppendEntriesRequest?,
    NativeArrayAppendReceive.rejection_success row request best bestMatch rejects]

theorem accepted_already_done (row : Local N T) (request : AppendEntriesRequest N T)
    (payload : Log N T) (signature : Nat) (samePayload : request.entries = payload.decode)
    (acceptable : Acceptable row request)
    (done : NativeArrayLogRanges.AlreadyDone row.log payload request.prevLogIndex)
    (latest : SignatureIndex
      (take row.log (min request.leaderCommit (request.prevLogIndex + payload.length))) signature) :
    handleAppendEntriesRequest? row.toModel request =
      some (({ row with commit := max row.commit signature } : Local N T).toModel,
        { term := row.currentTerm, success := true,
          lastLogIndex := request.prevLogIndex + payload.length,
          source := request.destination, destination := request.source }) := by
  rw [handleAppendEntriesRequest?, rejectAppendEntriesRequest?,
    if_neg (acceptable_not_rejected row request acceptable),
    acceptAppendEntriesRequest?, if_pos]
  · rw [NativeArrayAppendReceive.already_done_success
      row request payload signature samePayload done latest]
  · exact acceptable_model row request acceptable

theorem accepted_no_conflict_extension (row : Local N T) (request : AppendEntriesRequest N T)
    (payload : Log N T) (signature : Nat) (samePayload : request.entries = payload.decode)
    (acceptable : Acceptable row request)
    (extendsLog : NativeArrayLogRanges.NoConflictExtension row.log payload request.prevLogIndex)
    (latest : SignatureIndex
      (take (splice row.log payload request.prevLogIndex)
        (min request.leaderCommit (request.prevLogIndex + payload.length))) signature) :
    handleAppendEntriesRequest? row.toModel request =
      some (({ row with
          log := splice row.log payload request.prevLogIndex
          commit := max row.commit signature } : Local N T).toModel,
        { term := row.currentTerm, success := true,
          lastLogIndex := (splice row.log payload request.prevLogIndex).length,
          source := request.destination, destination := request.source }) := by
  have notDone : Not (NativeArrayLogRanges.AlreadyDone row.log payload request.prevLogIndex) := by
    intro done
    rcases done with empty | ⟨fits, _⟩
    · exact extendsLog.1 empty
    · exact (Nat.not_lt_of_ge fits) extendsLog.2.2.1
  have notDoneModel : Not (CCFRaft.alreadyDone row.toModel request) := by
    rw [<- NativeArrayLogRanges.already_done_correct row request payload samePayload]
    exact notDone
  rw [handleAppendEntriesRequest?, rejectAppendEntriesRequest?,
    if_neg (acceptable_not_rejected row request acceptable),
    acceptAppendEntriesRequest?, if_pos,
    appendEntriesAlreadyDone?, if_neg notDoneModel]
  · rw [NativeArrayAppendReceive.no_conflict_success
      row request payload signature samePayload extendsLog latest]
  · exact acceptable_model row request acceptable

theorem accepted_term_conflict (row : Local N T) (request : AppendEntriesRequest N T)
    (payload : Log N T) (signature : Nat) (samePayload : request.entries = payload.decode)
    (acceptable : Acceptable row request)
    (conflict : NativeArrayLogRanges.HasTermConflict row.log payload request.prevLogIndex)
    (newFollower : row.isNewFollower = true)
    (latest : SignatureIndex
      (take (splice row.log payload request.prevLogIndex)
        (min request.leaderCommit (request.prevLogIndex + payload.length))) signature) :
    handleAppendEntriesRequest? row.toModel request =
      some (({ row with
          log := splice row.log payload request.prevLogIndex
          isNewFollower := false
          commit := max row.commit signature } : Local N T).toModel,
        { term := row.currentTerm, success := true,
          lastLogIndex := (splice row.log payload request.prevLogIndex).length,
          source := request.destination, destination := request.source }) := by
  have previousWithin : request.prevLogIndex <= row.log.length := by
    rcases acceptable.2.2.1 with zero | bounded
    · omega
    · exact bounded.1
  have notDone : Not (NativeArrayLogRanges.AlreadyDone row.log payload request.prevLogIndex) := by
    intro done
    rcases done with empty | ⟨fits, sameTerms⟩
    · exact conflict.1 empty
    · apply conflict.2
      intro index within
      exact sameTerms index (lt_of_lt_of_le within (Nat.min_le_left _ _))
  have notDoneModel : Not (CCFRaft.alreadyDone row.toModel request) := by
    rw [<- NativeArrayLogRanges.already_done_correct row request payload samePayload]
    exact notDone
  have notExtends : Not (NativeArrayLogRanges.NoConflictExtension row.log payload request.prevLogIndex) := by
    intro extendsLog
    apply conflict.2
    intro index within
    have overlapLength :
        min payload.length (row.log.length - request.prevLogIndex) =
          row.log.length - request.prevLogIndex := by
      apply Nat.min_eq_right
      have grows := extendsLog.2.2.1
      omega
    have range := extendsLog.2.2.2 index
    rw [overlapLength] at within
    exact congrArg Entry.term (range within)
  have notExtendsModel : Not (CCFRaft.noConflictExtension row.toModel request) := by
    rw [<- NativeArrayLogRanges.no_conflict_extension_correct row request payload samePayload]
    exact notExtends
  let truncated : Local N T :=
    { row with log := take row.log request.prevLogIndex, isNewFollower := false }
  have truncatedLength : truncated.log.length = request.prevLogIndex := by
    change min request.prevLogIndex row.log.length = request.prevLogIndex
    exact Nat.min_eq_left previousWithin
  have retryExtends :
      NativeArrayLogRanges.NoConflictExtension truncated.log payload request.prevLogIndex := by
    refine ⟨conflict.1, ?_, ?_, ?_⟩
    · exact le_of_eq truncatedLength.symm
    · rw [truncatedLength]
      exact Nat.lt_add_of_pos_right (Nat.pos_of_ne_zero conflict.1)
    · intro index within
      rw [truncatedLength] at within
      omega
  have retryNotDone :
      Not (NativeArrayLogRanges.AlreadyDone truncated.log payload request.prevLogIndex) := by
    intro done
    rcases done with empty | ⟨fits, _⟩
    · exact conflict.1 empty
    · have positive := Nat.pos_of_ne_zero conflict.1
      rw [truncatedLength] at fits
      omega
  have retryNotDoneModel : Not (CCFRaft.alreadyDone truncated.toModel request) := by
    rw [<- NativeArrayLogRanges.already_done_correct truncated request payload samePayload]
    exact retryNotDone
  have sameSplice : splice truncated.log payload request.prevLogIndex =
      splice row.log payload request.prevLogIndex := by
    simp [truncated, splice, take, append, Nat.min_eq_left previousWithin]
  have retryLatest : SignatureIndex
      (take (splice truncated.log payload request.prevLogIndex)
        (min request.leaderCommit (request.prevLogIndex + payload.length))) signature := by
    rwa [sameSplice]
  have truncates :
      conflictAppendEntriesRequest? row.toModel request = some truncated.toModel := by
    simpa only [truncated] using
      NativeArrayLogWrite.conflict_truncation_correct
        row request payload samePayload conflict newFollower
  have retryHandled :
      (match appendEntriesAlreadyDone? truncated.toModel request with
        | some result => some result
        | none => noConflictAppendEntriesRequest? truncated.toModel request) =
        some (({ truncated with
            log := splice truncated.log payload request.prevLogIndex
            commit := max truncated.commit signature } : Local N T).toModel,
          { term := truncated.currentTerm, success := true,
            lastLogIndex := (splice truncated.log payload request.prevLogIndex).length,
            source := request.destination, destination := request.source }) := by
    rw [appendEntriesAlreadyDone?, if_neg retryNotDoneModel,
      NativeArrayAppendReceive.no_conflict_success
        truncated request payload signature samePayload retryExtends retryLatest]
  rw [handleAppendEntriesRequest?, rejectAppendEntriesRequest?,
    if_neg (acceptable_not_rejected row request acceptable),
    acceptAppendEntriesRequest?, if_pos]
  · rw [appendEntriesAlreadyDone?, if_neg notDoneModel]
    simp only
    rw [noConflictAppendEntriesRequest?, if_neg notExtendsModel]
    simp only
    rw [truncates]
    simp only
    calc
      _ = some (({ truncated with
            log := splice truncated.log payload request.prevLogIndex
            commit := max truncated.commit signature } : Local N T).toModel,
          { term := truncated.currentTerm, success := true,
            lastLogIndex := (splice truncated.log payload request.prevLogIndex).length,
            source := request.destination, destination := request.source }) := retryHandled
      _ = _ := by simp only [truncated, sameSplice]
  · exact acceptable_model row request acceptable

end CCFRaft.NativeArrayAppendHandler

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayAppendHandler).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
