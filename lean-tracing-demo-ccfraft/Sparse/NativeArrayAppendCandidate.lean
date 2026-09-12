-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayAppendHandlerCases

set_option autoImplicit false

namespace CCFRaft.NativeArrayAppendCandidate

open NativeArrayAppendHandler NativeArrayAppendHandlerCases
  NativeArrayAppendReceive NativeArrayCheckQuorum NativeArrayLogWrite
  NativeArrayVote

variable {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]

def candidateLog (row : Local N T) (request : AppendEntriesRequest N T)
    (payload : Log N T) (acceptable done : Bool) : Log N T :=
  if acceptable && !done then splice row.log payload request.prevLogIndex else row.log

def candidateRow (row : Local N T) (request : AppendEntriesRequest N T)
    (payload : Log N T) (signature : Nat)
    (acceptable done conflict : Bool) : Local N T :=
  { row with
    log := candidateLog row request payload acceptable done
    commit := if acceptable then max row.commit signature else row.commit
    isNewFollower :=
      if acceptable && !done && conflict then false else row.isNewFollower }

theorem acceptable_previous_le (row : Local N T)
    (request : AppendEntriesRequest N T) (acceptable : Acceptable row request) :
    request.prevLogIndex <= row.log.length := by
  rcases acceptable.2.2.1 with zero | bounded
  · omega
  · exact bounded.1

theorem no_conflict_extension_not_done (row : Local N T)
    (request : AppendEntriesRequest N T) (payload : Log N T)
    (extendsLog :
      NativeArrayLogRanges.NoConflictExtension row.log payload request.prevLogIndex) :
    Not (NativeArrayLogRanges.AlreadyDone row.log payload request.prevLogIndex) := by
  intro done
  rcases done with empty | ⟨fits, _⟩
  · exact extendsLog.1 empty
  · exact (Nat.not_lt_of_ge fits) extendsLog.2.2.1

theorem term_conflict_not_done (row : Local N T)
    (request : AppendEntriesRequest N T) (payload : Log N T)
    (conflict :
      NativeArrayLogRanges.HasTermConflict row.log payload request.prevLogIndex) :
    Not (NativeArrayLogRanges.AlreadyDone row.log payload request.prevLogIndex) := by
  intro done
  rcases done with empty | ⟨_, sameTerms⟩
  · exact conflict.1 empty
  · apply conflict.2
    intro index within
    exact sameTerms index (lt_of_lt_of_le within (Nat.min_le_left _ _))

theorem no_conflict_extension_not_term_conflict (row : Local N T)
    (request : AppendEntriesRequest N T) (payload : Log N T)
    (extendsLog :
      NativeArrayLogRanges.NoConflictExtension row.log payload request.prevLogIndex) :
    Not (NativeArrayLogRanges.HasTermConflict row.log payload request.prevLogIndex) := by
  intro conflict
  apply conflict.2
  intro index within
  have overlapLength :
      min payload.length (row.log.length - request.prevLogIndex) =
        row.log.length - request.prevLogIndex := by
    apply Nat.min_eq_right
    have previousWithin := extendsLog.2.1
    have grows := extendsLog.2.2.1
    omega
  rw [overlapLength] at within
  simpa only [id_eq, zero_add] using
    congrArg Entry.term (extendsLog.2.2.2 index within)

theorem splice_length_of_acceptable (row : Local N T)
    (request : AppendEntriesRequest N T) (payload : Log N T)
    (acceptable : Acceptable row request) :
    (splice row.log payload request.prevLogIndex).length =
      request.prevLogIndex + payload.length := by
  simp [splice, append, take, Nat.min_eq_left
    (acceptable_previous_le row request acceptable)]

theorem acceptable_not_native_rejected (row : Local N T)
    (request : AppendEntriesRequest N T) (acceptable : Acceptable row request) :
    Not (request.term < row.currentTerm \/
      (request.term = row.currentTerm /\ row.role = .follower /\
        Not (LogOk row.log request.prevLogIndex request.prevLogTerm))) := by
  rintro (stale | ⟨_, _, badLog⟩)
  · exact (Nat.ne_of_lt stale) acceptable.1
  · exact badLog acceptable.2.2.1

theorem step_down_not_acceptable (row : Local N T)
    (request : AppendEntriesRequest N T)
    (stepDown : request.term = row.currentTerm /\
      (row.role = .candidate \/ row.role = .preVoteCandidate)) :
    Not (Acceptable row request) := by
  intro acceptable
  rcases stepDown.2 with candidate | candidate <;>
    rw [acceptable.2.1] at candidate <;> contradiction

theorem acceptable_false_of_step_down (row : Local N T)
    (request : AppendEntriesRequest N T) (acceptable : Bool)
    (sameAcceptable : acceptable = true <-> Acceptable row request)
    (stepDown : request.term = row.currentTerm /\
      (row.role = .candidate \/ row.role = .preVoteCandidate)) :
    acceptable = false := by
  apply Bool.eq_false_iff.mpr
  intro accepted
  exact step_down_not_acceptable row request stepDown
    (sameAcceptable.mp accepted)

theorem candidate_row_of_step_down (row : Local N T)
    (request : AppendEntriesRequest N T) (payload : Log N T)
    (signature : Nat) (acceptable done conflict : Bool)
    (sameAcceptable : acceptable = true <-> Acceptable row request)
    (stepDown : request.term = row.currentTerm /\
      (row.role = .candidate \/ row.role = .preVoteCandidate)) :
    candidateRow row request payload signature acceptable done conflict = row := by
  have acceptableFalse :=
    acceptable_false_of_step_down row request acceptable sameAcceptable stepDown
  simp [candidateRow, candidateLog, acceptableFalse]

theorem candidate_handler_result {N T : Type} [DecidableEq N] [DecidableEq T]
    [Bootstrap N]
    (row : Local N T) (request : AppendEntriesRequest N T) (payload : Log N T)
    (signature : Nat) (acceptable done conflict : Bool)
    (samePayload : request.entries = payload.decode)
    (sameAcceptable : acceptable = true <-> Acceptable row request)
    (sameDone : done = true <->
      NativeArrayLogRanges.AlreadyDone row.log payload request.prevLogIndex)
    (sameConflict : conflict = true <->
      NativeArrayLogRanges.HasTermConflict row.log payload request.prevLogIndex)
    (latest : acceptable = true ->
      SignatureIndex
        (take (candidateLog row request payload acceptable done)
          (min request.leaderCommit (request.prevLogIndex + payload.length)))
        signature)
    (handles : Handles row request payload) :
    handleAppendEntriesRequest? row.toModel request =
      some ((candidateRow row request payload signature acceptable done conflict).toModel,
        if acceptable then
          successResponse row.toModel request (request.prevLogIndex + payload.length)
        else
          failureResponse row.toModel request) := by
  rcases handles with rejects |
      ⟨accepted, alreadyDone | extendsLog | ⟨termConflict, newFollower⟩⟩
  · have acceptableFalse : acceptable = false := by
      apply Bool.eq_false_iff.mpr
      intro enabled
      exact (acceptable_not_native_rejected row request
        (sameAcceptable.mp enabled)) rejects
    let best := findHighestPossibleMatch row.log.decode
      request.prevLogIndex request.prevLogTerm
    have bestMatch : Sparse.LogMatchSummary.StorageSummary
        row.log.length request.prevLogIndex best
        (fun position => (row.log.entries position).term <= request.prevLogTerm) := by
      apply (nack_match_correct row.log request.prevLogIndex request.prevLogTerm best).mpr
      rfl
    rw [NativeArrayAppendHandler.rejected row request best bestMatch rejects,
      nack_response_correct row request best bestMatch]
    simp [candidateRow, candidateLog, acceptableFalse]
  · have acceptableTrue : acceptable = true := sameAcceptable.mpr accepted
    have doneTrue : done = true := sameDone.mpr alreadyDone
    have latestOld :
        SignatureIndex
          (take row.log
            (min request.leaderCommit (request.prevLogIndex + payload.length)))
          signature := by
      simpa [candidateLog, acceptableTrue, doneTrue] using latest acceptableTrue
    rw [NativeArrayAppendHandler.accepted_already_done row request payload signature
      samePayload accepted alreadyDone latestOld]
    simp [candidateRow, candidateLog, acceptableTrue, doneTrue,
      successResponse, Local.toModel]
  · have acceptableTrue : acceptable = true := sameAcceptable.mpr accepted
    have doneFalse : done = false := by
      apply Bool.eq_false_iff.mpr
      intro doneTrue
      exact no_conflict_extension_not_done row request payload extendsLog
        (sameDone.mp doneTrue)
    have conflictFalse : conflict = false := by
      apply Bool.eq_false_iff.mpr
      intro conflictTrue
      exact no_conflict_extension_not_term_conflict row request payload extendsLog
        (sameConflict.mp conflictTrue)
    have latestSpliced :
        SignatureIndex
          (take (splice row.log payload request.prevLogIndex)
            (min request.leaderCommit (request.prevLogIndex + payload.length)))
          signature := by
      simpa [candidateLog, acceptableTrue, doneFalse] using latest acceptableTrue
    have spliceLength :=
      splice_length_of_acceptable row request payload accepted
    rw [NativeArrayAppendHandler.accepted_no_conflict_extension row request payload
      signature samePayload accepted extendsLog latestSpliced]
    simp [candidateRow, candidateLog, acceptableTrue, doneFalse, conflictFalse,
      successResponse, Local.toModel, spliceLength]
  · have acceptableTrue : acceptable = true := sameAcceptable.mpr accepted
    have doneFalse : done = false := by
      apply Bool.eq_false_iff.mpr
      intro doneTrue
      exact term_conflict_not_done row request payload termConflict
        (sameDone.mp doneTrue)
    have conflictTrue : conflict = true := sameConflict.mpr termConflict
    have latestSpliced :
        SignatureIndex
          (take (splice row.log payload request.prevLogIndex)
            (min request.leaderCommit (request.prevLogIndex + payload.length)))
          signature := by
      simpa [candidateLog, acceptableTrue, doneFalse] using latest acceptableTrue
    have spliceLength :=
      splice_length_of_acceptable row request payload accepted
    rw [NativeArrayAppendHandler.accepted_term_conflict row request payload signature
      samePayload accepted termConflict newFollower latestSpliced]
    simp [candidateRow, candidateLog, acceptableTrue, doneFalse, conflictTrue,
      successResponse, Local.toModel, spliceLength]

end CCFRaft.NativeArrayAppendCandidate

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayAppendCandidate).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
