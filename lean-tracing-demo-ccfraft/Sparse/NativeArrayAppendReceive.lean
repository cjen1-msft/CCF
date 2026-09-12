-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayLogWrite
import Sparse.NativeArrayVoteState
import Sparse.LogMatchSummary

set_option autoImplicit false

namespace CCFRaft.NativeArrayAppendReceive

open NativeArrayCheckQuorum NativeArrayVote NativeArrayLogWrite

variable {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]

theorem bounded_signature_correct (log : Log N T) (limit index : Nat) :
    SignatureIndex (take log limit) index <-> maxCommittableIndexUpTo log.decode limit = index := by
  rw [signature_index_correct, take_correct]
  simp [maxCommittableIndexUpTo]

theorem committed_from_leader_correct (row : Local N T) (request : AppendEntriesRequest N T)
    (payload newLog : Log N T) (signature : Nat) (samePayload : request.entries = payload.decode)
    (latest : SignatureIndex (take newLog (min request.leaderCommit (request.prevLogIndex + payload.length))) signature) :
    max row.commit signature = committedFromLeader row.toModel request newLog.decode := by
  have same := (bounded_signature_correct newLog _ signature).mp latest
  simp only [committedFromLeader, Local.toModel, samePayload, Log.decode_length, same]

theorem already_done_success (row : Local N T) (request : AppendEntriesRequest N T)
    (payload : Log N T) (signature : Nat) (samePayload : request.entries = payload.decode)
    (done : NativeArrayLogRanges.AlreadyDone row.log payload request.prevLogIndex)
    (latest : SignatureIndex (take row.log (min request.leaderCommit (request.prevLogIndex + payload.length))) signature) :
    appendEntriesAlreadyDone? row.toModel request =
      some (({ row with commit := max row.commit signature } : Local N T).toModel,
        { term := row.currentTerm, success := true, lastLogIndex := request.prevLogIndex + payload.length,
          source := request.destination, destination := request.source }) := by
  have accepted := (NativeArrayLogRanges.already_done_correct row request payload samePayload).mp done
  have committed := committed_from_leader_correct row request payload row.log signature samePayload latest
  rw [appendEntriesAlreadyDone?, if_pos accepted]
  simp only [Local.toModel] at committed ⊢
  rw [<- committed]
  simp [successResponse, samePayload]

theorem no_conflict_success (row : Local N T) (request : AppendEntriesRequest N T)
    (payload : Log N T) (signature : Nat) (samePayload : request.entries = payload.decode)
    (extendsLog : NativeArrayLogRanges.NoConflictExtension row.log payload request.prevLogIndex)
    (latest : SignatureIndex
      (take (splice row.log payload request.prevLogIndex)
        (min request.leaderCommit (request.prevLogIndex + payload.length))) signature) :
    noConflictAppendEntriesRequest? row.toModel request =
      some (({ row with
          log := splice row.log payload request.prevLogIndex
          commit := max row.commit signature } : Local N T).toModel,
        { term := row.currentTerm, success := true,
          lastLogIndex := (splice row.log payload request.prevLogIndex).length,
          source := request.destination, destination := request.source }) := by
  have accepted := (NativeArrayLogRanges.no_conflict_extension_correct row request payload samePayload).mp extendsLog
  have committed := committed_from_leader_correct row request payload (splice row.log payload request.prevLogIndex)
    signature samePayload latest
  rw [noConflictAppendEntriesRequest?, if_pos accepted]
  simp only [samePayload, Local.toModel] at committed ⊢
  rw [<- splice_correct, <- committed]
  simp [successResponse]

omit [DecidableEq N] [DecidableEq T] [Bootstrap N] in
theorem return_to_follower_success (row : Local N T) (request : AppendEntriesRequest N T)
    (sameTerm : request.term = row.currentTerm)
    (candidate : row.role = .candidate \/ row.role = .preVoteCandidate) :
    returnToFollowerState? row.toModel request =
      some (({ row with role := .follower, isNewFollower := true } : Local N T).toModel) := by
  simp [returnToFollowerState?, Local.toModel, sameTerm, candidate]

theorem stepdown_keeps_request (state : State N T) (source destination : N)
    (request : AppendEntriesRequest N T) (remaining : List (Message N T))
    (selected : takeFirstFrom source (state.network destination) = some (.appendEntriesRequest request, remaining))
    (recipient : request.destination = destination)
    (sameTerm : request.term = (state.nodes destination).currentTerm)
    (candidate : (state.nodes destination).role = .candidate \/ (state.nodes destination).role = .preVoteCandidate) :
    (handleReceive? state source destination).map State.network = some state.network := by
  simp [handleReceive?, selected, Message.destination, recipient, returnToFollowerState?, sameTerm, candidate]

theorem nack_match_correct (log : Log N T) (previous threshold best : Nat) :
    Sparse.LogMatchSummary.StorageSummary log.length previous best
      (fun position => (log.entries position).term <= threshold) <->
        findHighestPossibleMatch log.decode previous threshold = best := by
  rw [Sparse.LogMatchSummary.result_iff]
  have entryTerm (candidate : Nat) (positive : 0 < candidate) (within : candidate <= log.length) :
      CCFRaft.termAt log.decode candidate = (log.entries (candidate - 1)).term := by
    have live : candidate - 1 < log.length := by omega
    simp [CCFRaft.termAt, entryAt?, Log.decode, Nat.ne_of_gt positive, live]
  simp only [Sparse.LogMatchSummary.StorageSummary, Sparse.LogMatchSummary.Summary, Log.decode_length]
  constructor
  · rintro ⟨bound, hit, exclusion⟩
    refine ⟨bound, ?_, ?_⟩
    · intro positive
      rw [entryTerm best positive (by omega)]
      exact hit positive
    · intro candidate greater within matched
      apply exclusion (candidate - 1) (by omega) (by omega)
      rw [<- entryTerm candidate (by omega) (by omega)]
      exact matched
  · rintro ⟨bound, hit, exclusion⟩
    refine ⟨bound, ?_, ?_⟩
    · intro positive
      rw [<- entryTerm best positive (by omega)]
      exact hit positive
    · intro position after within matched
      apply exclusion (position + 1) (by omega) (by omega)
      simpa only [entryTerm (position + 1) (by omega) (by omega), Nat.add_sub_cancel] using matched

def nackResponse (row : Local N T) (request : AppendEntriesRequest N T) (best : Nat) :
    AppendEntriesResponse N :=
  let ordinary : AppendEntriesResponse N :=
    { term := row.currentTerm, success := false, lastLogIndex := row.log.length,
      source := request.destination, destination := request.source }
  if request.term < row.currentTerm then ordinary
  else
    let previousTerm :=
      if request.prevLogIndex = 0 then 0
      else if request.prevLogIndex > row.log.length then 0
      else NativeArrayVote.termAt row.log row.log.length
    if previousTerm = 0 then ordinary
    else
      { term := if best = 0 then TERM_ONE else NativeArrayVote.termAt row.log best
        success := false, lastLogIndex := best, source := request.destination, destination := request.source }

theorem nack_response_correct (row : Local N T) (request : AppendEntriesRequest N T) (best : Nat)
    (bestMatch : Sparse.LogMatchSummary.StorageSummary row.log.length request.prevLogIndex best
      (fun position => (row.log.entries position).term <= request.prevLogTerm)) :
    nackResponse row request best = failureResponse row.toModel request := by
  have same := (nack_match_correct row.log request.prevLogIndex request.prevLogTerm best).mp bestMatch
  simp only [nackResponse, failureResponse, Local.toModel, Log.decode_length, same,
    NativeArrayVote.term_at_correct]

def LogOk (log : Log N T) (previous previousTerm : Nat) : Prop :=
  previous = 0 \/ (previous <= log.length /\ NativeArrayVote.termAt log previous = previousTerm)

theorem log_ok_correct (row : Local N T) (request : AppendEntriesRequest N T) :
    LogOk row.log request.prevLogIndex request.prevLogTerm <-> logOk row.toModel request := by
  simp only [LogOk, logOk, Local.toModel, Log.decode_length, NativeArrayVote.term_at_correct]

theorem rejection_success (row : Local N T) (request : AppendEntriesRequest N T) (best : Nat)
    (bestMatch : Sparse.LogMatchSummary.StorageSummary row.log.length request.prevLogIndex best
      (fun position => (row.log.entries position).term <= request.prevLogTerm))
    (rejected : request.term < row.currentTerm \/
      (request.term = row.currentTerm /\ row.role = .follower /\
        Not (LogOk row.log request.prevLogIndex request.prevLogTerm))) :
    rejectAppendEntriesRequest? row.toModel request = some (row.toModel, nackResponse row request best) := by
  have allowed : request.term < row.toModel.currentTerm \/
      (request.term = row.toModel.currentTerm /\ row.toModel.role = .follower /\
        Not (logOk row.toModel request)) := by
    rw [<- log_ok_correct row request]
    exact rejected
  rw [rejectAppendEntriesRequest?, if_pos allowed, nack_response_correct row request best bestMatch]

end CCFRaft.NativeArrayAppendReceive

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayAppendReceive).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
