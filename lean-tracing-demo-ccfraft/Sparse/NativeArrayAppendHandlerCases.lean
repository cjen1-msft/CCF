-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayAppendHandler

set_option autoImplicit false

namespace CCFRaft.NativeArrayAppendHandlerCases

open NativeArrayAppendReceive NativeArrayAppendHandler NativeArrayCheckQuorum
  NativeArrayLogWrite NativeArrayVote

variable {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]

def Handles (row : Local N T) (request : AppendEntriesRequest N T) (payload : Log N T) : Prop :=
  (request.term < row.currentTerm \/
    (request.term = row.currentTerm /\ row.role = .follower /\
      Not (LogOk row.log request.prevLogIndex request.prevLogTerm))) \/
  (Acceptable row request /\
    (NativeArrayLogRanges.AlreadyDone row.log payload request.prevLogIndex \/
      NativeArrayLogRanges.NoConflictExtension row.log payload request.prevLogIndex \/
      (NativeArrayLogRanges.HasTermConflict row.log payload request.prevLogIndex /\
        row.isNewFollower = true)))

theorem handles_iff (row : Local N T) (request : AppendEntriesRequest N T) (payload : Log N T)
    (samePayload : request.entries = payload.decode) :
    Handles row request payload <->
      (CCFRaft.handleAppendEntriesRequest? row.toModel request).isSome = true := by
  constructor
  · rintro (rejects | ⟨acceptable, done | extendsLog | ⟨conflict, newFollower⟩⟩)
    · let best := findHighestPossibleMatch row.log.decode request.prevLogIndex request.prevLogTerm
      have bestMatch : Sparse.LogMatchSummary.StorageSummary
          row.log.length request.prevLogIndex best
          (fun position => (row.log.entries position).term <= request.prevLogTerm) := by
        apply (NativeArrayAppendReceive.nack_match_correct
          row.log request.prevLogIndex request.prevLogTerm best).mpr
        rfl
      rw [NativeArrayAppendHandler.rejected row request best bestMatch rejects]
      rfl
    · let boundedLog :=
        take row.log (min request.leaderCommit (request.prevLogIndex + payload.length))
      let signature := maxCommittableIndex boundedLog.decode
      have latest : SignatureIndex boundedLog signature := by
        apply (signature_index_correct boundedLog signature).mpr
        rfl
      rw [NativeArrayAppendHandler.accepted_already_done
        row request payload signature samePayload acceptable done latest]
      rfl
    · let finalLog := splice row.log payload request.prevLogIndex
      let boundedLog :=
        take finalLog (min request.leaderCommit (request.prevLogIndex + payload.length))
      let signature := maxCommittableIndex boundedLog.decode
      have latest : SignatureIndex boundedLog signature := by
        apply (signature_index_correct boundedLog signature).mpr
        rfl
      rw [NativeArrayAppendHandler.accepted_no_conflict_extension
        row request payload signature samePayload acceptable extendsLog latest]
      rfl
    · let finalLog := splice row.log payload request.prevLogIndex
      let boundedLog :=
        take finalLog (min request.leaderCommit (request.prevLogIndex + payload.length))
      let signature := maxCommittableIndex boundedLog.decode
      have latest : SignatureIndex boundedLog signature := by
        apply (signature_index_correct boundedLog signature).mpr
        rfl
      rw [NativeArrayAppendHandler.accepted_term_conflict
        row request payload signature samePayload acceptable conflict newFollower latest]
      rfl
  · intro handled
    by_cases rejects : request.term < row.currentTerm \/
        (request.term = row.currentTerm /\ row.role = .follower /\
          Not (LogOk row.log request.prevLogIndex request.prevLogTerm))
    · exact Or.inl rejects
    · right
      have notRejectedModel :
          Not (request.term < row.toModel.currentTerm \/
            (request.term = row.toModel.currentTerm /\ row.toModel.role = .follower /\
              Not (CCFRaft.logOk row.toModel request))) := by
        rintro (stale | ⟨sameTerm, follower, badLog⟩)
        · apply rejects
          left
          simpa only [Local.toModel] using stale
        · apply rejects
          right
          refine ⟨?_, ?_, ?_⟩
          · simpa only [Local.toModel] using sameTerm
          · simpa only [Local.toModel] using follower
          · intro logOk
            exact badLog ((NativeArrayAppendReceive.log_ok_correct row request).mp logOk)
      rw [handleAppendEntriesRequest?, rejectAppendEntriesRequest?,
        if_neg notRejectedModel] at handled
      by_cases accepted :
          request.term = row.toModel.currentTerm /\
            row.toModel.role = .follower /\
            CCFRaft.logOk row.toModel request /\
            request.prevLogIndex >= row.toModel.commitIndex
      · have acceptable : Acceptable row request := by
          refine ⟨?_, ?_, ?_, ?_⟩
          · simpa only [Local.toModel] using accepted.1
          · simpa only [Local.toModel] using accepted.2.1
          · exact (NativeArrayAppendReceive.log_ok_correct row request).mpr accepted.2.2.1
          · simpa only [Local.toModel] using accepted.2.2.2
        refine ⟨acceptable, ?_⟩
        rw [acceptAppendEntriesRequest?, if_pos accepted] at handled
        by_cases doneModel : CCFRaft.alreadyDone row.toModel request
        · left
          exact (NativeArrayLogRanges.already_done_correct
            row request payload samePayload).mpr doneModel
        · rw [appendEntriesAlreadyDone?, if_neg doneModel] at handled
          simp only at handled
          by_cases extendsModel : CCFRaft.noConflictExtension row.toModel request
          · right
            left
            exact (NativeArrayLogRanges.no_conflict_extension_correct
              row request payload samePayload).mpr extendsModel
          · rw [noConflictAppendEntriesRequest?, if_neg extendsModel] at handled
            simp only at handled
            by_cases conflictModel :
                CCFRaft.hasTermConflict row.toModel request /\ row.toModel.isNewFollower
            · right
              right
              exact ⟨(NativeArrayLogRanges.term_conflict_correct
                row request payload samePayload).mpr conflictModel.1, conflictModel.2⟩
            · rw [conflictAppendEntriesRequest?, if_neg conflictModel] at handled
              simp at handled
      · rw [acceptAppendEntriesRequest?, if_neg accepted] at handled
        simp at handled

end CCFRaft.NativeArrayAppendHandlerCases

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayAppendHandlerCases).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
