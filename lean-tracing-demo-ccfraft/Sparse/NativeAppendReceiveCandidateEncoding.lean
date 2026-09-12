-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendReceiveCandidateTerms
import Sparse.NativeAppendReceiveTermsEncoding
import Sparse.NativeArrayAppendCandidate
import Sparse.NativeLogSpliceEncoding
import Sparse.NativeLogSummaryEncoding
import Sparse.NativeNodeRowWritesEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem append_receive_candidate_log_rep {width : PNat}
    [Bootstrap (Fin width)]
    (assignment : Assignment) (columns : Columns)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays) (destination : Fin width)
    (packet : Expr (packetTy width))
    (request : AppendEntriesRequest (Fin width) Nat)
    (samePacket :
      packet.eval assignment Locals.empty =
        packetValue (.appendEntriesRequest request))
    (grows : Expr .bool)
    (spliced logEntries : Expr (.array .int (entryTy width)))
    (logLength : Expr .int)
    (sameGrows :
      grows.eval assignment Locals.empty =
        (Term.and
          (appendReceiveTerms columns destination packet).acceptable
          (Term.not (appendReceiveTerms columns destination packet).alreadyDone)).eval
            assignment Locals.empty)
    (spliceAccepted :
      (implies grows
        (let requestPayload := appendRequestPayloadTerm packet
         let entries := requestPayload.snd.snd.snd
         let old := nodeRowSnapshot columns destination
         logSpliceTerm width old.logLength old.logEntries entries.fst entries.snd
           requestPayload.fst spliced)).eval assignment Locals.empty = true)
    (sameLogLength :
      logLength.eval assignment Locals.empty =
        (Term.ite grows
          (let requestPayload := appendRequestPayloadTerm packet
           let entries := requestPayload.snd.snd.snd
           let old := nodeRowSnapshot columns destination
           logSpliceLength old.logLength entries.fst requestPayload.fst)
          (nodeRowSnapshot columns destination).logLength).eval
            assignment Locals.empty)
    (sameLogEntries :
      logEntries.eval assignment Locals.empty =
        (Term.ite grows spliced
          (nodeRowSnapshot columns destination).logEntries).eval
            assignment Locals.empty) :
    let branches := appendReceiveTerms columns destination packet
    let payload := NativeArrayCheckQuorum.Log.ofList request.entries
    let row := NativeArrayCheckQuorum.get arrays destination
    let candidate := NativeArrayAppendCandidate.candidateLog row request payload
      (branches.acceptable.eval assignment Locals.empty)
      (branches.alreadyDone.eval assignment Locals.empty)
    logLength.eval assignment Locals.empty = (candidate.length : Int) /\
      forall index, index < candidate.length ->
        modelEntry (logEntries.eval assignment Locals.empty (index : Int)) =
          candidate.entries index := by
  let branches := appendReceiveTerms columns destination packet
  let requestPayload := appendRequestPayloadTerm packet
  let entries := requestPayload.snd.snd.snd
  let payload := NativeArrayCheckQuorum.Log.ofList request.entries
  let row := NativeArrayCheckQuorum.get arrays destination
  let old := nodeRowSnapshot columns destination
  have oldRep := node_row_snapshot_rep assignment columns arrays rep destination
  have payloadValue :=
    append_request_payload_term_correct packet assignment Locals.empty request samePacket
  have samePrevious : requestPayload.fst.eval assignment Locals.empty =
      (request.prevLogIndex : Int) := by
    simpa [requestPayload, Term.eval] using congrArg Prod.fst payloadValue
  obtain ⟨_, samePayloadLength, samePayloadEntries⟩ :=
    append_request_log_term_correct packet assignment Locals.empty request payload
      samePacket (by
        exact (NativeArrayCheckQuorum.Log.decode_ofList request.entries).symm)
  have sameGrowsValue :
      grows.eval assignment Locals.empty =
        (branches.acceptable.eval assignment Locals.empty &&
          !branches.alreadyDone.eval assignment Locals.empty) := by
    simpa [branches, Term.eval] using sameGrows
  by_cases growsTrue : grows.eval assignment Locals.empty = true
  · have combinedTrue :
        (branches.acceptable.eval assignment Locals.empty &&
          !branches.alreadyDone.eval assignment Locals.empty) = true :=
      sameGrowsValue.symm.trans growsTrue
    have branchTrue :
        branches.acceptable.eval assignment Locals.empty = true /\
          branches.alreadyDone.eval assignment Locals.empty = false := by
      simpa only [Bool.and_eq_true, Bool.not_eq_true'] using combinedTrue
    have acceptableTrue :
        branches.acceptable.eval assignment Locals.empty = true :=
      branchTrue.1
    have doneFalse :
        branches.alreadyDone.eval assignment Locals.empty = false :=
      branchTrue.2
    have spliceHolds :
        (logSpliceTerm width old.logLength old.logEntries entries.fst entries.snd
          requestPayload.fst spliced).eval assignment Locals.empty = true := by
      exact (implies_eval grows
        (logSpliceTerm width old.logLength old.logEntries entries.fst entries.snd
          requestPayload.fst spliced) assignment Locals.empty).mp
            (by simpa [old, requestPayload, entries] using spliceAccepted) growsTrue
    have splicedEntries := log_splice_term_sound assignment Locals.empty
      old.logLength old.logEntries entries.fst entries.snd requestPayload.fst spliced
      row.log payload request.prevLogIndex oldRep.logLength samePayloadLength
      samePrevious oldRep.logEntries samePayloadEntries spliceHolds
    constructor
    · calc
        logLength.eval assignment Locals.empty =
            (logSpliceLength old.logLength entries.fst requestPayload.fst).eval
              assignment Locals.empty := by
                simpa [old, requestPayload, entries, Term.eval, growsTrue] using
                  sameLogLength
        _ = (NativeArrayLogWrite.splice row.log payload request.prevLogIndex).length := by
          rw [log_splice_length_eval, oldRep.logLength, samePayloadLength, samePrevious]
          change min (request.prevLogIndex : Int) (row.log.length : Int) +
              (payload.length : Int) =
            ((min request.prevLogIndex row.log.length + payload.length : Nat) : Int)
          rw [Nat.cast_add, Nat.cast_min]
        _ = (NativeArrayAppendCandidate.candidateLog row request payload
              (branches.acceptable.eval assignment Locals.empty)
              (branches.alreadyDone.eval assignment Locals.empty)).length := by
          simp [branches, NativeArrayAppendCandidate.candidateLog,
            acceptableTrue, doneFalse]
    · intro index live
      have spliceLive :
          index < (NativeArrayLogWrite.splice row.log payload request.prevLogIndex).length := by
        simpa [branches, NativeArrayAppendCandidate.candidateLog,
          acceptableTrue, doneFalse] using live
      calc
        modelEntry (logEntries.eval assignment Locals.empty (index : Int)) =
            modelEntry (spliced.eval assignment Locals.empty (index : Int)) := by
              have selected := congrFun sameLogEntries (index : Int)
              simpa [Term.eval, growsTrue] using congrArg modelEntry selected
        _ = (NativeArrayLogWrite.splice row.log payload request.prevLogIndex).entries index :=
          splicedEntries index spliceLive
        _ = (NativeArrayAppendCandidate.candidateLog row request payload
              (branches.acceptable.eval assignment Locals.empty)
              (branches.alreadyDone.eval assignment Locals.empty)).entries index := by
          simp [branches, NativeArrayAppendCandidate.candidateLog,
            acceptableTrue, doneFalse]
  · have growsFalse : grows.eval assignment Locals.empty = false :=
      Bool.eq_false_iff.mpr growsTrue
    have branchFalse : Not (
        branches.acceptable.eval assignment Locals.empty = true /\
          branches.alreadyDone.eval assignment Locals.empty = false) := by
      rintro ⟨acceptableTrue, doneFalse⟩
      apply growsTrue
      calc
        grows.eval assignment Locals.empty =
            (branches.acceptable.eval assignment Locals.empty &&
              !branches.alreadyDone.eval assignment Locals.empty) := sameGrowsValue
        _ = true := by simp [acceptableTrue, doneFalse]
    constructor
    · calc
        logLength.eval assignment Locals.empty =
            old.logLength.eval assignment Locals.empty := by
              simpa [old, requestPayload, entries, Term.eval, growsFalse] using
                sameLogLength
        _ = (row.log.length : Int) := oldRep.logLength
        _ = (NativeArrayAppendCandidate.candidateLog row request payload
              (branches.acceptable.eval assignment Locals.empty)
              (branches.alreadyDone.eval assignment Locals.empty)).length := by
          simp [branches, NativeArrayAppendCandidate.candidateLog, branchFalse]
    · intro index live
      have oldLive : index < row.log.length := by
        simpa [branches, NativeArrayAppendCandidate.candidateLog, branchFalse] using live
      calc
        modelEntry (logEntries.eval assignment Locals.empty (index : Int)) =
            modelEntry (old.logEntries.eval assignment Locals.empty (index : Int)) := by
              have selected := congrFun sameLogEntries (index : Int)
              simpa [old, Term.eval, growsFalse] using congrArg modelEntry selected
        _ = row.log.entries index := oldRep.logEntries index oldLive
        _ = (NativeArrayAppendCandidate.candidateLog row request payload
              (branches.acceptable.eval assignment Locals.empty)
              (branches.alreadyDone.eval assignment Locals.empty)).entries index := by
          simp [branches, NativeArrayAppendCandidate.candidateLog, branchFalse]

theorem append_receive_candidate_row_terms_rep {width : PNat}
    [Bootstrap (Fin width)]
    (assignment : Assignment) (columns : Columns)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays) (destination : Fin width)
    (packet : Expr (packetTy width))
    (request : AppendEntriesRequest (Fin width) Nat)
    (samePacket :
      packet.eval assignment Locals.empty =
        packetValue (.appendEntriesRequest request))
    (grows : Expr .bool)
    (spliced logEntries : Expr (.array .int (entryTy width)))
    (logLength commitSignature commit : Expr .int)
    (sameGrows :
      grows.eval assignment Locals.empty =
        (Term.and
          (appendReceiveTerms columns destination packet).acceptable
          (Term.not (appendReceiveTerms columns destination packet).alreadyDone)).eval
            assignment Locals.empty)
    (spliceAccepted :
      (implies grows
        (let requestPayload := appendRequestPayloadTerm packet
         let entries := requestPayload.snd.snd.snd
         let old := nodeRowSnapshot columns destination
         logSpliceTerm width old.logLength old.logEntries entries.fst entries.snd
           requestPayload.fst spliced)).eval assignment Locals.empty = true)
    (sameLogLength :
      logLength.eval assignment Locals.empty =
        (Term.ite grows
          (let requestPayload := appendRequestPayloadTerm packet
           let entries := requestPayload.snd.snd.snd
           let old := nodeRowSnapshot columns destination
           logSpliceLength old.logLength entries.fst requestPayload.fst)
          (nodeRowSnapshot columns destination).logLength).eval
            assignment Locals.empty)
    (sameLogEntries :
      logEntries.eval assignment Locals.empty =
        (Term.ite grows spliced
          (nodeRowSnapshot columns destination).logEntries).eval
            assignment Locals.empty)
    (signatureAccepted :
      (implies
        (appendReceiveTerms columns destination packet).acceptable
        (let requestPayload := appendRequestPayloadTerm packet
         let entries := requestPayload.snd.snd.snd
         boundedSignatureTerm width logLength logEntries
           (logRangeMinTerm requestPayload.snd.snd.fst
             (.add requestPayload.fst entries.fst))
           commitSignature)).eval assignment Locals.empty = true)
    (sameCommit :
      commit.eval assignment Locals.empty =
        (Term.ite
          (appendReceiveTerms columns destination packet).acceptable
          (intMaxTerm (nodeRowSnapshot columns destination).commit commitSignature)
          (nodeRowSnapshot columns destination).commit).eval
            assignment Locals.empty) :
    let branches := appendReceiveTerms columns destination packet
    let payload := NativeArrayCheckQuorum.Log.ofList request.entries
    let row := NativeArrayCheckQuorum.get arrays destination
    let acceptable := branches.acceptable.eval assignment Locals.empty
    let done := branches.alreadyDone.eval assignment Locals.empty
    let conflict := branches.conflict.eval assignment Locals.empty
    exists signature : Nat,
      (acceptable = true <->
        NativeArrayAppendHandler.Acceptable row request) /\
      (done = true <->
        NativeArrayLogRanges.AlreadyDone row.log payload request.prevLogIndex) /\
      (conflict = true <->
        NativeArrayLogRanges.HasTermConflict row.log payload request.prevLogIndex) /\
      (acceptable = true ->
        commitSignature.eval assignment Locals.empty = (signature : Int)) /\
      (acceptable = true ->
        NativeArrayVote.SignatureIndex
          (NativeArrayLogWrite.take
            (NativeArrayAppendCandidate.candidateLog row request payload
              acceptable done)
            (min request.leaderCommit (request.prevLogIndex + payload.length)))
          signature) /\
      NodeRowTerms.Rep assignment
        (appendReceiveCandidateRowTerms columns destination packet grows
          logLength logEntries commit)
        (NativeArrayAppendCandidate.candidateRow row request payload signature
          acceptable done conflict) := by
  let branches := appendReceiveTerms columns destination packet
  let requestPayload := appendRequestPayloadTerm packet
  let entries := requestPayload.snd.snd.snd
  let payload := NativeArrayCheckQuorum.Log.ofList request.entries
  let row := NativeArrayCheckQuorum.get arrays destination
  let old := nodeRowSnapshot columns destination
  let acceptable := branches.acceptable.eval assignment Locals.empty
  let done := branches.alreadyDone.eval assignment Locals.empty
  let conflict := branches.conflict.eval assignment Locals.empty
  have oldRep := node_row_snapshot_rep assignment columns arrays rep destination
  have payloadValue :=
    append_request_payload_term_correct packet assignment Locals.empty request samePacket
  have samePrevious : requestPayload.fst.eval assignment Locals.empty =
      (request.prevLogIndex : Int) := by
    simpa [requestPayload, Term.eval] using congrArg Prod.fst payloadValue
  have sameLeaderCommit : requestPayload.snd.snd.fst.eval assignment Locals.empty =
      (request.leaderCommit : Int) := by
    simpa [requestPayload, Term.eval] using
      congrArg (fun value => value.2.2.1) payloadValue
  obtain ⟨_, samePayloadLength, _⟩ :=
    append_request_log_term_correct packet assignment Locals.empty request payload
      samePacket (by
        exact (NativeArrayCheckQuorum.Log.decode_ofList request.entries).symm)
  have candidateLogRep :=
    append_receive_candidate_log_rep assignment columns arrays rep destination packet
      request samePacket grows spliced logEntries logLength sameGrows spliceAccepted
      sameLogLength sameLogEntries
  change logLength.eval assignment Locals.empty =
      (NativeArrayAppendCandidate.candidateLog row request payload
        acceptable done).length /\
    forall index,
      index < (NativeArrayAppendCandidate.candidateLog row request payload
        acceptable done).length ->
      modelEntry (logEntries.eval assignment Locals.empty (index : Int)) =
        (NativeArrayAppendCandidate.candidateLog row request payload
          acceptable done).entries index at candidateLogRep
  have oldRole : old.role.eval assignment Locals.empty = roleCode row.role := by
    simpa [old, row] using oldRep.role
  have oldNewFollower :
      old.newFollower.eval assignment Locals.empty = row.isNewFollower := by
    simpa [old, row] using oldRep.newFollower
  have oldCommit : old.commit.eval assignment Locals.empty = (row.commit : Int) := by
    simpa [old, row] using oldRep.commit
  have oldCurrentTerm :
      old.currentTerm.eval assignment Locals.empty = (row.currentTerm : Int) := by
    simpa [old, row] using oldRep.currentTerm
  have sameGrowsValue :
      grows.eval assignment Locals.empty = (acceptable && !done) := by
    simpa [branches, acceptable, done, Term.eval] using sameGrows
  have acceptableCorrect :
      acceptable = true <-> NativeArrayAppendHandler.Acceptable row request := by
    simpa [acceptable, branches, row] using
      append_receive_acceptable_correct assignment columns arrays rep destination
        packet request samePacket
  have doneCorrect :
      done = true <->
        NativeArrayLogRanges.AlreadyDone row.log payload request.prevLogIndex := by
    simpa [done, branches, row, payload] using
      append_receive_already_done_correct assignment columns arrays rep destination
        packet request payload samePacket
        (NativeArrayCheckQuorum.Log.decode_ofList request.entries).symm
  have conflictCorrect :
      conflict = true <->
        NativeArrayLogRanges.HasTermConflict row.log payload request.prevLogIndex := by
    simpa [conflict, branches, row, payload] using
      append_receive_conflict_correct assignment columns arrays rep destination
        packet request payload samePacket
        (NativeArrayCheckQuorum.Log.decode_ofList request.entries).symm
  have sameCap :
      (logRangeMinTerm requestPayload.snd.snd.fst
        (.add requestPayload.fst entries.fst)).eval assignment Locals.empty =
          (min request.leaderCommit
            (request.prevLogIndex + payload.length) : Nat) := by
    rw [log_range_min_term_eval]
    change min (requestPayload.snd.snd.fst.eval assignment Locals.empty)
        (requestPayload.fst.eval assignment Locals.empty +
          entries.fst.eval assignment Locals.empty) =
      (min request.leaderCommit
        (request.prevLogIndex + payload.length) : Nat)
    rw [sameLeaderCommit, samePrevious, samePayloadLength,
      Nat.cast_min]
    rw [Nat.cast_add]
  have selectedCommit : exists signature : Nat,
      (acceptable = true ->
        commitSignature.eval assignment Locals.empty = (signature : Int)) /\
      (acceptable = true ->
        NativeArrayVote.SignatureIndex
          (NativeArrayLogWrite.take
            (NativeArrayAppendCandidate.candidateLog row request payload
              acceptable done)
            (min request.leaderCommit (request.prevLogIndex + payload.length)))
          signature) /\
      commit.eval assignment Locals.empty =
        ((NativeArrayAppendCandidate.candidateRow row request payload signature
          acceptable done conflict).commit : Int) := by
    by_cases acceptableTrue : acceptable = true
    · have signatureHolds :
          (boundedSignatureTerm width logLength logEntries
            (logRangeMinTerm requestPayload.snd.snd.fst
              (.add requestPayload.fst entries.fst))
            commitSignature).eval assignment Locals.empty = true := by
        exact (implies_eval branches.acceptable
          (boundedSignatureTerm width logLength logEntries
            (logRangeMinTerm requestPayload.snd.snd.fst
              (.add requestPayload.fst entries.fst))
            commitSignature) assignment Locals.empty).mp
              (by simpa [branches, requestPayload, entries] using signatureAccepted)
              acceptableTrue
      obtain ⟨signature, sameSignature, _⟩ :=
        bounded_signature_term_sound assignment Locals.empty logLength logEntries
          (logRangeMinTerm requestPayload.snd.snd.fst
            (.add requestPayload.fst entries.fst))
          commitSignature
          (NativeArrayAppendCandidate.candidateLog row request payload acceptable done)
          (min request.leaderCommit (request.prevLogIndex + payload.length))
          candidateLogRep.1 sameCap candidateLogRep.2 signatureHolds
      have latest :=
        (bounded_signature_term_native_correct assignment Locals.empty
          logLength logEntries
          (logRangeMinTerm requestPayload.snd.snd.fst
            (.add requestPayload.fst entries.fst))
          commitSignature
          (NativeArrayAppendCandidate.candidateLog row request payload acceptable done)
          (min request.leaderCommit (request.prevLogIndex + payload.length))
          signature candidateLogRep.1 sameCap sameSignature candidateLogRep.2).mp
            signatureHolds
      refine ⟨signature, fun _ => sameSignature, fun _ => latest, ?_⟩
      calc
        commit.eval assignment Locals.empty =
            max ((nodeRowSnapshot columns destination).commit.eval
              assignment Locals.empty)
              (commitSignature.eval assignment Locals.empty) := by
          rw [sameCommit]
          simp [branches, acceptable, Term.eval, acceptableTrue, int_max_term_eval]
        _ = (max row.commit signature : Nat) := by
          rw [oldRep.commit, sameSignature, Nat.cast_max]
        _ = (NativeArrayAppendCandidate.candidateRow row request payload signature
              acceptable done conflict).commit := by
          simp [NativeArrayAppendCandidate.candidateRow, acceptableTrue]
    · have acceptableFalse : acceptable = false :=
        Bool.eq_false_iff.mpr acceptableTrue
      refine ⟨0, ?_, ?_, ?_⟩
      · intro impossible
        exact False.elim (acceptableTrue impossible)
      · intro impossible
        exact False.elim (acceptableTrue impossible)
      · calc
          commit.eval assignment Locals.empty =
              (nodeRowSnapshot columns destination).commit.eval
                assignment Locals.empty := by
            rw [sameCommit]
            simp [branches, acceptable, Term.eval, acceptableFalse]
          _ = (row.commit : Int) := oldRep.commit
          _ = (NativeArrayAppendCandidate.candidateRow row request payload 0
                acceptable done conflict).commit := by
            simp [NativeArrayAppendCandidate.candidateRow, acceptableFalse]
  obtain ⟨signature, sameSignature, latest, selectedCommit⟩ := selectedCommit
  refine ⟨signature, acceptableCorrect, doneCorrect, conflictCorrect,
    sameSignature, latest, ?_⟩
  constructor
  · exact oldRole
  · calc
      (appendReceiveCandidateRowTerms columns destination packet grows
          logLength logEntries commit).newFollower.eval assignment Locals.empty =
          if grows.eval assignment Locals.empty && conflict then false
          else old.newFollower.eval assignment Locals.empty := by
        rfl
      _ = if (acceptable && !done) && conflict then false
          else old.newFollower.eval assignment Locals.empty := by
        rw [sameGrowsValue]
      _ = (NativeArrayAppendCandidate.candidateRow row request payload signature
            acceptable done conflict).isNewFollower := by
        rw [oldNewFollower]
        rfl
  · simpa [NativeArrayAppendCandidate.candidateRow] using candidateLogRep.1
  · exact selectedCommit
  · exact oldCurrentTerm
  · intro index live
    exact candidateLogRep.2 index (by
      simpa [NativeArrayAppendCandidate.candidateRow] using live)
  · simpa [appendReceiveCandidateRowTerms,
      NativeArrayAppendCandidate.candidateRow] using oldRep.retirementIndex
  · simpa [appendReceiveCandidateRowTerms,
      NativeArrayAppendCandidate.candidateRow] using oldRep.retirementCommittableIndex
  · simpa [appendReceiveCandidateRowTerms,
      NativeArrayAppendCandidate.candidateRow] using oldRep.retiredCommittedIndex
  · simpa [appendReceiveCandidateRowTerms,
      NativeArrayAppendCandidate.candidateRow] using oldRep.votedFor
  · simpa [appendReceiveCandidateRowTerms,
      NativeArrayAppendCandidate.candidateRow] using oldRep.votesGranted
  · simpa [appendReceiveCandidateRowTerms,
      NativeArrayAppendCandidate.candidateRow] using oldRep.preVotesGranted
  · simpa [appendReceiveCandidateRowTerms,
      NativeArrayAppendCandidate.candidateRow] using oldRep.membershipState
  · intro peer
    simpa [appendReceiveCandidateRowTerms,
      NativeArrayAppendCandidate.candidateRow] using oldRep.sentIndex peer
  · intro peer
    simpa [appendReceiveCandidateRowTerms,
      NativeArrayAppendCandidate.candidateRow] using oldRep.matchIndex peer

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
