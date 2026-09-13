-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayCommitIndex
import Sparse.NativeCommitIndexTerms

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem majority_at_term_correct {context : List Ty} {width : PNat}
    [Bootstrap (Fin width)]
    (assignment : Assignment) (locals : Locals context)
    (bootstrap : BitVec width)
    (length : Term context .int)
    (entries : Term context (.array .int (entryTy width)))
    (matchIndex : Term context (.array .int .int))
    (source : Fin width) (current candidate : Term context .int)
    (row : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (currentNat candidateNat : Nat)
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (sameLength : length.eval assignment locals = (row.log.length : Int))
    (sameEntries : forall position, position < row.log.length ->
      modelEntry (entries.eval assignment locals (position : Int)) =
        row.log.entries position)
    (sameMatches : forall peer,
      matchIndex.eval assignment locals peer.val = (row.matchIndex peer : Int))
    (sameCurrent : current.eval assignment locals = (currentNat : Int))
    (sameCandidate : candidate.eval assignment locals = (candidateNat : Int)) :
    (majorityAtTerm width bootstrap length entries matchIndex source current candidate).eval
        assignment locals = true <->
      NativeArrayMajority.MajorityAt row source currentNat candidateNat := by
  rw [majorityAtTerm]
  apply all_active_term_correct assignment locals length current entries
    (replicationMajorityTerm (.bits bootstrap) matchIndex source candidate)
    (implies (.le (.add (.bound .here) (.integer 1)) (candidate.weaken .int))
      (replicationMajorityTerm (members (.snd (selectedLogEntry entries)))
        (matchIndex.weaken .int) source (candidate.weaken .int)))
    row.log currentNat
    (fun configurationIndex nodes =>
      configurationIndex <= candidateNat ->
        (nodes.filter fun peer =>
          peer = source \/ candidateNat <= row.matchIndex peer).card * 2 >
            nodes.card)
    sameLength sameCurrent sameEntries
  · have encodedBootstrap : (.bits bootstrap : Term context (.bits width)).eval
        assignment locals = encodeBits INITIAL_CONFIGURATION := by
      simp only [Term.eval]
      rw [<- sameBootstrap, encode_decode_bits]
    rw [replication_majority_term_eval (.bits bootstrap) matchIndex source candidate
      assignment locals INITIAL_CONFIGURATION candidateNat row.matchIndex
      encodedBootstrap sameCandidate sameMatches]
    simp only [decide_eq_true_eq, Nat.zero_le, true_implies]
  · intro position nodes live content
    have decoded :
        decodeContent
            ((.snd (selectedLogEntry entries) :
              Term (.int :: context) (contentTy width)).eval
              assignment (locals.cons (position : Int))) =
          .reconfiguration nodes := by
      simp only [Term.eval, selected_log_entry_eval]
      change
        (modelEntry (entries.eval assignment locals (position : Int))).content =
          .reconfiguration nodes
      rw [sameEntries position live]
      exact content
    have decodedMembers :=
      (configuration_decoding (.snd (selectedLogEntry entries)) assignment
        (locals.cons (position : Int)) nodes).mp decoded |>.2
    have encodedMembers :
        (members (.snd (selectedLogEntry entries))).eval assignment
            (locals.cons (position : Int)) = encodeBits nodes := by
      rw [<- decodedMembers, encode_decode_bits]
    have weakenedMatches : forall peer,
        (matchIndex.weaken .int).eval assignment
            (locals.cons (position : Int)) peer.val =
          (row.matchIndex peer : Int) := by
      intro peer
      simpa only [Term.weaken_eval] using sameMatches peer
    have weakenedCandidate :
        (candidate.weaken .int).eval assignment
            (locals.cons (position : Int)) = (candidateNat : Int) := by
      simpa only [Term.weaken_eval] using sameCandidate
    rw [implies_eval]
    simp only [Term.eval, Term.weaken_eval, Locals.cons, sameCandidate,
      decide_eq_true_eq]
    rw [replication_majority_term_eval
      (members (.snd (selectedLogEntry entries))) (matchIndex.weaken .int) source
      (candidate.weaken .int) assignment (locals.cons (position : Int)) nodes
      candidateNat row.matchIndex encodedMembers weakenedCandidate weakenedMatches]
    simp only [decide_eq_true_eq]
    constructor
    · intro accepted lower
      apply accepted
      simpa only [Nat.cast_add, Nat.cast_one] using Int.ofNat_le.mpr lower
    · intro accepted lower
      apply accepted
      apply Int.ofNat_le.mp
      simpa only [Nat.cast_add, Nat.cast_one] using lower

theorem commit_eligible_predicate_correct {context : List Ty} {width : PNat}
    [Bootstrap (Fin width)]
    (assignment : Assignment) (locals : Locals context)
    (bootstrap : BitVec width)
    (length : Term context .int)
    (entries : Term context (.array .int (entryTy width)))
    (matchIndex : Term context (.array .int .int))
    (source : Fin width)
    (commit currentTerm current : Term context .int)
    (row : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (currentNat position : Nat)
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (sameLength : length.eval assignment locals = (row.log.length : Int))
    (sameEntries : forall index, index < row.log.length ->
      modelEntry (entries.eval assignment locals (index : Int)) =
        row.log.entries index)
    (sameMatches : forall peer,
      matchIndex.eval assignment locals peer.val = (row.matchIndex peer : Int))
    (sameCommit : commit.eval assignment locals = (row.commit : Int))
    (sameCurrentTerm :
      currentTerm.eval assignment locals = (row.currentTerm : Int))
    (sameCurrent : current.eval assignment locals = (currentNat : Int))
    (live : position < row.log.length) :
    (commitEligiblePredicate width bootstrap length entries matchIndex source
      commit currentTerm current).eval assignment
        (locals.cons (position : Int)) = true <->
      NativeArrayCommitIndex.Eligible row source currentNat position := by
  have signatureCorrect :
      (isSignature (.snd (selectedLogEntry entries))).eval assignment
          (locals.cons (position : Int)) = true <->
        (row.log.entries position).content = .signature := by
    rw [signature_content_correct]
    simp only [Term.eval, selected_log_entry_eval]
    change
      (modelEntry (entries.eval assignment locals (position : Int))).content =
          .signature <->
        (row.log.entries position).content = .signature
    rw [sameEntries position live]
  have termCorrect :
      (Term.equal (.fst (normalizedEntryTerm (selectedLogEntry entries)))
        (currentTerm.weaken .int)).eval assignment
          (locals.cons (position : Int)) = true <->
        (row.log.entries position).term = row.currentTerm := by
    simp only [Term.eval, normalized_entry_term_correct, selected_log_entry_eval,
      Term.weaken_eval, sameCurrentTerm, decide_eq_true_eq, entryValue]
    rw [sameEntries position live]
    norm_num
  have commitCorrect :
      (lt (commit.weaken .int) (.add (.bound .here) (.integer 1))).eval
          assignment (locals.cons (position : Int)) = true <->
        row.commit < position + 1 := by
    simp only [lt, Term.eval, Term.weaken_eval, Locals.cons, sameCommit,
      Bool.not_eq_true', decide_eq_false_iff_not, not_le]
    constructor
    · intro accepted
      apply Int.ofNat_lt.mp
      simpa only [Nat.cast_add, Nat.cast_one] using accepted
    · intro accepted
      simpa only [Nat.cast_add, Nat.cast_one] using Int.ofNat_lt.mpr accepted
  have majorityCorrect :=
    majority_at_term_correct assignment (locals.cons (position : Int)) bootstrap
      (length.weaken .int) (entries.weaken .int) (matchIndex.weaken .int) source
      (current.weaken .int) (.add (.bound .here) (.integer 1)) row currentNat
      (position + 1) sameBootstrap
      (by simpa only [Term.weaken_eval] using sameLength)
      (by
        intro index within
        simpa only [Term.weaken_eval] using sameEntries index within)
      (by
        intro peer
        simpa only [Term.weaken_eval] using sameMatches peer)
      (by simpa only [Term.weaken_eval] using sameCurrent)
      (by simp [Term.eval, Locals.cons])
  change
    (((lt (commit.weaken .int)
        (.add (.bound .here) (.integer 1))).eval assignment
          (locals.cons (position : Int)) &&
      ((isSignature (.snd (selectedLogEntry entries))).eval assignment
          (locals.cons (position : Int)) &&
      ((Term.equal (.fst (normalizedEntryTerm (selectedLogEntry entries)))
        (currentTerm.weaken .int)).eval assignment
          (locals.cons (position : Int)) &&
      ((majorityAtTerm width bootstrap (length.weaken .int)
        (entries.weaken .int) (matchIndex.weaken .int) source
        (current.weaken .int) (.add (.bound .here) (.integer 1))).eval
          assignment (locals.cons (position : Int)) && true)))) = true) <->
      NativeArrayCommitIndex.Eligible row source currentNat position
  simp only [Bool.and_eq_true, and_true, commitCorrect, signatureCorrect,
    termCorrect, majorityCorrect, NativeArrayCommitIndex.Eligible]

theorem highest_commit_index_term_correct {context : List Ty} {width : PNat}
    [Bootstrap (Fin width)]
    (assignment : Assignment) (locals : Locals context)
    (bootstrap : BitVec width)
    (length : Term context .int)
    (entries : Term context (.array .int (entryTy width)))
    (matchIndex : Term context (.array .int .int))
    (source : Fin width)
    (commit currentTerm current selected : Term context .int)
    (row : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (currentNat best : Nat)
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (sameLength : length.eval assignment locals = (row.log.length : Int))
    (sameEntries : forall position, position < row.log.length ->
      modelEntry (entries.eval assignment locals (position : Int)) =
        row.log.entries position)
    (sameMatches : forall peer,
      matchIndex.eval assignment locals peer.val = (row.matchIndex peer : Int))
    (sameCommit : commit.eval assignment locals = (row.commit : Int))
    (sameCurrentTerm :
      currentTerm.eval assignment locals = (row.currentTerm : Int))
    (sameCurrent : current.eval assignment locals = (currentNat : Int))
    (sameSelected : selected.eval assignment locals = (best : Int)) :
    (highestCommitIndexTerm width bootstrap length entries matchIndex source
      commit currentTerm current selected).eval assignment locals = true <->
      NativeArrayCommitIndex.CommitIndex row source currentNat best := by
  apply max_match_term_correct assignment locals length length selected
    (commitEligiblePredicate width bootstrap length entries matchIndex source
      commit currentTerm current)
    row.log.length row.log.length best
    (NativeArrayCommitIndex.Eligible row source currentNat)
    sameLength sameLength sameSelected
  intro position live
  apply commit_eligible_predicate_correct assignment locals bootstrap length entries
    matchIndex source commit currentTerm current row currentNat position
    sameBootstrap sameLength sameEntries sameMatches sameCommit sameCurrentTerm
    sameCurrent
  simpa using live

theorem highest_commit_index_term_sound {context : List Ty} {width : PNat}
    [Bootstrap (Fin width)]
    (assignment : Assignment) (locals : Locals context)
    (bootstrap : BitVec width)
    (length : Term context .int)
    (entries : Term context (.array .int (entryTy width)))
    (matchIndex : Term context (.array .int .int))
    (source : Fin width)
    (commit currentTerm current selected : Term context .int)
    (row : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (currentNat : Nat)
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (sameLength : length.eval assignment locals = (row.log.length : Int))
    (sameEntries : forall position, position < row.log.length ->
      modelEntry (entries.eval assignment locals (position : Int)) =
        row.log.entries position)
    (sameMatches : forall peer,
      matchIndex.eval assignment locals peer.val = (row.matchIndex peer : Int))
    (sameCommit : commit.eval assignment locals = (row.commit : Int))
    (sameCurrentTerm :
      currentTerm.eval assignment locals = (row.currentTerm : Int))
    (sameCurrent : current.eval assignment locals = (currentNat : Int))
    (accepted : (highestCommitIndexTerm width bootstrap length entries matchIndex source
      commit currentTerm current selected).eval assignment locals = true) :
    exists best : Nat,
      selected.eval assignment locals = (best : Int) /\
      NativeArrayCommitIndex.CommitIndex row source currentNat best := by
  apply max_match_term_sound assignment locals length length selected
    (commitEligiblePredicate width bootstrap length entries matchIndex source
      commit currentTerm current)
    row.log.length row.log.length
    (NativeArrayCommitIndex.Eligible row source currentNat)
    sameLength sameLength
  · intro position live
    apply commit_eligible_predicate_correct assignment locals bootstrap length entries
      matchIndex source commit currentTerm current row currentNat position
      sameBootstrap sameLength sameEntries sameMatches sameCommit sameCurrentTerm
      sameCurrent
    simpa using live
  · exact accepted

theorem highest_commit_index_term_model_correct
    {context : List Ty} {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (locals : Locals context)
    (bootstrap : BitVec width)
    (length : Term context .int)
    (entries : Term context (.array .int (entryTy width)))
    (matchIndex : Term context (.array .int .int))
    (source : Fin width)
    (commit currentTerm current selected : Term context .int)
    (row : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (state : State (Fin width) Nat)
    (currentNat best : Nat)
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (sameLength : length.eval assignment locals = (row.log.length : Int))
    (sameEntries : forall position, position < row.log.length ->
      modelEntry (entries.eval assignment locals (position : Int)) =
        row.log.entries position)
    (sameMatches : forall peer,
      matchIndex.eval assignment locals peer.val = (row.matchIndex peer : Int))
    (sameCommit : commit.eval assignment locals = (row.commit : Int))
    (sameCurrentTerm :
      currentTerm.eval assignment locals = (row.currentTerm : Int))
    (sameCurrent : current.eval assignment locals = (currentNat : Int))
    (sameSelected : selected.eval assignment locals = (best : Int))
    (sameRow : state.nodes source = row.toModel)
    (currentIndex :
      NativeArrayCheckQuorum.CurrentIndex row.log row.commit currentNat) :
    (highestCommitIndexTerm width bootstrap length entries matchIndex source
      commit currentTerm current selected).eval assignment locals = true <->
      highestCommittableIndex state source = best := by
  exact (highest_commit_index_term_correct assignment locals bootstrap length entries
    matchIndex source commit currentTerm current selected row currentNat best
    sameBootstrap sameLength sameEntries sameMatches sameCommit sameCurrentTerm
    sameCurrent sameSelected).trans
      (NativeArrayCommitIndex.commit_index_correct row state source currentNat best
        sameRow currentIndex)

theorem highest_commit_index_term_model_sound
    {context : List Ty} {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (locals : Locals context)
    (bootstrap : BitVec width)
    (length : Term context .int)
    (entries : Term context (.array .int (entryTy width)))
    (matchIndex : Term context (.array .int .int))
    (source : Fin width)
    (commit currentTerm current selected : Term context .int)
    (row : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (state : State (Fin width) Nat)
    (currentNat : Nat)
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (sameLength : length.eval assignment locals = (row.log.length : Int))
    (sameEntries : forall position, position < row.log.length ->
      modelEntry (entries.eval assignment locals (position : Int)) =
        row.log.entries position)
    (sameMatches : forall peer,
      matchIndex.eval assignment locals peer.val = (row.matchIndex peer : Int))
    (sameCommit : commit.eval assignment locals = (row.commit : Int))
    (sameCurrentTerm :
      currentTerm.eval assignment locals = (row.currentTerm : Int))
    (sameCurrent : current.eval assignment locals = (currentNat : Int))
    (sameRow : state.nodes source = row.toModel)
    (currentIndex :
      NativeArrayCheckQuorum.CurrentIndex row.log row.commit currentNat)
    (accepted : (highestCommitIndexTerm width bootstrap length entries matchIndex source
      commit currentTerm current selected).eval assignment locals = true) :
    exists best : Nat,
      selected.eval assignment locals = (best : Int) /\
      highestCommittableIndex state source = best := by
  obtain ⟨best, sameSelected, native⟩ :=
    highest_commit_index_term_sound assignment locals bootstrap length entries
      matchIndex source commit currentTerm current selected row currentNat
      sameBootstrap sameLength sameEntries sameMatches sameCommit sameCurrentTerm
      sameCurrent accepted
  exact ⟨best, sameSelected,
    (NativeArrayCommitIndex.commit_index_correct row state source currentNat best
      sameRow currentIndex).mp native⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
