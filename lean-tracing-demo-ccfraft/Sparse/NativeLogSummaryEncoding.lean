-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayLogSummaries
import Sparse.NativeLogSummaryTerms

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem bounded_signature_predicate_eval {context : List Ty} {width : PNat}
    (assignment : Assignment) (locals : Locals context)
    (entries : Term context (.array .int (entryTy width)))
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (position : Nat) (live : position < log.length)
    (sameEntries : forall index, index < log.length ->
      modelEntry (entries.eval assignment locals (index : Int)) = log.entries index) :
    (isSignature (.snd (selectedLogEntry entries))).eval assignment
        (locals.cons (position : Int)) = true <->
      (log.entries position).content = .signature := by
  rw [signature_content_correct]
  simp only [Term.eval, selected_log_entry_eval]
  change
    (modelEntry (entries.eval assignment locals (position : Int))).content = .signature <->
      (log.entries position).content = .signature
  rw [sameEntries position live]

theorem current_configuration_predicate_eval {context : List Ty} {width : PNat}
    (assignment : Assignment) (locals : Locals context)
    (entries : Term context (.array .int (entryTy width)))
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (position : Nat) (live : position < log.length)
    (sameEntries : forall index, index < log.length ->
      modelEntry (entries.eval assignment locals (index : Int)) = log.entries index) :
    (isConfiguration (.snd (selectedLogEntry entries))).eval assignment
        (locals.cons (position : Int)) = true <->
      exists nodes, (log.entries position).content = .reconfiguration nodes := by
  rw [configuration_exists]
  simp only [Term.eval, selected_log_entry_eval]
  change
    (exists nodes,
      (modelEntry (entries.eval assignment locals (position : Int))).content =
        .reconfiguration nodes) <->
      exists nodes, (log.entries position).content = .reconfiguration nodes
  rw [sameEntries position live]

theorem nack_match_predicate_eval {context : List Ty} {width : PNat}
    (assignment : Assignment) (locals : Locals context)
    (entries : Term context (.array .int (entryTy width)))
    (threshold : Term context .int)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (thresholdNat position : Nat) (live : position < log.length)
    (sameThreshold : threshold.eval assignment locals = (thresholdNat : Int))
    (sameEntries : forall index, index < log.length ->
      modelEntry (entries.eval assignment locals (index : Int)) = log.entries index) :
    (Term.le (.fst (normalizedEntryTerm (selectedLogEntry entries)))
      (threshold.weaken .int)).eval assignment (locals.cons (position : Int)) = true <->
        (log.entries position).term <= thresholdNat := by
  simp only [Term.eval, decide_eq_true_eq, Term.weaken_eval,
    normalized_entry_term_correct, selected_log_entry_eval, sameThreshold]
  rw [sameEntries position live]
  simp [entryValue]

theorem bounded_signature_term_native_correct {context : List Ty} {width : PNat}
    [Bootstrap (Fin width)] (assignment : Assignment) (locals : Locals context)
    (length : Term context .int) (entries : Term context (.array .int (entryTy width)))
    (cap selected : Term context .int)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (capNat best : Nat)
    (sameLength : length.eval assignment locals = (log.length : Int))
    (sameCap : cap.eval assignment locals = (capNat : Int))
    (sameSelected : selected.eval assignment locals = (best : Int))
    (sameEntries : forall position, position < log.length ->
      modelEntry (entries.eval assignment locals (position : Int)) = log.entries position) :
    (boundedSignatureTerm width length entries cap selected).eval assignment locals = true <->
      NativeArrayVote.SignatureIndex (NativeArrayLogWrite.take log capNat) best := by
  rw [boundedSignatureTerm]
  refine (max_match_term_correct assignment locals length cap selected
    (isSignature (.snd (selectedLogEntry entries))) log.length capNat best
    (fun position => (log.entries position).content = .signature)
    sameLength sameCap sameSelected ?_).trans
      (NativeArrayLogSummaries.signature_storage_summary_iff log capNat best)
  intro position live
  exact bounded_signature_predicate_eval assignment locals entries log position
    (by omega) sameEntries

theorem bounded_signature_term_correct {context : List Ty} {width : PNat}
    [Bootstrap (Fin width)] (assignment : Assignment) (locals : Locals context)
    (length : Term context .int) (entries : Term context (.array .int (entryTy width)))
    (cap selected : Term context .int)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (capNat best : Nat)
    (sameLength : length.eval assignment locals = (log.length : Int))
    (sameCap : cap.eval assignment locals = (capNat : Int))
    (sameSelected : selected.eval assignment locals = (best : Int))
    (sameEntries : forall position, position < log.length ->
      modelEntry (entries.eval assignment locals (position : Int)) = log.entries position) :
    (boundedSignatureTerm width length entries cap selected).eval assignment locals = true <->
      maxCommittableIndexUpTo log.decode capNat = best :=
  (bounded_signature_term_native_correct assignment locals length entries cap selected
    log capNat best sameLength sameCap sameSelected sameEntries).trans
      (NativeArrayAppendReceive.bounded_signature_correct log capNat best)

theorem bounded_signature_term_sound {context : List Ty} {width : PNat}
    [Bootstrap (Fin width)] (assignment : Assignment) (locals : Locals context)
    (length : Term context .int) (entries : Term context (.array .int (entryTy width)))
    (cap selected : Term context .int)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (capNat : Nat)
    (sameLength : length.eval assignment locals = (log.length : Int))
    (sameCap : cap.eval assignment locals = (capNat : Int))
    (sameEntries : forall position, position < log.length ->
      modelEntry (entries.eval assignment locals (position : Int)) = log.entries position)
    (accepted :
      (boundedSignatureTerm width length entries cap selected).eval assignment locals = true) :
    exists best : Nat,
      selected.eval assignment locals = (best : Int) /\
        maxCommittableIndexUpTo log.decode capNat = best := by
  rw [boundedSignatureTerm] at accepted
  obtain ⟨best, sameSelected, summary⟩ :=
    max_match_term_sound assignment locals length cap selected
      (isSignature (.snd (selectedLogEntry entries))) log.length capNat
      (fun position => (log.entries position).content = .signature)
      sameLength sameCap
      (fun position live => bounded_signature_predicate_eval assignment locals entries
        log position (by omega) sameEntries) accepted
  exact ⟨best, sameSelected,
    (NativeArrayLogSummaries.signature_storage_summary_model_iff log capNat best).mp summary⟩

theorem current_configuration_index_term_native_correct
    {context : List Ty} {width : PNat}
    (assignment : Assignment) (locals : Locals context)
    (length : Term context .int) (entries : Term context (.array .int (entryTy width)))
    (commit selected : Term context .int)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (commitNat current : Nat)
    (sameLength : length.eval assignment locals = (log.length : Int))
    (sameCommit : commit.eval assignment locals = (commitNat : Int))
    (sameSelected : selected.eval assignment locals = (current : Int))
    (sameEntries : forall position, position < log.length ->
      modelEntry (entries.eval assignment locals (position : Int)) = log.entries position) :
    (currentConfigurationIndexTerm width length entries commit selected).eval
        assignment locals = true <->
      NativeArrayCheckQuorum.CurrentIndex log commitNat current := by
  rw [currentConfigurationIndexTerm]
  refine (max_match_term_correct assignment locals length commit selected
    (isConfiguration (.snd (selectedLogEntry entries))) log.length commitNat current
    (fun position => exists nodes, (log.entries position).content = .reconfiguration nodes)
    sameLength sameCommit sameSelected ?_).trans
      (NativeArrayLogSummaries.current_storage_summary_iff log commitNat current)
  intro position live
  exact current_configuration_predicate_eval assignment locals entries log position
    (by omega) sameEntries

theorem current_configuration_index_term_correct {context : List Ty} {width : PNat}
    [Bootstrap (Fin width)] (assignment : Assignment) (locals : Locals context)
    (length : Term context .int) (entries : Term context (.array .int (entryTy width)))
    (commit selected : Term context .int)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (commitNat current : Nat)
    (sameLength : length.eval assignment locals = (log.length : Int))
    (sameCommit : commit.eval assignment locals = (commitNat : Int))
    (sameSelected : selected.eval assignment locals = (current : Int))
    (sameEntries : forall position, position < log.length ->
      modelEntry (entries.eval assignment locals (position : Int)) = log.entries position) :
    (currentConfigurationIndexTerm width length entries commit selected).eval
        assignment locals = true <->
      (currentConfigurationAt log.decode commitNat).index = current :=
  (current_configuration_index_term_native_correct assignment locals length entries
    commit selected log commitNat current sameLength sameCommit sameSelected sameEntries).trans
      (NativeArrayCheckQuorum.current_index_correct log commitNat current)

theorem current_configuration_index_term_sound {context : List Ty} {width : PNat}
    [Bootstrap (Fin width)] (assignment : Assignment) (locals : Locals context)
    (length : Term context .int) (entries : Term context (.array .int (entryTy width)))
    (commit selected : Term context .int)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (commitNat : Nat)
    (sameLength : length.eval assignment locals = (log.length : Int))
    (sameCommit : commit.eval assignment locals = (commitNat : Int))
    (sameEntries : forall position, position < log.length ->
      modelEntry (entries.eval assignment locals (position : Int)) = log.entries position)
    (accepted : (currentConfigurationIndexTerm width length entries commit selected).eval
      assignment locals = true) :
    exists current : Nat,
      selected.eval assignment locals = (current : Int) /\
        (currentConfigurationAt log.decode commitNat).index = current := by
  rw [currentConfigurationIndexTerm] at accepted
  obtain ⟨current, sameSelected, summary⟩ :=
    max_match_term_sound assignment locals length commit selected
      (isConfiguration (.snd (selectedLogEntry entries))) log.length commitNat
      (fun position => exists nodes, (log.entries position).content = .reconfiguration nodes)
      sameLength sameCommit
      (fun position live => current_configuration_predicate_eval assignment locals entries
        log position (by omega) sameEntries) accepted
  exact ⟨current, sameSelected,
    (NativeArrayLogSummaries.current_storage_summary_model_iff
      log commitNat current).mp summary⟩

theorem nack_match_term_correct {context : List Ty} {width : PNat}
    [Bootstrap (Fin width)] (assignment : Assignment) (locals : Locals context)
    (length : Term context .int) (entries : Term context (.array .int (entryTy width)))
    (previous threshold selected : Term context .int)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (previousNat thresholdNat best : Nat)
    (sameLength : length.eval assignment locals = (log.length : Int))
    (samePrevious : previous.eval assignment locals = (previousNat : Int))
    (sameThreshold : threshold.eval assignment locals = (thresholdNat : Int))
    (sameSelected : selected.eval assignment locals = (best : Int))
    (sameEntries : forall position, position < log.length ->
      modelEntry (entries.eval assignment locals (position : Int)) = log.entries position) :
    (nackMatchTerm width length entries previous threshold selected).eval
        assignment locals = true <->
      findHighestPossibleMatch log.decode previousNat thresholdNat = best := by
  rw [nackMatchTerm]
  refine (max_match_term_correct assignment locals length previous selected
    (.le (.fst (normalizedEntryTerm (selectedLogEntry entries))) (threshold.weaken .int))
    log.length previousNat best
    (fun position => (log.entries position).term <= thresholdNat)
    sameLength samePrevious sameSelected ?_).trans
      (NativeArrayAppendReceive.nack_match_correct
        log previousNat thresholdNat best)
  intro position live
  exact nack_match_predicate_eval assignment locals entries threshold log thresholdNat
    position (by omega) sameThreshold sameEntries

theorem nack_match_term_sound {context : List Ty} {width : PNat}
    [Bootstrap (Fin width)] (assignment : Assignment) (locals : Locals context)
    (length : Term context .int) (entries : Term context (.array .int (entryTy width)))
    (previous threshold selected : Term context .int)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (previousNat thresholdNat : Nat)
    (sameLength : length.eval assignment locals = (log.length : Int))
    (samePrevious : previous.eval assignment locals = (previousNat : Int))
    (sameThreshold : threshold.eval assignment locals = (thresholdNat : Int))
    (sameEntries : forall position, position < log.length ->
      modelEntry (entries.eval assignment locals (position : Int)) = log.entries position)
    (accepted : (nackMatchTerm width length entries previous threshold selected).eval
      assignment locals = true) :
    exists best : Nat,
      selected.eval assignment locals = (best : Int) /\
        findHighestPossibleMatch log.decode previousNat thresholdNat = best := by
  rw [nackMatchTerm] at accepted
  obtain ⟨best, sameSelected, summary⟩ :=
    max_match_term_sound assignment locals length previous selected
      (.le (.fst (normalizedEntryTerm (selectedLogEntry entries))) (threshold.weaken .int))
      log.length previousNat (fun position => (log.entries position).term <= thresholdNat)
      sameLength samePrevious
      (fun position live => nack_match_predicate_eval assignment locals entries threshold
        log thresholdNat position (by omega) sameThreshold sameEntries) accepted
  exact ⟨best, sameSelected,
    (NativeArrayAppendReceive.nack_match_correct
      log previousNat thresholdNat best).mp summary⟩

theorem current_configuration_members_term_correct
    {context : List Ty} {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (locals : Locals context)
    (bootstrap : BitVec width)
    (length : Term context .int) (entries : Term context (.array .int (entryTy width)))
    (commit selected : Term context .int)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (commitNat current : Nat)
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (sameLength : length.eval assignment locals = (log.length : Int))
    (sameCommit : commit.eval assignment locals = (commitNat : Int))
    (sameSelected : selected.eval assignment locals = (current : Int))
    (sameEntries : forall position, position < log.length ->
      modelEntry (entries.eval assignment locals (position : Int)) = log.entries position)
    (accepted : (currentConfigurationIndexTerm width length entries commit selected).eval
      assignment locals = true) :
    (currentConfigurationMembersTerm width bootstrap entries selected).eval assignment locals =
      encodeBits (currentConfigurationAt log.decode commitNat).nodes := by
  have currentIndex :=
    (current_configuration_index_term_native_correct assignment locals length entries
      commit selected log commitNat current sameLength sameCommit sameSelected sameEntries).mp accepted
  cases current with
  | zero =>
    have configuration :=
      (NativeArrayConfiguration.current_configuration_correct log commitNat 0
        INITIAL_CONFIGURATION).mp ⟨currentIndex, Or.inl ⟨rfl, rfl⟩⟩
    have sameNodes := congrArg Configuration.nodes configuration
    have sameBits : bootstrap = encodeBits INITIAL_CONFIGURATION := by
      rw [<- sameBootstrap, encode_decode_bits]
    simp [currentConfigurationMembersTerm, Term.eval, sameSelected, sameBits, sameNodes]
  | succ position =>
    obtain ⟨nodes, reconfiguration⟩ := currentIndex.2.1.resolve_left (by omega)
    have live : position < log.length := by
      rcases reconfiguration with ⟨_, within, _⟩
      omega
    have selectedEntry :
        modelEntry (entries.eval assignment locals (position : Int)) =
          log.entries position :=
      sameEntries position live
    have decoded :
        decodeContent
          ((.snd (.select entries (.sub selected (.integer 1))) :
            Term context (contentTy width)).eval assignment locals) =
          .reconfiguration nodes := by
      simp only [Term.eval, sameSelected]
      have castSub : ((Nat.succ position : Nat) : Int) - 1 = (position : Int) := by omega
      rw [castSub]
      change (modelEntry (entries.eval assignment locals (position : Int))).content =
        .reconfiguration nodes
      rw [selectedEntry]
      exact reconfiguration.2.2
    have decodedMembers :=
      (configuration_decoding
        (.snd (.select entries (.sub selected (.integer 1))))
        assignment locals nodes).mp decoded |>.2
    have configuration :=
      (NativeArrayConfiguration.current_configuration_correct log commitNat
        (Nat.succ position) nodes).mp ⟨currentIndex, Or.inr reconfiguration⟩
    have sameNodes := congrArg Configuration.nodes configuration
    simp only [currentConfigurationMembersTerm, Term.eval, sameSelected]
    simp [show (position : Int) + 1 ≠ 0 by omega]
    rw [<- encode_decode_bits
      ((members (.snd (.select entries (.sub selected (.integer 1))))).eval
        assignment locals)]
    rw [decodedMembers, sameNodes]

theorem current_configuration_terms_sound
    {context : List Ty} {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (locals : Locals context)
    (bootstrap : BitVec width)
    (length : Term context .int) (entries : Term context (.array .int (entryTy width)))
    (commit selected : Term context .int)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (commitNat : Nat)
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (sameLength : length.eval assignment locals = (log.length : Int))
    (sameCommit : commit.eval assignment locals = (commitNat : Int))
    (sameEntries : forall position, position < log.length ->
      modelEntry (entries.eval assignment locals (position : Int)) = log.entries position)
    (accepted : (currentConfigurationIndexTerm width length entries commit selected).eval
      assignment locals = true) :
    exists current : Nat,
      selected.eval assignment locals = (current : Int) /\
        (currentConfigurationAt log.decode commitNat).index = current /\
        (currentConfigurationMembersTerm width bootstrap entries selected).eval
            assignment locals =
          encodeBits (currentConfigurationAt log.decode commitNat).nodes := by
  obtain ⟨current, sameSelected, sameCurrent⟩ :=
    current_configuration_index_term_sound assignment locals length entries commit selected
      log commitNat sameLength sameCommit sameEntries accepted
  exact ⟨current, sameSelected, sameCurrent,
    current_configuration_members_term_correct assignment locals bootstrap length entries
      commit selected log commitNat current sameBootstrap sameLength sameCommit sameSelected
      sameEntries accepted⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
