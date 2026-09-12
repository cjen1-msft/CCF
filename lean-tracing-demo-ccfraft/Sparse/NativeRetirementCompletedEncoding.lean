-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeFirstMatchWitness
import Sparse.NativeLogSummaryEncoding
import Sparse.NativeRetirementCompletedTerm
import Sparse.NativeRetirementIndexSound

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem retirement_completed_member_constraints_correct
    {context : List Ty} {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (locals : Locals context)
    (bootstrap : BitVec width)
    (length : Term context .int) (entries : Term context (.array .int (entryTy width)))
    (commit current first retirement retired : Term context .int)
    (node : Fin width) (log : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (commitNat : Nat)
    (sameLength : length.eval assignment locals = (log.length : Int))
    (sameCommit : commit.eval assignment locals = (commitNat : Int))
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (sameEntries : forall position, position < log.length ->
      modelEntry (entries.eval assignment locals (position : Int)) = log.entries position)
    (currentAccepted :
      (currentConfigurationIndexTerm width length entries commit current).eval
        assignment locals = true)
    (retirementAccepted :
      (retirementIndexTerm width bootstrap (logRangeMinTerm commit length) entries node
        first retirement).eval assignment locals = true)
    (retiredAccepted :
      (retiredRecordTerm width (logRangeMinTerm commit length) entries node retired).eval
        assignment locals = true) :
    (retirementCompletedMemberTerm node current
      (currentConfigurationMembersTerm width bootstrap entries current)
      first retirement retired).eval assignment locals = true <->
        node ∈ retirementCompletedNodes log.decode commitNat := by
  let committedLog := NativeArrayLogWrite.take log commitNat
  have sameCommittedLength :
      (logRangeMinTerm commit length).eval assignment locals =
        (committedLog.length : Int) := by
    simp [committedLog, log_range_min_term_eval, NativeArrayLogWrite.take,
      sameCommit, sameLength]
  have sameCommittedEntries : forall position, position < committedLog.length ->
      modelEntry (entries.eval assignment locals (position : Int)) =
        committedLog.entries position := by
    intro position live
    simpa [committedLog, NativeArrayLogWrite.take] using
      sameEntries position (by simp [committedLog, NativeArrayLogWrite.take] at live; omega)
  obtain ⟨currentNat, sameCurrent, currentModel, sameMembers⟩ :=
    current_configuration_terms_sound assignment locals bootstrap length entries
      commit current log commitNat sameBootstrap sameLength sameCommit sameEntries
      currentAccepted
  have currentIndex :=
    (current_configuration_index_term_native_correct assignment locals length entries
      commit current log commitNat currentNat sameLength sameCommit sameCurrent
      sameEntries).mp currentAccepted
  have configuration :
      NativeArrayConfiguration.At log currentNat
        (currentConfigurationAt log.decode commitNat).nodes := by
    exact ((NativeArrayConfiguration.current_configuration_correct log commitNat currentNat
      (currentConfigurationAt log.decode commitNat).nodes).mpr (by
        cases hcfg : currentConfigurationAt log.decode commitNat with
        | mk index nodes =>
          rw [hcfg] at currentModel
          simp only at currentModel
          subst index
          rfl)).2
  obtain ⟨firstChoice, retirementChoice, sameFirst, sameRetirement,
      firstCorrect, retirementCorrect⟩ :=
    retirement_index_term_sound assignment locals bootstrap
      (logRangeMinTerm commit length) entries node first retirement committedLog
      sameCommittedLength sameBootstrap sameCommittedEntries retirementAccepted
  rw [retiredRecordTerm] at retiredAccepted
  obtain ⟨retiredChoice, sameRetired, retiredCorrect⟩ :=
    first_match_term_sound assignment locals (logRangeMinTerm commit length) retired
      (retiredRecordPredicate entries node) committedLog
      (fun _ entry => Sparse.RetirementScan.namesRetiredNode node entry)
      retiredAccepted sameCommittedLength
      (fun position live => by
        rw [retired_record_predicate_eval, sameCommittedEntries position live])
  exact retirement_completed_member_term_correct assignment locals node current
    (currentConfigurationMembersTerm width bootstrap entries current)
    first retirement retired log commitNat currentNat
    (currentConfigurationAt log.decode commitNat).nodes firstChoice retirementChoice
    retiredChoice sameCurrent sameMembers sameFirst sameRetirement sameRetired
    currentIndex configuration firstCorrect retirementCorrect retiredCorrect

theorem retirement_completed_bits_constraints_correct
    {context : List Ty} {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (locals : Locals context)
    (bootstrap : BitVec width)
    (length : Term context .int) (entries : Term context (.array .int (entryTy width)))
    (commit current : Term context .int)
    (first retirement retired : Fin width -> Term context .int)
    (completed : Term context (.bits width))
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (commitNat : Nat)
    (sameLength : length.eval assignment locals = (log.length : Int))
    (sameCommit : commit.eval assignment locals = (commitNat : Int))
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (sameEntries : forall position, position < log.length ->
      modelEntry (entries.eval assignment locals (position : Int)) = log.entries position)
    (currentAccepted :
      (currentConfigurationIndexTerm width length entries commit current).eval
        assignment locals = true)
    (retirementAccepted : forall node,
      (retirementIndexTerm width bootstrap (logRangeMinTerm commit length) entries node
        (first node) (retirement node)).eval assignment locals = true)
    (retiredAccepted : forall node,
      (retiredRecordTerm width (logRangeMinTerm commit length) entries node
        (retired node)).eval assignment locals = true)
    (sameBits : forall node,
      (Term.bit completed node).eval assignment locals =
        (retirementCompletedMemberTerm node current
          (currentConfigurationMembersTerm width bootstrap entries current)
          (first node) (retirement node) (retired node)).eval assignment locals) :
    completed.eval assignment locals =
      encodeBits (retirementCompletedNodes log.decode commitNat) := by
  apply BitVec.eq_of_getLsbD_eq
  intro index live
  let node : Fin width := ⟨index, live⟩
  have memberCorrect :=
    retirement_completed_member_constraints_correct assignment locals bootstrap length
      entries commit current (first node) (retirement node) (retired node) node log
      commitNat sameLength sameCommit
      sameBootstrap sameEntries currentAccepted (retirementAccepted node)
      (retiredAccepted node)
  have sameBit := sameBits node
  change (completed.eval assignment locals).getLsbD node.val =
    (encodeBits (retirementCompletedNodes log.decode commitNat)).getLsbD node.val
  rw [encode_bits_bit]
  change (completed.eval assignment locals).getLsbD node.val =
    (retirementCompletedMemberTerm node current
      (currentConfigurationMembersTerm width bootstrap entries current)
      (first node) (retirement node) (retired node)).eval assignment locals at sameBit
  rw [sameBit]
  apply Bool.eq_iff_iff.mpr
  simpa only [decide_eq_true_eq] using memberCorrect

theorem retirement_completed_constraints_complete
    {context : List Ty} {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (locals : Locals context)
    (bootstrap : BitVec width)
    (length : Term context .int) (entries : Term context (.array .int (entryTy width)))
    (commit : Term context .int)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (commitNat : Nat)
    (sameLength : length.eval assignment locals = (log.length : Int))
    (sameCommit : commit.eval assignment locals = (commitNat : Int))
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (sameEntries : forall position, position < log.length ->
      modelEntry (entries.eval assignment locals (position : Int)) = log.entries position) :
    exists firstChoice retirementChoice retiredChoice : Fin width -> Option Nat,
      (currentConfigurationIndexTerm width length entries commit
        (.integer (currentConfigurationAt log.decode commitNat).index)).eval
          assignment locals = true /\
      forall node,
        (retirementIndexTerm width bootstrap (logRangeMinTerm commit length) entries node
          (.integer (firstMatchValue (firstChoice node)))
          (.integer (firstMatchValue (retirementChoice node)))).eval assignment locals = true /\
        (retiredRecordTerm width (logRangeMinTerm commit length) entries node
          (.integer (firstMatchValue (retiredChoice node)))).eval assignment locals = true /\
        (Term.bit (.bits (encodeBits (retirementCompletedNodes log.decode commitNat)))
          node).eval assignment locals =
            (retirementCompletedMemberTerm node
              (.integer (currentConfigurationAt log.decode commitNat).index)
              (currentConfigurationMembersTerm width bootstrap entries
                (.integer (currentConfigurationAt log.decode commitNat).index))
              (.integer (firstMatchValue (firstChoice node)))
              (.integer (firstMatchValue (retirementChoice node)))
              (.integer (firstMatchValue (retiredChoice node)))).eval assignment locals := by
  classical
  let committedLog := NativeArrayLogWrite.take log commitNat
  have sameCommittedLength :
      (logRangeMinTerm commit length).eval assignment locals =
        (committedLog.length : Int) := by
    simp [committedLog, log_range_min_term_eval, NativeArrayLogWrite.take,
      sameCommit, sameLength]
  have sameCommittedEntries : forall position, position < committedLog.length ->
      modelEntry (entries.eval assignment locals (position : Int)) =
        committedLog.entries position := by
    intro position live
    simpa [committedLog, NativeArrayLogWrite.take] using
      sameEntries position (by simp [committedLog, NativeArrayLogWrite.take] at live; omega)
  have firstExists (node : Fin width) :
      exists choice, NativeArrayFirstMatch.FirstMatch
        (NativeArrayRetirementIndex.virtualLog committedLog)
        (NativeArrayRetirementIndex.includes node) choice := by
    let choice :=
      (((NativeArrayRetirementIndex.virtualLog committedLog).decode.zipIdx).find?
        fun indexed =>
          NativeArrayRetirementIndex.includes node indexed.2 indexed.1).map Prod.snd
    exact ⟨choice,
      (NativeArrayFirstMatch.first_match_correct
        (NativeArrayRetirementIndex.virtualLog committedLog)
        (NativeArrayRetirementIndex.includes node) choice).mpr rfl⟩
  choose firstChoice firstCorrect using firstExists
  let retirementChoice : Fin width -> Option Nat :=
    fun node => retirementIndexInLog node committedLog.decode
  have retiredExists (node : Fin width) :
      exists choice, NativeArrayFirstMatch.FirstMatch committedLog
        (fun _ entry => Sparse.RetirementScan.namesRetiredNode node entry) choice := by
    let choice :=
      ((committedLog.decode.zipIdx).find? fun indexed =>
        Sparse.RetirementScan.namesRetiredNode node indexed.1).map Prod.snd
    exact ⟨choice,
      (NativeArrayFirstMatch.first_match_correct committedLog
        (fun _ entry => Sparse.RetirementScan.namesRetiredNode node entry) choice).mpr rfl⟩
  choose retiredChoice retiredCorrect using retiredExists
  refine ⟨firstChoice, retirementChoice, retiredChoice, ?_, ?_⟩
  · have currentIndex :=
      ((NativeArrayConfiguration.current_configuration_correct log commitNat
        (currentConfigurationAt log.decode commitNat).index
        (currentConfigurationAt log.decode commitNat).nodes).mpr rfl).1
    apply (current_configuration_index_term_native_correct assignment locals length entries
      commit (.integer (currentConfigurationAt log.decode commitNat).index) log commitNat
      (currentConfigurationAt log.decode commitNat).index sameLength sameCommit
      (by simp [Term.eval]) sameEntries).mpr
    exact currentIndex
  · intro node
    have retirementAccepted :=
      (retirement_index_term_correct assignment locals bootstrap
        (logRangeMinTerm commit length) entries node
        (.integer (firstMatchValue (firstChoice node)))
        (.integer (firstMatchValue (retirementChoice node))) committedLog
        (firstChoice node) (retirementChoice node) sameCommittedLength
        (by simp [Term.eval]) (by simp [Term.eval]) sameBootstrap
        sameCommittedEntries).mpr ⟨firstCorrect node, rfl⟩
    have retiredAccepted : (retiredRecordTerm width (logRangeMinTerm commit length) entries
        node (.integer (firstMatchValue (retiredChoice node)))).eval
          assignment locals = true := by
      rw [retiredRecordTerm]
      apply (first_match_term_correct assignment locals
        (logRangeMinTerm commit length) (.integer (firstMatchValue (retiredChoice node)))
        (retiredRecordPredicate entries node) committedLog
        (fun _ entry => Sparse.RetirementScan.namesRetiredNode node entry)
        (retiredChoice node) sameCommittedLength (by simp [Term.eval]) _).mpr
      · exact retiredCorrect node
      · intro position live
        rw [retired_record_predicate_eval, sameCommittedEntries position live]
    refine ⟨retirementAccepted, retiredAccepted, ?_⟩
    have memberCorrect :=
      retirement_completed_member_constraints_correct assignment locals bootstrap length entries
        commit (.integer (currentConfigurationAt log.decode commitNat).index)
        (.integer (firstMatchValue (firstChoice node)))
        (.integer (firstMatchValue (retirementChoice node)))
        (.integer (firstMatchValue (retiredChoice node))) node log commitNat sameLength
        sameCommit sameBootstrap sameEntries
        (by
          have currentIndex :=
            ((NativeArrayConfiguration.current_configuration_correct log commitNat
              (currentConfigurationAt log.decode commitNat).index
              (currentConfigurationAt log.decode commitNat).nodes).mpr rfl).1
          exact (current_configuration_index_term_native_correct assignment locals length entries
            commit (.integer (currentConfigurationAt log.decode commitNat).index) log commitNat
            (currentConfigurationAt log.decode commitNat).index sameLength sameCommit
            (by simp [Term.eval]) sameEntries).mpr currentIndex)
        retirementAccepted retiredAccepted
    apply Bool.eq_iff_iff.mpr
    simpa only [Term.eval, encode_bits_bit, decide_eq_true_eq] using memberCorrect.symm

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
