-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayConfiguration
import Sparse.NativeLogRangeEncoding
import Sparse.NativeRetirementEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def allActiveTerm {context : List Ty} (width : PNat)
    (length current : Term context .int)
    (entries : Term context (.array .int (entryTy width)))
    (bootstrapPredicate : Term context .bool)
    (physicalPredicate : Term (.int :: context) .bool) :
    Term context .bool :=
  all [
    implies (.equal current (.integer 0)) bootstrapPredicate,
    boundedForall length (
      let position : Term (.int :: context) .int := .bound .here
      implies
        (all [
          .le (current.weaken .int) (.add position (.integer 1)),
          isConfiguration (.snd (selectedLogEntry entries))])
        physicalPredicate)]

theorem all_active_term_correct {context : List Ty} {width : PNat}
    [Bootstrap (Fin width)]
    (assignment : Assignment) (locals : Locals context)
    (length current : Term context .int)
    (entries : Term context (.array .int (entryTy width)))
    (bootstrapPredicate : Term context .bool)
    (physicalPredicate : Term (.int :: context) .bool)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (currentNat : Nat)
    (predicate : Nat -> Finset (Fin width) -> Prop)
    (sameLength : length.eval assignment locals = (log.length : Int))
    (sameCurrent : current.eval assignment locals = (currentNat : Int))
    (sameEntries : forall position, position < log.length ->
      modelEntry (entries.eval assignment locals (position : Int)) =
        log.entries position)
    (bootstrapCorrect :
      bootstrapPredicate.eval assignment locals = true <->
        predicate 0 INITIAL_CONFIGURATION)
    (physicalCorrect : forall position nodes, position < log.length ->
      (log.entries position).content = .reconfiguration nodes ->
      (physicalPredicate.eval assignment (locals.cons (position : Int)) = true <->
        predicate (position + 1) nodes)) :
    (allActiveTerm width length current entries bootstrapPredicate physicalPredicate).eval
        assignment locals = true <->
      NativeArrayConfiguration.AllActive log currentNat predicate := by
  have bootstrapTermCorrect :
      (implies (.equal current (.integer 0)) bootstrapPredicate).eval
          assignment locals = true <->
        (currentNat = 0 -> predicate 0 INITIAL_CONFIGURATION) := by
    rw [implies_eval, bootstrapCorrect]
    simp only [Term.eval, sameCurrent, decide_eq_true_eq]
    norm_num
  have configurationCorrect (position : Nat) (live : position < log.length) :
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
  have physicalTermCorrect :
      (boundedForall length (
        let position : Term (.int :: context) .int := .bound .here
        implies
          (all [
            .le (current.weaken .int) (.add position (.integer 1)),
            isConfiguration (.snd (selectedLogEntry entries))])
          physicalPredicate)).eval assignment locals = true <->
        forall index nodes, currentNat <= index ->
          NativeArrayCheckQuorum.Reconfiguration log index nodes ->
          predicate index nodes := by
    rw [bounded_forall_nat_eval assignment locals length _ log.length sameLength]
    constructor
    · intro accepted index nodes lower reconfiguration
      rcases reconfiguration with ⟨positive, within, content⟩
      have live : index - 1 < log.length := by omega
      have selected := accepted (index - 1) live
      rw [implies_eval] at selected
      have configuration :
          (isConfiguration (.snd (selectedLogEntry entries))).eval assignment
              (locals.cons ((index - 1 : Nat) : Int)) = true := by
        apply (configurationCorrect (index - 1) live).mpr
        exact ⟨nodes, content⟩
      have guard :
          (all [
            .le (current.weaken .int)
              (.add (.bound .here) (.integer 1)),
            isConfiguration (.snd (selectedLogEntry entries))]).eval assignment
              (locals.cons ((index - 1 : Nat) : Int)) = true := by
        simp only [all, List.foldr_cons, List.foldr_nil, Term.eval,
          Term.weaken_eval, Locals.cons, Bool.and_eq_true, and_true,
          decide_eq_true_eq, sameCurrent]
        constructor
        · have lowerNat : currentNat <= index - 1 + 1 := by omega
          simpa only [Nat.cast_add, Nat.cast_one] using
            Int.ofNat_le.mpr lowerNat
        · exact configuration
      have represented := selected guard
      have semantic :=
        (physicalCorrect (index - 1) nodes live content).mp represented
      simpa only [Nat.sub_add_cancel positive] using semantic
    · intro active position live
      rw [implies_eval]
      intro guard
      have separated := guard
      simp only [all, List.foldr_cons, List.foldr_nil, Term.eval,
        Term.weaken_eval, Locals.cons, Bool.and_eq_true, and_true,
        decide_eq_true_eq, sameCurrent] at separated
      have lower : currentNat <= position + 1 := by
        apply Int.ofNat_le.mp
        simpa only [Nat.cast_add, Nat.cast_one] using separated.1
      obtain ⟨nodes, content⟩ :=
        (configurationCorrect position live).mp separated.2
      have reconfiguration :
          NativeArrayCheckQuorum.Reconfiguration log (position + 1) nodes := by
        simp only [NativeArrayCheckQuorum.Reconfiguration]
        constructor
        · omega
        constructor
        · omega
        · simpa only [Nat.add_sub_cancel] using content
      exact (physicalCorrect position nodes live content).mpr
        (active (position + 1) nodes lower reconfiguration)
  change
    (((implies (.equal current (.integer 0)) bootstrapPredicate).eval
          assignment locals &&
        ((boundedForall length (
          implies
            (all [
              .le (current.weaken .int)
                (.add (.bound .here) (.integer 1)),
              isConfiguration (.snd (selectedLogEntry entries))])
            physicalPredicate)).eval assignment locals && true)) = true) <->
      NativeArrayConfiguration.AllActive log currentNat predicate
  simp only [Bool.and_eq_true, and_true, bootstrapTermCorrect,
    physicalTermCorrect, NativeArrayConfiguration.AllActive]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
