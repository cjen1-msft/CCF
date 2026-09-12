-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayRetirementIndex
import Sparse.NativeFirstMatchEncoding
import Sparse.NativeEncodeProofs

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def virtualLogEntryTerm {context : List Ty} (width : PNat) (bootstrap : BitVec width)
    (entries : Term context (.array .int (entryTy width))) (candidate : Term context .int) :
    Term context (entryTy width) :=
  .ite (.equal candidate (.integer 0))
    (entryTerm { term := 0, content := .reconfiguration (decodeBits bootstrap) })
    (.select entries (.sub candidate (.integer 1)))

def configurationIncludesTerm {context : List Ty} {width : PNat}
    (entry : Term context (entryTy width)) (node : Fin width) : Term context .bool :=
  all [isConfiguration entry.snd, .bit (members entry.snd) node]

def configurationExcludesAfterTerm {context : List Ty} {width : PNat}
    (entry : Term context (entryTy width)) (node : Fin width)
    (first candidate : Term context .int) : Term context .bool :=
  all [
    lt first candidate,
    isConfiguration entry.snd,
    .not (.bit (members entry.snd) node)]

def retirementInclusionPredicate {context : List Ty} (width : PNat)
    (bootstrap : BitVec width) (entries : Term context (.array .int (entryTy width)))
    (node : Fin width) : Term (.int :: context) .bool :=
  configurationIncludesTerm
    (virtualLogEntryTerm width bootstrap (entries.weaken .int) (.bound .here)) node

def retirementExclusionPredicate {context : List Ty} (width : PNat)
    (bootstrap : BitVec width) (entries : Term context (.array .int (entryTy width)))
    (node : Fin width) (first : Term context .int) : Term (.int :: context) .bool :=
  configurationExcludesAfterTerm
    (virtualLogEntryTerm width bootstrap (entries.weaken .int) (.bound .here)) node
    (first.weaken .int) (.bound .here)

def retirementIndexTerm {context : List Ty} (width : PNat) (bootstrap : BitVec width)
    (limit : Term context .int) (entries : Term context (.array .int (entryTy width)))
    (node : Fin width) (first retirement : Term context .int) : Term context .bool :=
  let virtualLimit := .add (.integer 1) limit
  all [
    firstMatchTerm virtualLimit first
      (retirementInclusionPredicate width bootstrap entries node),
    .ite (.equal first (.integer (-1)))
      (.equal retirement (.integer (-1)))
      (firstMatchTerm virtualLimit retirement
        (retirementExclusionPredicate width bootstrap entries node first))]

theorem virtual_log_entry_term_eval {context : List Ty} {width : PNat}
    [Bootstrap (Fin width)] (assignment : Assignment) (locals : Locals context)
    (bootstrap : BitVec width) (entries : Term context (.array .int (entryTy width)))
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (candidate : Nat)
    (live : candidate < (NativeArrayRetirementIndex.virtualLog log).length)
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (sameEntries : forall index, index < log.length ->
      modelEntry (entries.eval assignment locals (index : Int)) = log.entries index) :
    modelEntry
        ((virtualLogEntryTerm width bootstrap (entries.weaken .int) (.bound .here)).eval
          assignment (locals.cons (candidate : Int))) =
      (NativeArrayRetirementIndex.virtualLog log).entries candidate := by
  by_cases zero : candidate = 0
  · subst candidate
    simp only [Nat.cast_zero]
    have evaluated :
        (virtualLogEntryTerm width bootstrap (entries.weaken .int) (.bound .here)).eval
            assignment (locals.cons ((0 : Nat) : Int)) =
          entryValue { term := 0, content := .reconfiguration (decodeBits bootstrap) } := by
      simp [virtualLogEntryTerm, Term.eval, Locals.cons, entry_term_eval]
    calc
      _ = modelEntry
          (entryValue { term := 0, content := .reconfiguration (decodeBits bootstrap) }) :=
        by simpa using congrArg modelEntry evaluated
      _ = { term := 0, content := .reconfiguration (decodeBits bootstrap) } :=
        model_entry_value _
      _ = (NativeArrayRetirementIndex.virtualLog log).entries 0 := by
        simp [NativeArrayRetirementIndex.virtualLog, NativeArrayRetirementIndex.bootstrapEntry,
          NativeArrayLogWrite.append, NativeArrayCheckQuorum.Log.ofList, sameBootstrap]
  · have positive : 0 < candidate := Nat.pos_of_ne_zero zero
    have originalLive : candidate - 1 < log.length := by
      simp [NativeArrayRetirementIndex.virtualLog, NativeArrayLogWrite.append,
        NativeArrayCheckQuorum.Log.ofList] at live
      omega
    have castSub : (candidate : Int) - 1 = ((candidate - 1 : Nat) : Int) := by omega
    have evaluated :
        (virtualLogEntryTerm width bootstrap (entries.weaken .int) (.bound .here)).eval
            assignment (locals.cons (candidate : Int)) =
          entries.eval assignment locals (candidate - 1 : Nat) := by
      simp [virtualLogEntryTerm, Term.eval, Term.weaken_eval, Locals.cons, zero, castSub]
    rw [evaluated, sameEntries (candidate - 1) originalLive]
    simp [NativeArrayRetirementIndex.virtualLog, NativeArrayLogWrite.append,
      NativeArrayCheckQuorum.Log.ofList]
    intro same
    exact (zero same).elim

theorem configuration_includes_term_eval {context : List Ty} {width : PNat}
    (assignment : Assignment) (locals : Locals context)
    (entry : Term context (entryTy width)) (node : Fin width) (position : Nat) :
    (configurationIncludesTerm entry node).eval assignment locals =
      NativeArrayRetirementIndex.includes node position
        (modelEntry (entry.eval assignment locals)) := by
  apply Bool.eq_iff_iff.mpr
  simp only [configurationIncludesTerm, all, List.foldr_cons, List.foldr_nil,
    Term.eval, Bool.and_eq_true, and_true]
  rcases decoded : entry.eval assignment locals with ⟨term, content⟩
  cases content with
  | inl payload =>
    cases payload
    simp only [isConfiguration, members, Term.eval]
    rw [decoded]
    simp [NativeArrayRetirementIndex.includes, NativeArrayRetirementIndex.configurationPredicate,
      modelEntry, decodeContent]
  | inr rest =>
    cases rest with
    | inl transaction =>
      simp only [isConfiguration, members, Term.eval]
      rw [decoded]
      simp [NativeArrayRetirementIndex.includes, NativeArrayRetirementIndex.configurationPredicate,
        Locals.cons, modelEntry, decodeContent]
    | inr tagged =>
      cases tagged with
      | inl configuration =>
        simp only [isConfiguration, members, Term.eval]
        rw [decoded]
        simp [NativeArrayRetirementIndex.includes, NativeArrayRetirementIndex.configurationPredicate,
          Locals.cons, modelEntry, decodeContent]
      | inr retired =>
        simp only [isConfiguration, members, Term.eval]
        rw [decoded]
        simp [NativeArrayRetirementIndex.includes, NativeArrayRetirementIndex.configurationPredicate,
          Locals.cons, modelEntry, decodeContent]

theorem configuration_excludes_after_term_eval {context : List Ty} {width : PNat}
    (assignment : Assignment) (locals : Locals context)
    (entry : Term context (entryTy width)) (node : Fin width)
    (first candidate : Term context .int) (firstIndex position : Nat)
    (sameFirst : first.eval assignment locals = (firstIndex : Int))
    (samePosition : candidate.eval assignment locals = (position : Int)) :
    (configurationExcludesAfterTerm entry node first candidate).eval assignment locals =
      NativeArrayRetirementIndex.excludesAfter node firstIndex position
        (modelEntry (entry.eval assignment locals)) := by
  apply Bool.eq_iff_iff.mpr
  simp only [configurationExcludesAfterTerm, all, List.foldr_cons, List.foldr_nil,
    Term.eval, Bool.and_eq_true, and_true]
  rcases decoded : entry.eval assignment locals with ⟨term, content⟩
  cases content with
  | inl payload =>
    cases payload
    simp only [lt, isConfiguration, members, Term.eval, sameFirst, samePosition]
    rw [decoded]
    simp [NativeArrayRetirementIndex.excludesAfter,
      NativeArrayRetirementIndex.configurationPredicate, modelEntry, decodeContent]
  | inr rest =>
    cases rest with
    | inl transaction =>
      simp only [lt, isConfiguration, members, Term.eval, sameFirst, samePosition]
      rw [decoded]
      simp [NativeArrayRetirementIndex.excludesAfter,
        NativeArrayRetirementIndex.configurationPredicate, Locals.cons, modelEntry, decodeContent]
    | inr tagged =>
      cases tagged with
      | inl configuration =>
        simp only [lt, isConfiguration, members, Term.eval, sameFirst, samePosition]
        rw [decoded]
        simp [NativeArrayRetirementIndex.excludesAfter,
          NativeArrayRetirementIndex.configurationPredicate, Locals.cons, modelEntry, decodeContent]
      | inr retired =>
        simp only [lt, isConfiguration, members, Term.eval, sameFirst, samePosition]
        rw [decoded]
        simp [NativeArrayRetirementIndex.excludesAfter,
          NativeArrayRetirementIndex.configurationPredicate, Locals.cons, modelEntry, decodeContent]

theorem retirement_inclusion_predicate_eval {context : List Ty} {width : PNat}
    [Bootstrap (Fin width)] (assignment : Assignment) (locals : Locals context)
    (bootstrap : BitVec width) (entries : Term context (.array .int (entryTy width)))
    (node : Fin width) (log : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (candidate : Nat) (live : candidate < (NativeArrayRetirementIndex.virtualLog log).length)
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (sameEntries : forall index, index < log.length ->
      modelEntry (entries.eval assignment locals (index : Int)) = log.entries index) :
    (retirementInclusionPredicate width bootstrap entries node).eval
        assignment (locals.cons (candidate : Int)) =
      NativeArrayRetirementIndex.includes node candidate
        ((NativeArrayRetirementIndex.virtualLog log).entries candidate) := by
  have same := virtual_log_entry_term_eval assignment locals bootstrap entries log candidate live
    sameBootstrap sameEntries
  rw [retirementInclusionPredicate, configuration_includes_term_eval]
  rw [same]

theorem retirement_exclusion_predicate_eval {context : List Ty} {width : PNat}
    [Bootstrap (Fin width)] (assignment : Assignment) (locals : Locals context)
    (bootstrap : BitVec width) (entries : Term context (.array .int (entryTy width)))
    (node : Fin width) (first : Term context .int)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (firstIndex candidate : Nat)
    (live : candidate < (NativeArrayRetirementIndex.virtualLog log).length)
    (sameFirst : first.eval assignment locals = (firstIndex : Int))
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (sameEntries : forall index, index < log.length ->
      modelEntry (entries.eval assignment locals (index : Int)) = log.entries index) :
    (retirementExclusionPredicate width bootstrap entries node first).eval
        assignment (locals.cons (candidate : Int)) =
      NativeArrayRetirementIndex.excludesAfter node firstIndex candidate
        ((NativeArrayRetirementIndex.virtualLog log).entries candidate) := by
  have same := virtual_log_entry_term_eval assignment locals bootstrap entries log candidate live
    sameBootstrap sameEntries
  rw [retirementExclusionPredicate]
  rw [configuration_excludes_after_term_eval assignment (locals.cons (candidate : Int))
    _ node (first.weaken .int) (.bound .here) firstIndex candidate]
  · rw [same]
  · simpa only [Term.weaken_eval] using sameFirst
  · simp [Term.eval, Locals.cons]

theorem retirement_index_term_correct {context : List Ty} {width : PNat}
    [Bootstrap (Fin width)] (assignment : Assignment) (locals : Locals context)
    (bootstrap : BitVec width) (limit : Term context .int)
    (entries : Term context (.array .int (entryTy width))) (node : Fin width)
    (first retirement : Term context .int)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (firstOption retirementOption : Option Nat)
    (sameLimit : limit.eval assignment locals = (log.length : Int))
    (sameFirst : first.eval assignment locals = firstMatchValue firstOption)
    (sameRetirement : retirement.eval assignment locals = firstMatchValue retirementOption)
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (sameEntries : forall index, index < log.length ->
      modelEntry (entries.eval assignment locals (index : Int)) = log.entries index) :
    (retirementIndexTerm width bootstrap limit entries node first retirement).eval
        assignment locals = true <->
      NativeArrayFirstMatch.FirstMatch (NativeArrayRetirementIndex.virtualLog log)
          (NativeArrayRetirementIndex.includes node) firstOption /\
        retirementIndexInLog node log.decode = retirementOption := by
  let virtual := NativeArrayRetirementIndex.virtualLog log
  let virtualLimit : Term context .int := .add (.integer 1) limit
  have sameVirtualLimit :
      virtualLimit.eval assignment locals = (virtual.length : Int) := by
    simp [virtual, NativeArrayRetirementIndex.virtualLog, NativeArrayLogWrite.append,
      virtualLimit, Term.eval, sameLimit, NativeArrayCheckQuorum.Log.ofList]
  have inclusion :=
    first_match_term_correct assignment locals virtualLimit first
      (retirementInclusionPredicate width bootstrap entries node) virtual
      (NativeArrayRetirementIndex.includes node) firstOption sameVirtualLimit sameFirst
      (fun index live => retirement_inclusion_predicate_eval assignment locals bootstrap entries
        node log index live sameBootstrap sameEntries)
  simp only [retirementIndexTerm, all, List.foldr_cons, List.foldr_nil, Term.eval,
    Bool.and_eq_true, and_true]
  rw [inclusion]
  constructor
  · rintro ⟨firstCorrect, conditional⟩
    refine ⟨firstCorrect, ?_⟩
    apply (NativeArrayRetirementIndex.retirement_index_correct
      log node firstOption retirementOption firstCorrect).mp
    cases firstOption with
    | none =>
      simp only [firstMatchValue] at sameFirst
      simp [sameFirst, sameRetirement, firstMatchValue] at conditional
      change retirementOption = none
      cases retirementOption with
      | none => rfl
      | some index => simp at conditional
    | some firstIndex =>
      have exclusion :=
        first_match_term_correct assignment locals virtualLimit retirement
          (retirementExclusionPredicate width bootstrap entries node first) virtual
          (NativeArrayRetirementIndex.excludesAfter node firstIndex) retirementOption
          sameVirtualLimit sameRetirement
          (fun index live => retirement_exclusion_predicate_eval assignment locals bootstrap entries
            node first log firstIndex index live
            (by simpa only [firstMatchValue] using sameFirst) sameBootstrap sameEntries)
      simp only [firstMatchValue] at sameFirst
      simp [sameFirst] at conditional
      change NativeArrayFirstMatch.FirstMatch virtual
        (NativeArrayRetirementIndex.excludesAfter node firstIndex) retirementOption
      apply exclusion.mp
      simpa only [virtualLimit] using conditional
  · rintro ⟨firstCorrect, retirementCorrect⟩
    refine ⟨firstCorrect, ?_⟩
    have witnessed := (NativeArrayRetirementIndex.retirement_index_correct
      log node firstOption retirementOption firstCorrect).mpr retirementCorrect
    cases firstOption with
    | none =>
      simp only [firstMatchValue] at sameFirst
      change retirementOption = none at witnessed
      rw [witnessed] at sameRetirement
      simp [sameFirst, sameRetirement, firstMatchValue]
    | some firstIndex =>
      have exclusion :=
        first_match_term_correct assignment locals virtualLimit retirement
          (retirementExclusionPredicate width bootstrap entries node first) virtual
          (NativeArrayRetirementIndex.excludesAfter node firstIndex) retirementOption
          sameVirtualLimit sameRetirement
          (fun index live => retirement_exclusion_predicate_eval assignment locals bootstrap entries
            node first log firstIndex index live
            (by simpa only [firstMatchValue] using sameFirst) sameBootstrap sameEntries)
      simp only [firstMatchValue] at sameFirst
      change NativeArrayFirstMatch.FirstMatch virtual
        (NativeArrayRetirementIndex.excludesAfter node firstIndex) retirementOption at witnessed
      have held := exclusion.mpr witnessed
      simp [sameFirst]
      simpa only [virtualLimit] using held

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
