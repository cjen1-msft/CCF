-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeFirstMatchWitness
import Sparse.NativeRetirementIndexEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem retirement_index_term_sound {context : List Ty} {width : PNat}
    [Bootstrap (Fin width)] (assignment : Assignment) (locals : Locals context)
    (bootstrap : BitVec width) (limit : Term context .int)
    (entries : Term context (.array .int (entryTy width))) (node : Fin width)
    (first retirement : Term context .int)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (sameLimit : limit.eval assignment locals = (log.length : Int))
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (sameEntries : forall index, index < log.length ->
      modelEntry (entries.eval assignment locals (index : Int)) = log.entries index)
    (accepted : (retirementIndexTerm width bootstrap limit entries node first retirement).eval
      assignment locals = true) :
    exists firstChoice retirementChoice : Option Nat,
      first.eval assignment locals = firstMatchValue firstChoice /\
        retirement.eval assignment locals = firstMatchValue retirementChoice /\
        NativeArrayFirstMatch.FirstMatch (NativeArrayRetirementIndex.virtualLog log)
          (NativeArrayRetirementIndex.includes node) firstChoice /\
        retirementIndexInLog node log.decode = retirementChoice := by
  let virtual := NativeArrayRetirementIndex.virtualLog log
  let virtualLimit : Term context .int := .add (.integer 1) limit
  have sameVirtualLimit :
      virtualLimit.eval assignment locals = (virtual.length : Int) := by
    simp [virtual, virtualLimit, NativeArrayRetirementIndex.virtualLog,
      NativeArrayLogWrite.append, NativeArrayCheckQuorum.Log.ofList, Term.eval, sameLimit]
  have clauses := accepted
  simp only [retirementIndexTerm, all, List.foldr_cons, List.foldr_nil, Term.eval,
    Bool.and_eq_true, and_true] at clauses
  obtain ⟨firstChoice, sameFirst, firstCorrect⟩ :=
    first_match_term_sound assignment locals virtualLimit first
      (retirementInclusionPredicate width bootstrap entries node) virtual
      (NativeArrayRetirementIndex.includes node)
      (by simpa only [virtualLimit] using clauses.1) sameVirtualLimit
      (fun index live => retirement_inclusion_predicate_eval assignment locals bootstrap entries
        node log index live sameBootstrap sameEntries)
  cases firstChoice with
  | none =>
    simp only [firstMatchValue] at sameFirst
    have sameRetirement : retirement.eval assignment locals = firstMatchValue none := by
      simp only [firstMatchValue]
      simpa [sameFirst] using clauses.2
    have correct := (retirement_index_term_correct assignment locals bootstrap limit entries
      node first retirement log none none sameLimit sameFirst sameRetirement
      sameBootstrap sameEntries).mp accepted
    exact ⟨none, none, sameFirst, sameRetirement, correct.1, correct.2⟩
  | some firstIndex =>
    simp only [firstMatchValue] at sameFirst
    have exclusionAccepted :
        (firstMatchTerm virtualLimit retirement
          (retirementExclusionPredicate width bootstrap entries node first)).eval
            assignment locals = true := by
      simpa [sameFirst, virtualLimit] using clauses.2
    obtain ⟨retirementChoice, sameRetirement, _⟩ :=
      first_match_term_sound assignment locals virtualLimit retirement
        (retirementExclusionPredicate width bootstrap entries node first) virtual
        (NativeArrayRetirementIndex.excludesAfter node firstIndex)
        exclusionAccepted sameVirtualLimit
        (fun index live => retirement_exclusion_predicate_eval assignment locals bootstrap entries
          node first log firstIndex index live sameFirst sameBootstrap sameEntries)
    have correct := (retirement_index_term_correct assignment locals bootstrap limit entries
      node first retirement log (some firstIndex) retirementChoice sameLimit sameFirst
      sameRetirement sameBootstrap sameEntries).mp accepted
    exact ⟨some firstIndex, retirementChoice, sameFirst, sameRetirement, correct.1, correct.2⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
