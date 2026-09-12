-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeFirstMatchEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem first_match_term_witness {context : List Ty}
    (assignment : Assignment) (locals : Locals context)
    (limit selected : Term context .int) (predicate : Term (.int :: context) .bool)
    (accepted : (firstMatchTerm limit selected predicate).eval assignment locals = true) :
    exists choice : Option Nat,
      selected.eval assignment locals = firstMatchValue choice := by
  rcases ((first_match_term_eval assignment locals limit selected predicate).mp accepted).1 with
    sentinel | ⟨nonnegative, _⟩
  · exact ⟨none, sentinel⟩
  · refine ⟨some (selected.eval assignment locals).toNat, ?_⟩
    simp only [firstMatchValue]
    exact (Int.toNat_of_nonneg nonnegative).symm

theorem first_match_term_sound {context : List Ty} {N T : Type}
    (assignment : Assignment) (locals : Locals context)
    (limit selected : Term context .int) (predicate : Term (.int :: context) .bool)
    (log : NativeArrayCheckQuorum.Log N T) (test : Nat -> Entry N T -> Bool)
    (accepted : (firstMatchTerm limit selected predicate).eval assignment locals = true)
    (sameLimit : limit.eval assignment locals = (log.length : Int))
    (samePredicate : forall index, index < log.length ->
      predicate.eval assignment (locals.cons (index : Int)) = test index (log.entries index)) :
    exists choice : Option Nat,
      selected.eval assignment locals = firstMatchValue choice /\
        NativeArrayFirstMatch.FirstMatch log test choice := by
  obtain ⟨choice, sameChoice⟩ :=
    first_match_term_witness assignment locals limit selected predicate accepted
  exact ⟨choice, sameChoice,
    (first_match_term_correct assignment locals limit selected predicate log test choice
      sameLimit sameChoice samePredicate).mp accepted⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
