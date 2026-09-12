-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeLogValue

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def logMatches {context : List Ty} {width : PNat}
    (value : Term context (logTy width)) (entries : List (Entry (Fin width) Nat)) :
    Term context .bool :=
  .and (.equal (.fst value) (.integer entries.length))
    (all (List.ofFn fun index : Fin entries.length =>
      .equal (.select (.snd value) (.integer index.val)) (entryTerm (entries.get index))))

theorem log_value_eq_iff {width : PNat} (value : (logTy width).denote)
    (entries : List (Entry (Fin width) Nat)) (valid : LogValueValid value) :
    value = logValue entries <->
      value.1 = (entries.length : Int) /\
        forall index : Fin entries.length, value.2 index.val = entryValue (entries.get index) := by
  constructor
  · rintro rfl
    refine ⟨rfl, ?_⟩
    intro index
    simp [logValue, index.isLt]
  · rintro ⟨length, cells⟩
    apply Prod.ext length
    funext index
    by_cases live : 0 <= index /\ index < value.1
    · have bound : index < (entries.length : Int) := by simpa only [length] using live.2
      have within : index.toNat < entries.length := by
        simpa using (Int.toNat_lt_toNat (lt_of_le_of_lt live.1 bound)).mpr bound
      let position : Fin entries.length := ⟨index.toNat, within⟩
      have sameIndex : (position.val : Int) = index := Int.toNat_of_nonneg live.1
      rw [<- sameIndex]
      simpa [logValue, position.isLt] using cells position
    · have outside : index < 0 \/ value.1 <= index := by
        rcases not_and_or.mp live with negative | beyond
        · exact Or.inl (lt_of_not_ge negative)
        · exact Or.inr (le_of_not_gt beyond)
      rw [valid.tail index outside,
        (log_value_valid entries).tail index (by simpa only [logValue, <- length] using outside)]

theorem log_matches_correct {context : List Ty} {width : PNat}
    (value : Term context (logTy width)) (entries : List (Entry (Fin width) Nat))
    (assignment : Assignment) (locals : Locals context)
    (valid : LogValueValid (value.eval assignment locals)) :
    (logMatches value entries).eval assignment locals = true <->
      modelLog (value.eval assignment locals) = entries := by
  rw [<- model_log_eq_iff _ _ valid, log_value_eq_iff _ _ valid]
  simp only [logMatches, Term.eval, Bool.and_eq_true, decide_eq_true_eq]
  rw [all_eval]
  simp [List.mem_ofFn, Term.eval, entry_term_eval]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
