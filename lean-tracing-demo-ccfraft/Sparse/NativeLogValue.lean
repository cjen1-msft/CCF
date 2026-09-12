-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeEncodeProofs
import Sparse.NativeRenaming

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def logTy (width : PNat) : Ty := .pair .int (.array .int (entryTy width))

def defaultLogEntry (width : PNat) : Entry (Fin width) Nat :=
  { term := 0, content := .signature }

def logValue {width : PNat} (entries : List (Entry (Fin width) Nat)) : (logTy width).denote :=
  (entries.length, fun index =>
    if 0 <= index then entryValue (entries[index.toNat]?.getD (defaultLogEntry width))
    else entryValue (defaultLogEntry width))

def modelLog {width : PNat} (value : (logTy width).denote) : List (Entry (Fin width) Nat) :=
  List.ofFn fun index : Fin value.1.toNat => modelEntry (value.2 index.val)

structure LogValueValid {width : PNat} (value : (logTy width).denote) : Prop where
  length : 0 <= value.1
  entries : forall index : Int, 0 <= index /\ index < value.1 -> EntryValid (value.2 index)
  tail : forall index : Int, index < 0 \/ value.1 <= index ->
    value.2 index = entryValue (defaultLogEntry width)

def logCellDomain {context : List Ty} {width : PNat}
    (value : Term context (logTy width)) (index : Term context .int) : Term context .bool :=
  let cell := Term.select (Term.snd value) index
  .and
    (implies (.and (.le (.integer 0) index) (lt index (.fst value))) (entryDomain cell))
    (implies (.or (lt index (.integer 0)) (.le (.fst value) index))
      (.equal cell (entryTerm (defaultLogEntry width))))

def logDomain {context : List Ty} {width : PNat}
    (value : Term context (logTy width)) : Term context .bool :=
  .and (.le (.integer 0) (.fst value))
    (.forall_ .int (logCellDomain (value.weaken .int) (.bound .here)))

theorem log_cell_domain_correct {context : List Ty} {width : PNat}
    (value : Term context (logTy width)) (index : Term context .int)
    (assignment : Assignment) (locals : Locals context) :
    (logCellDomain value index).eval assignment locals = true <->
      ((0 <= index.eval assignment locals /\ index.eval assignment locals < (value.eval assignment locals).1 ->
          EntryValid ((value.eval assignment locals).2 (index.eval assignment locals))) /\
        (index.eval assignment locals < 0 \/ (value.eval assignment locals).1 <= index.eval assignment locals ->
          (value.eval assignment locals).2 (index.eval assignment locals) = entryValue (defaultLogEntry width))) := by
  simp only [logCellDomain, Term.eval, Bool.and_eq_true]
  rw [implies_eval, implies_eval, entry_domain_correct]
  simp [lt, Term.eval, entry_term_eval]

theorem log_domain_correct {context : List Ty} {width : PNat}
    (value : Term context (logTy width)) (assignment : Assignment) (locals : Locals context) :
    (logDomain value).eval assignment locals = true <-> LogValueValid (value.eval assignment locals) := by
  simp only [logDomain, Term.eval, Bool.and_eq_true, decide_eq_true_eq]
  constructor
  · rintro ⟨length, rows⟩
    have cells (index : Int) := (log_cell_domain_correct (value.weaken .int) (.bound .here)
      assignment (locals.cons index)).mp (rows index)
    simp only [Term.weaken_eval, Term.eval, Locals.cons] at cells
    exact ⟨length, fun index => (cells index).1, fun index => (cells index).2⟩
  · intro valid
    refine ⟨valid.length, ?_⟩
    intro index
    apply (log_cell_domain_correct (value.weaken .int) (.bound .here)
      assignment (locals.cons index)).mpr
    simpa only [Term.weaken_eval, Term.eval, Locals.cons] using
      And.intro (valid.entries index) (valid.tail index)

@[simp] theorem log_value_valid {width : PNat} (entries : List (Entry (Fin width) Nat)) :
    LogValueValid (logValue entries) := by
  constructor
  · simp [logValue]
  · intro index _
    dsimp only [logValue]
    split <;> exact entry_value_valid _
  · intro index outside
    change index < 0 \/ (entries.length : Int) <= index at outside
    by_cases nonnegative : 0 <= index
    · have beyond : entries.length <= index.toNat := by omega
      simp [logValue, nonnegative, List.getElem?_eq_none beyond]
    · simp [logValue, nonnegative]

@[simp] theorem model_log_value {width : PNat} (entries : List (Entry (Fin width) Nat)) :
    modelLog (logValue entries) = entries := by
  simp [modelLog, logValue, List.ofFn_getElem]

theorem log_value_model {width : PNat} (value : (logTy width).denote)
    (valid : LogValueValid value) : logValue (modelLog value) = value := by
  have lengths : (logValue (modelLog value)).1 = value.1 := by
    simp [logValue, modelLog, Int.toNat_of_nonneg valid.length]
  apply Prod.ext lengths
  funext index
  by_cases live : 0 <= index /\ index < value.1
  · have within : index.toNat < value.1.toNat :=
      (Int.toNat_lt_toNat (lt_of_le_of_lt live.1 live.2)).mpr live.2
    simp only [logValue, if_pos live.1, modelLog, List.getElem?_ofFn,
      dif_pos within, Option.getD_some, Int.toNat_of_nonneg live.1]
    exact entry_value_model _ (valid.entries index live)
  · have outside : index < 0 \/ value.1 <= index := by
      rcases not_and_or.mp live with negative | beyond
      · exact Or.inl (lt_of_not_ge negative)
      · exact Or.inr (le_of_not_gt beyond)
    have left := (log_value_valid (modelLog value)).tail index (by simpa only [lengths] using outside)
    exact left.trans (valid.tail index outside).symm

theorem model_log_eq_iff {width : PNat} (value : (logTy width).denote)
    (entries : List (Entry (Fin width) Nat)) (valid : LogValueValid value) :
    value = logValue entries <-> modelLog value = entries := by
  constructor
  · rintro rfl
    exact model_log_value entries
  · intro same
    rw [<- same, log_value_model value valid]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
