-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeLogValue

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def logCellsTerm {context : List Ty} {width : PNat}
    (entries : List (Entry (Fin width) Nat)) : Nat -> Term context (.array .int (entryTy width))
  | 0 => .defaultValue _
  | count + 1 =>
    .store (logCellsTerm entries count) (.integer count)
      (entryTerm (entries[count]?.getD (defaultLogEntry width)))

def logTerm {context : List Ty} {width : PNat} (entries : List (Entry (Fin width) Nat)) :
    Term context (logTy width) :=
  .pair (.integer entries.length) (logCellsTerm entries entries.length)

theorem log_cells_term_eval {context : List Ty} {width : PNat}
    (entries : List (Entry (Fin width) Nat)) (count : Nat)
    (assignment : Assignment) (locals : Locals context) (index : Int) :
    (logCellsTerm entries count).eval assignment locals index =
      if 0 <= index /\ index < (count : Int) then
        entryValue (entries[index.toNat]?.getD (defaultLogEntry width))
      else entryValue (defaultLogEntry width) := by
  classical
  induction count with
  | zero =>
    have outside : ¬ (0 <= index /\ index < (0 : Int)) := by omega
    simp only [logCellsTerm, Term.eval, Nat.cast_zero, if_neg outside]
    rfl
  | succ count previous =>
    simp only [logCellsTerm, Term.eval, entry_term_eval]
    by_cases same : index = (count : Int)
    · subst index
      simp
    · simp only [Function.update_apply, same, if_false, previous]
      have range : (0 <= index /\ index < ((count + 1 : Nat) : Int)) <->
          (0 <= index /\ index < (count : Int)) := by omega
      simp only [range]

theorem log_term_eval {context : List Ty} {width : PNat}
    (entries : List (Entry (Fin width) Nat)) (assignment : Assignment) (locals : Locals context) :
    (logTerm entries).eval assignment locals = logValue entries := by
  refine Prod.ext ?_ ?_
  · rfl
  funext (index : Int)
  simp only [logTerm, Term.eval, log_cells_term_eval, logValue]
  by_cases nonnegative : 0 <= index
  · by_cases within : index < (entries.length : Int)
    · simp [nonnegative, within]
    · simp [nonnegative, within]
  · simp [nonnegative]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
