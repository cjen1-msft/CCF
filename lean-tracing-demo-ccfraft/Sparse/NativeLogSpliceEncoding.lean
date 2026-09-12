-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayLogWrite
import Sparse.NativeSignatureEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def logSpliceKeep {context : List Ty}
    (oldLength previous : Term context .int) : Term context .int :=
  .ite (.le previous oldLength) previous oldLength

def logSpliceLength {context : List Ty}
    (oldLength payloadLength previous : Term context .int) : Term context .int :=
  .add (logSpliceKeep oldLength previous) payloadLength

def logSpliceTerm {context : List Ty} (width : PNat)
    (oldLength : Term context .int)
    (oldEntries : Term context (.array .int (entryTy width)))
    (payloadLength : Term context .int)
    (payloadEntries : Term context (.array .int (entryTy width)))
    (previous : Term context .int)
    (outputEntries : Term context (.array .int (entryTy width))) :
    Term context .bool :=
  .forall_ .int (
    let position : Term (.int :: context) .int := .bound .here
    let keep := (logSpliceKeep oldLength previous).weaken .int
    let resultLength := (logSpliceLength oldLength payloadLength previous).weaken .int
    implies
      (all [.le (.integer 0) position, lt position resultLength])
      (.equal
        (.select (outputEntries.weaken .int) position)
        (.ite (lt position keep)
          (.select (oldEntries.weaken .int) position)
          (.select (payloadEntries.weaken .int) (.sub position keep)))))

theorem log_splice_keep_eval {context : List Ty}
    (assignment : Assignment) (locals : Locals context)
    (oldLength previous : Term context .int) :
    (logSpliceKeep oldLength previous).eval assignment locals =
      min (previous.eval assignment locals) (oldLength.eval assignment locals) := by
  simp [logSpliceKeep, Term.eval, min_def]

theorem log_splice_length_eval {context : List Ty}
    (assignment : Assignment) (locals : Locals context)
    (oldLength payloadLength previous : Term context .int) :
    (logSpliceLength oldLength payloadLength previous).eval assignment locals =
      min (previous.eval assignment locals) (oldLength.eval assignment locals) +
        payloadLength.eval assignment locals := by
  simp [logSpliceLength, Term.eval, log_splice_keep_eval]

theorem log_splice_term_eval {context : List Ty} {width : PNat}
    (assignment : Assignment) (locals : Locals context)
    (oldLength : Term context .int)
    (oldEntries : Term context (.array .int (entryTy width)))
    (payloadLength : Term context .int)
    (payloadEntries : Term context (.array .int (entryTy width)))
    (previous : Term context .int)
    (outputEntries : Term context (.array .int (entryTy width))) :
    (logSpliceTerm width oldLength oldEntries payloadLength payloadEntries previous
      outputEntries).eval assignment locals = true <->
      forall position : Int,
        0 <= position ->
        position <
          min (previous.eval assignment locals) (oldLength.eval assignment locals) +
            payloadLength.eval assignment locals ->
        outputEntries.eval assignment locals position =
          if position <
              min (previous.eval assignment locals) (oldLength.eval assignment locals) then
            oldEntries.eval assignment locals position
          else
            payloadEntries.eval assignment locals
              (position -
                min (previous.eval assignment locals) (oldLength.eval assignment locals)) := by
  simp only [logSpliceTerm, Term.eval, decide_eq_true_eq]
  constructor
  · intro accepted position nonnegative within
    have premise :
        (all [
          .le (.integer 0) (.bound .here),
          lt (.bound .here)
            ((logSpliceLength oldLength payloadLength previous).weaken .int)]).eval
          assignment (locals.cons position) = true := by
      simp [all, Term.eval, Term.weaken_eval, Locals.cons, lt,
        log_splice_length_eval, nonnegative, within]
    have copied := (implies_eval
      (all [
        .le (.integer 0) (.bound .here),
        lt (.bound .here)
          ((logSpliceLength oldLength payloadLength previous).weaken .int)])
      (.equal
        (.select (outputEntries.weaken .int) (.bound .here))
        (.ite
          (lt (.bound .here) ((logSpliceKeep oldLength previous).weaken .int))
          (.select (oldEntries.weaken .int) (.bound .here))
          (.select (payloadEntries.weaken .int)
            (.sub (.bound .here) ((logSpliceKeep oldLength previous).weaken .int)))))
      assignment (locals.cons position)).mp (accepted position) premise
    simpa [lt, Term.eval, Term.weaken_eval, Locals.cons, logSpliceKeep, min_def] using copied
  · intro copies position
    apply (implies_eval
      (all [
        .le (.integer 0) (.bound .here),
        lt (.bound .here)
          ((logSpliceLength oldLength payloadLength previous).weaken .int)])
      (.equal
        (.select (outputEntries.weaken .int) (.bound .here))
        (.ite
          (lt (.bound .here) ((logSpliceKeep oldLength previous).weaken .int))
          (.select (oldEntries.weaken .int) (.bound .here))
          (.select (payloadEntries.weaken .int)
            (.sub (.bound .here) ((logSpliceKeep oldLength previous).weaken .int)))))
      assignment (locals.cons position)).mpr
    intro live
    have separated := live
    simp only [all, List.foldr_cons, List.foldr_nil, Term.eval, Bool.and_eq_true,
      and_true] at separated
    have nonnegative : 0 <= position := by
      simpa only [Term.eval, decide_eq_true_eq] using separated.1
    have within :
        position <
          min (previous.eval assignment locals) (oldLength.eval assignment locals) +
            payloadLength.eval assignment locals := by
      have upper := separated.2
      simpa only [lt, Term.eval, Term.weaken_eval, Locals.cons,
        log_splice_length_eval, Bool.not_eq_true', decide_eq_false_iff_not, not_le] using upper
    have copied := copies position nonnegative within
    simpa [lt, Term.eval, Term.weaken_eval, Locals.cons, logSpliceKeep, min_def] using copied

theorem log_splice_term_sound {context : List Ty} {width : PNat}
    (assignment : Assignment) (locals : Locals context)
    (oldLength : Term context .int)
    (oldEntries : Term context (.array .int (entryTy width)))
    (payloadLength : Term context .int)
    (payloadEntries : Term context (.array .int (entryTy width)))
    (previous : Term context .int)
    (outputEntries : Term context (.array .int (entryTy width)))
    (oldLog payload : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (previousIndex : Nat)
    (sameOldLength : oldLength.eval assignment locals = (oldLog.length : Int))
    (samePayloadLength : payloadLength.eval assignment locals = (payload.length : Int))
    (samePrevious : previous.eval assignment locals = (previousIndex : Int))
    (sameOldEntries : forall index, index < oldLog.length ->
      modelEntry (oldEntries.eval assignment locals (index : Int)) = oldLog.entries index)
    (samePayloadEntries : forall index, index < payload.length ->
      modelEntry (payloadEntries.eval assignment locals (index : Int)) = payload.entries index)
    (holds : (logSpliceTerm width oldLength oldEntries payloadLength payloadEntries previous
      outputEntries).eval assignment locals = true) :
    forall index, index < (NativeArrayLogWrite.splice oldLog payload previousIndex).length ->
      modelEntry (outputEntries.eval assignment locals (index : Int)) =
        (NativeArrayLogWrite.splice oldLog payload previousIndex).entries index := by
  intro index live
  have copied := (log_splice_term_eval assignment locals oldLength oldEntries payloadLength
    payloadEntries previous outputEntries).mp holds (index : Int) (by omega)
  simp only [sameOldLength, samePayloadLength, samePrevious] at copied
  have resultLength :
      (NativeArrayLogWrite.splice oldLog payload previousIndex).length =
        min previousIndex oldLog.length + payload.length := rfl
  have within :
      (index : Int) < (min previousIndex oldLog.length : Nat) + payload.length := by
    rw [resultLength] at live
    exact_mod_cast live
  rw [<- Nat.cast_min] at copied
  specialize copied within
  by_cases inPrefix : index < min previousIndex oldLog.length
  · have prefixInt : (index : Int) < (min previousIndex oldLog.length : Nat) :=
      Int.ofNat_lt.mpr inPrefix
    rw [if_pos prefixInt] at copied
    calc
      modelEntry (outputEntries.eval assignment locals (index : Int)) =
          modelEntry (oldEntries.eval assignment locals (index : Int)) :=
        congrArg modelEntry copied
      _ = oldLog.entries index :=
        sameOldEntries index (lt_of_lt_of_le inPrefix (Nat.min_le_right _ _))
      _ = (NativeArrayLogWrite.splice oldLog payload previousIndex).entries index :=
        (NativeArrayLogWrite.splice_prefix oldLog payload previousIndex index inPrefix).symm
  · have keepWithin : min previousIndex oldLog.length <= index := Nat.not_lt.mp inPrefix
    have payloadLive : index - min previousIndex oldLog.length < payload.length := by
      rw [resultLength] at live
      omega
    have suffixInt :
        Not ((index : Int) < (min previousIndex oldLog.length : Nat)) := by
      exact not_lt.mpr (Int.ofNat_le.mpr keepWithin)
    have difference :
        (index : Int) - (min previousIndex oldLog.length : Nat) =
          ((index - min previousIndex oldLog.length : Nat) : Int) := by
      omega
    rw [if_neg suffixInt, difference] at copied
    have split : min previousIndex oldLog.length +
        (index - min previousIndex oldLog.length) = index := Nat.add_sub_of_le keepWithin
    calc
      modelEntry (outputEntries.eval assignment locals (index : Int)) =
          modelEntry (payloadEntries.eval assignment locals
            (index - min previousIndex oldLog.length : Nat)) :=
        congrArg modelEntry copied
      _ = payload.entries (index - min previousIndex oldLog.length) :=
        samePayloadEntries _ payloadLive
      _ = (NativeArrayLogWrite.splice oldLog payload previousIndex).entries index := by
        have payloadAt := NativeArrayLogWrite.splice_payload oldLog payload previousIndex
          (index - min previousIndex oldLog.length)
        rw [split] at payloadAt
        exact payloadAt.symm

def spliceRawOutput {width : PNat}
    (oldEntries payloadEntries tail : Int -> (entryTy width).denote)
    (oldLength payloadLength previous : Nat) : Int -> (entryTy width).denote :=
  let keep := min previous oldLength
  let resultLength := keep + payloadLength
  fun position =>
    if 0 <= position /\ position < (resultLength : Int) then
      if position < (keep : Int) then
        oldEntries position
      else
        payloadEntries (position - keep)
    else
      tail position

theorem splice_raw_output_live {width : PNat}
    (oldEntries payloadEntries tail : Int -> (entryTy width).denote)
    (oldLength payloadLength previous : Nat) (position : Int)
    (nonnegative : 0 <= position)
    (within : position < (min previous oldLength + payloadLength : Nat)) :
    spliceRawOutput oldEntries payloadEntries tail oldLength payloadLength previous position =
      if position < (min previous oldLength : Nat) then
        oldEntries position
      else
        payloadEntries (position - min previous oldLength) := by
  have withinInt :
      position < (min previous oldLength : Int) + (payloadLength : Int) := by
    exact_mod_cast within
  simp [spliceRawOutput, nonnegative, withinInt, Nat.cast_min]

theorem log_splice_term_complete {context : List Ty} {width : PNat}
    (assignment : Assignment) (locals : Locals context)
    (oldLength : Term context .int)
    (oldEntries : Term context (.array .int (entryTy width)))
    (payloadLength : Term context .int)
    (payloadEntries : Term context (.array .int (entryTy width)))
    (previous : Term context .int)
    (outputEntries : Term context (.array .int (entryTy width)))
    (oldLengthValue payloadLengthValue previousIndex : Nat)
    (tail : Int -> (entryTy width).denote)
    (sameOldLength : oldLength.eval assignment locals = (oldLengthValue : Int))
    (samePayloadLength : payloadLength.eval assignment locals = (payloadLengthValue : Int))
    (samePrevious : previous.eval assignment locals = (previousIndex : Int))
    (sameOutput : outputEntries.eval assignment locals =
      spliceRawOutput (oldEntries.eval assignment locals)
        (payloadEntries.eval assignment locals) tail
        oldLengthValue payloadLengthValue previousIndex) :
    (logSpliceTerm width oldLength oldEntries payloadLength payloadEntries previous
      outputEntries).eval assignment locals = true := by
  apply (log_splice_term_eval assignment locals oldLength oldEntries payloadLength
    payloadEntries previous outputEntries).mpr
  intro position nonnegative within
  simp only [sameOldLength, samePayloadLength, samePrevious] at within ⊢
  rw [<- Nat.cast_min] at within ⊢
  rw [sameOutput, splice_raw_output_live _ _ _ _ _ _ position nonnegative]
  exact within

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
