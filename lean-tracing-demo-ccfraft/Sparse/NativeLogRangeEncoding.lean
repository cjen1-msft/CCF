-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayLogRanges
import Sparse.NativeEntryNormalize
import Sparse.NativeSignatureEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def boundedForall {context : List Ty} (count : Term context .int)
    (predicate : Term (.int :: context) .bool) : Term context .bool :=
  .forall_ .int (implies
    (all [.le (.integer 0) (.bound .here),
      lt (.bound .here) (count.weaken .int)])
    predicate)

theorem bounded_forall_eval {context : List Ty}
    (assignment : Assignment) (locals : Locals context)
    (count : Term context .int) (predicate : Term (.int :: context) .bool) :
    (boundedForall count predicate).eval assignment locals = true <->
      forall offset : Int, 0 <= offset -> offset < count.eval assignment locals ->
        predicate.eval assignment (locals.cons offset) = true := by
  simp only [boundedForall, Term.eval, decide_eq_true_eq]
  constructor
  · intro accepted offset nonnegative within
    apply (implies_eval
      (all [.le (.integer 0) (.bound .here),
        lt (.bound .here) (count.weaken .int)])
      predicate assignment (locals.cons offset)).mp (accepted offset)
    simp [all, Term.eval, Term.weaken_eval, Locals.cons, lt, nonnegative, within]
  · intro accepted offset
    apply (implies_eval
      (all [.le (.integer 0) (.bound .here),
        lt (.bound .here) (count.weaken .int)])
      predicate assignment (locals.cons offset)).mpr
    intro live
    have separated := live
    simp only [all, List.foldr_cons, List.foldr_nil, Term.eval, Bool.and_eq_true,
      and_true] at separated
    have nonnegative : 0 <= offset := by
      simpa only [Term.eval, decide_eq_true_eq] using separated.1
    have within : offset < count.eval assignment locals := by
      have upper := separated.2
      simpa only [lt, Term.eval, Term.weaken_eval, Locals.cons, Bool.not_eq_true',
        decide_eq_false_iff_not, not_le] using upper
    exact accepted offset nonnegative within

def logRangeEntryEqual {context : List Ty} {width : PNat} (termsOnly : Bool)
    (left right : Term context (entryTy width)) : Term context .bool :=
  if termsOnly then
    .equal (.fst (normalizedEntryTerm left)) (.fst (normalizedEntryTerm right))
  else
    .equal (normalizedEntryTerm left) (normalizedEntryTerm right)

theorem entry_value_eq_iff {width : PNat}
    (left right : Entry (Fin width) Nat) :
    entryValue left = entryValue right <-> left = right := by
  constructor
  · intro same
    simpa using congrArg modelEntry same
  · rintro rfl
    rfl

theorem log_range_entry_equal_eval {context : List Ty} {width : PNat}
    (assignment : Assignment) (locals : Locals context) (termsOnly : Bool)
    (left right : Term context (entryTy width)) :
    (logRangeEntryEqual termsOnly left right).eval assignment locals = true <->
      if termsOnly then
        (modelEntry (left.eval assignment locals)).term =
          (modelEntry (right.eval assignment locals)).term
      else
        modelEntry (left.eval assignment locals) =
          modelEntry (right.eval assignment locals) := by
  cases termsOnly with
  | false =>
    simp only [logRangeEntryEqual, Bool.false_eq_true, if_false, Term.eval,
      decide_eq_true_eq,
      normalized_entry_term_correct]
    exact entry_value_eq_iff _ _
  | true =>
    simp [logRangeEntryEqual, Term.eval, normalized_entry_term_correct, entryValue]

def logRangeEqualTerm {context : List Ty} (width : PNat) (termsOnly : Bool)
    (leftEntries rightEntries : Term context (.array .int (entryTy width)))
    (leftStart rightStart count : Term context .int) : Term context .bool :=
  boundedForall count (
    let offset : Term (.int :: context) .int := .bound .here
    let leftIndex := .add (leftStart.weaken .int) offset
    let rightIndex := .add (rightStart.weaken .int) offset
    logRangeEntryEqual termsOnly
      (.select (leftEntries.weaken .int) leftIndex)
      (.select (rightEntries.weaken .int) rightIndex))

theorem log_range_equal_term_eval {context : List Ty} {width : PNat}
    (assignment : Assignment) (locals : Locals context) (termsOnly : Bool)
    (leftEntries rightEntries : Term context (.array .int (entryTy width)))
    (leftStart rightStart count : Term context .int) :
    (logRangeEqualTerm width termsOnly leftEntries rightEntries leftStart rightStart count).eval
        assignment locals = true <->
      forall offset : Int, 0 <= offset -> offset < count.eval assignment locals ->
        if termsOnly then
          (modelEntry (leftEntries.eval assignment locals
            (leftStart.eval assignment locals + offset))).term =
            (modelEntry (rightEntries.eval assignment locals
              (rightStart.eval assignment locals + offset))).term
        else
          modelEntry (leftEntries.eval assignment locals
            (leftStart.eval assignment locals + offset)) =
            modelEntry (rightEntries.eval assignment locals
              (rightStart.eval assignment locals + offset)) := by
  rw [logRangeEqualTerm, bounded_forall_eval]
  apply forall_congr'
  intro offset
  apply imp_congr_right
  intro _
  apply imp_congr_right
  intro _
  rw [log_range_entry_equal_eval]
  simp [Term.eval, Term.weaken_eval, Locals.cons]

theorem log_range_terms_correct {context : List Ty} {width : PNat}
    (assignment : Assignment) (locals : Locals context)
    (leftEntries rightEntries : Term context (.array .int (entryTy width)))
    (leftStart rightStart count : Term context .int)
    (left right : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (leftStartValue rightStartValue countValue : Nat)
    (sameLeftStart : leftStart.eval assignment locals = (leftStartValue : Int))
    (sameRightStart : rightStart.eval assignment locals = (rightStartValue : Int))
    (sameCount : count.eval assignment locals = (countValue : Int))
    (leftLive : forall offset, offset < countValue ->
      leftStartValue + offset < left.length)
    (rightLive : forall offset, offset < countValue ->
      rightStartValue + offset < right.length)
    (sameLeft : forall index, index < left.length ->
      modelEntry (leftEntries.eval assignment locals (index : Int)) = left.entries index)
    (sameRight : forall index, index < right.length ->
      modelEntry (rightEntries.eval assignment locals (index : Int)) = right.entries index) :
    (logRangeEqualTerm width true leftEntries rightEntries leftStart rightStart count).eval
        assignment locals = true <->
      NativeArrayLogRanges.EqualRange Entry.term left right
        leftStartValue rightStartValue countValue := by
  rw [log_range_equal_term_eval]
  simp only [sameLeftStart, sameRightStart, sameCount]
  constructor
  · intro equal offset within
    have compared := equal (offset : Int) (by omega) (Int.ofNat_lt.mpr within)
    have leftIndex : (leftStartValue : Int) + (offset : Int) =
        (leftStartValue + offset : Nat) := by norm_num
    have rightIndex : (rightStartValue : Int) + (offset : Int) =
        (rightStartValue + offset : Nat) := by norm_num
    rw [leftIndex, rightIndex, sameLeft _ (leftLive offset within),
      sameRight _ (rightLive offset within)] at compared
    exact compared
  · intro equal offset nonnegative within
    have natural : (offset.toNat : Int) = offset := Int.toNat_of_nonneg nonnegative
    have bounded : offset.toNat < countValue := by
      exact Int.ofNat_lt.mp (natural.trans_lt within)
    have compared := equal offset.toNat bounded
    have leftIndex : (leftStartValue : Int) + offset =
        (leftStartValue + offset.toNat : Nat) := by omega
    have rightIndex : (rightStartValue : Int) + offset =
        (rightStartValue + offset.toNat : Nat) := by omega
    rw [leftIndex, rightIndex, sameLeft _ (leftLive offset.toNat bounded),
      sameRight _ (rightLive offset.toNat bounded)]
    exact compared

theorem log_range_entries_correct {context : List Ty} {width : PNat}
    (assignment : Assignment) (locals : Locals context)
    (leftEntries rightEntries : Term context (.array .int (entryTy width)))
    (leftStart rightStart count : Term context .int)
    (left right : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (leftStartValue rightStartValue countValue : Nat)
    (sameLeftStart : leftStart.eval assignment locals = (leftStartValue : Int))
    (sameRightStart : rightStart.eval assignment locals = (rightStartValue : Int))
    (sameCount : count.eval assignment locals = (countValue : Int))
    (leftLive : forall offset, offset < countValue ->
      leftStartValue + offset < left.length)
    (rightLive : forall offset, offset < countValue ->
      rightStartValue + offset < right.length)
    (sameLeft : forall index, index < left.length ->
      modelEntry (leftEntries.eval assignment locals (index : Int)) = left.entries index)
    (sameRight : forall index, index < right.length ->
      modelEntry (rightEntries.eval assignment locals (index : Int)) = right.entries index) :
    (logRangeEqualTerm width false leftEntries rightEntries leftStart rightStart count).eval
        assignment locals = true <->
      NativeArrayLogRanges.EqualRange id left right
        leftStartValue rightStartValue countValue := by
  rw [log_range_equal_term_eval]
  simp only [Bool.false_eq_true, if_false, sameLeftStart, sameRightStart, sameCount]
  constructor
  · intro equal offset within
    have compared := equal (offset : Int) (by omega) (Int.ofNat_lt.mpr within)
    have leftIndex : (leftStartValue : Int) + (offset : Int) =
        (leftStartValue + offset : Nat) := by norm_num
    have rightIndex : (rightStartValue : Int) + (offset : Int) =
        (rightStartValue + offset : Nat) := by norm_num
    rw [leftIndex, rightIndex, sameLeft _ (leftLive offset within),
      sameRight _ (rightLive offset within)] at compared
    exact compared
  · intro equal offset nonnegative within
    have natural : (offset.toNat : Int) = offset := Int.toNat_of_nonneg nonnegative
    have bounded : offset.toNat < countValue := by
      exact Int.ofNat_lt.mp (natural.trans_lt within)
    have compared := equal offset.toNat bounded
    have leftIndex : (leftStartValue : Int) + offset =
        (leftStartValue + offset.toNat : Nat) := by omega
    have rightIndex : (rightStartValue : Int) + offset =
        (rightStartValue + offset.toNat : Nat) := by omega
    rw [leftIndex, rightIndex, sameLeft _ (leftLive offset.toNat bounded),
      sameRight _ (rightLive offset.toNat bounded)]
    exact compared

def logRangeMinTerm {context : List Ty}
    (left right : Term context .int) : Term context .int :=
  .ite (.le left right) left right

theorem log_range_min_term_eval {context : List Ty}
    (assignment : Assignment) (locals : Locals context)
    (left right : Term context .int) :
    (logRangeMinTerm left right).eval assignment locals =
      min (left.eval assignment locals) (right.eval assignment locals) := by
  simp [logRangeMinTerm, Term.eval, min_def]

def appendAlreadyDoneTerm {context : List Ty} (width : PNat)
    (oldLength : Term context .int)
    (oldEntries : Term context (.array .int (entryTy width)))
    (payloadLength : Term context .int)
    (payloadEntries : Term context (.array .int (entryTy width)))
    (previous : Term context .int) : Term context .bool :=
  .or (.equal payloadLength (.integer 0))
    (all [
      .le (.add previous payloadLength) oldLength,
      logRangeEqualTerm width true oldEntries payloadEntries
        previous (.integer 0) payloadLength])

def appendTermConflictTerm {context : List Ty} (width : PNat)
    (oldLength : Term context .int)
    (oldEntries : Term context (.array .int (entryTy width)))
    (payloadLength : Term context .int)
    (payloadEntries : Term context (.array .int (entryTy width)))
    (previous : Term context .int) : Term context .bool :=
  .and (.not (.equal payloadLength (.integer 0)))
    (.not (logRangeEqualTerm width true oldEntries payloadEntries
      previous (.integer 0)
      (logRangeMinTerm payloadLength
        (intMaxTerm (.integer 0) (.sub oldLength previous)))))

def appendNoConflictExtensionTerm {context : List Ty} (width : PNat)
    (oldLength : Term context .int)
    (oldEntries : Term context (.array .int (entryTy width)))
    (payloadLength : Term context .int)
    (payloadEntries : Term context (.array .int (entryTy width)))
    (previous : Term context .int) : Term context .bool :=
  all [
    .not (.equal payloadLength (.integer 0)),
    .le previous oldLength,
    lt oldLength (.add previous payloadLength),
    logRangeEqualTerm width false oldEntries payloadEntries
      previous (.integer 0) (intMaxTerm (.integer 0) (.sub oldLength previous))]

theorem append_already_done_term_correct {context : List Ty} {width : PNat}
    (assignment : Assignment) (locals : Locals context)
    (oldLength : Term context .int)
    (oldEntries : Term context (.array .int (entryTy width)))
    (payloadLength : Term context .int)
    (payloadEntries : Term context (.array .int (entryTy width)))
    (previous : Term context .int)
    (oldLog payload : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (previousIndex : Nat)
    (sameOldLength : oldLength.eval assignment locals = (oldLog.length : Int))
    (samePayloadLength : payloadLength.eval assignment locals = (payload.length : Int))
    (samePrevious : previous.eval assignment locals = (previousIndex : Int))
    (sameOld : forall index, index < oldLog.length ->
      modelEntry (oldEntries.eval assignment locals (index : Int)) = oldLog.entries index)
    (samePayload : forall index, index < payload.length ->
      modelEntry (payloadEntries.eval assignment locals (index : Int)) = payload.entries index) :
    (appendAlreadyDoneTerm width oldLength oldEntries payloadLength payloadEntries previous).eval
        assignment locals = true <->
      NativeArrayLogRanges.AlreadyDone oldLog payload previousIndex := by
  by_cases empty : payload.length = 0
  · simp [appendAlreadyDoneTerm, all, Term.eval, sameOldLength, samePayloadLength,
      samePrevious, NativeArrayLogRanges.AlreadyDone, empty]
  · by_cases fits : previousIndex + payload.length <= oldLog.length
    · have range := log_range_terms_correct assignment locals oldEntries payloadEntries
        previous (.integer 0) payloadLength oldLog payload previousIndex 0 payload.length
        samePrevious rfl samePayloadLength
        (fun offset within => by omega) (fun offset within => by omega) sameOld samePayload
      have fitsInt :
        (previousIndex : Int) + payload.length <= oldLog.length <->
          previousIndex + payload.length <= oldLog.length := by norm_cast
      simp [appendAlreadyDoneTerm, all, Term.eval, sameOldLength, samePayloadLength,
        samePrevious, NativeArrayLogRanges.AlreadyDone, empty, fits, fitsInt, range]
    · have notFitsInt :
          Not ((previousIndex : Int) + payload.length <= oldLog.length) := by
        exact_mod_cast fits
      simp [appendAlreadyDoneTerm, all, Term.eval, sameOldLength, samePayloadLength,
        samePrevious, NativeArrayLogRanges.AlreadyDone, empty, fits, notFitsInt]

theorem append_term_conflict_term_correct {context : List Ty} {width : PNat}
    (assignment : Assignment) (locals : Locals context)
    (oldLength : Term context .int)
    (oldEntries : Term context (.array .int (entryTy width)))
    (payloadLength : Term context .int)
    (payloadEntries : Term context (.array .int (entryTy width)))
    (previous : Term context .int)
    (oldLog payload : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (previousIndex : Nat)
    (sameOldLength : oldLength.eval assignment locals = (oldLog.length : Int))
    (samePayloadLength : payloadLength.eval assignment locals = (payload.length : Int))
    (samePrevious : previous.eval assignment locals = (previousIndex : Int))
    (sameOld : forall index, index < oldLog.length ->
      modelEntry (oldEntries.eval assignment locals (index : Int)) = oldLog.entries index)
    (samePayload : forall index, index < payload.length ->
      modelEntry (payloadEntries.eval assignment locals (index : Int)) = payload.entries index) :
    (appendTermConflictTerm width oldLength oldEntries payloadLength payloadEntries previous).eval
        assignment locals = true <->
      NativeArrayLogRanges.HasTermConflict oldLog payload previousIndex := by
  let overlap := min payload.length (oldLog.length - previousIndex)
  have overlapEval :
      (logRangeMinTerm payloadLength
        (intMaxTerm (.integer 0) (.sub oldLength previous))).eval assignment locals =
          (overlap : Int) := by
    simp only [log_range_min_term_eval, int_max_zero_eval, Term.eval,
      sameOldLength, samePayloadLength, samePrevious, overlap]
    rw [Int.toNat_sub, Nat.cast_min]
  have range := log_range_terms_correct assignment locals oldEntries payloadEntries
    previous (.integer 0)
    (logRangeMinTerm payloadLength
      (intMaxTerm (.integer 0) (.sub oldLength previous)))
    oldLog payload previousIndex 0 overlap samePrevious rfl overlapEval
    (fun offset within => by
      have overlapBound := Nat.min_le_right payload.length (oldLog.length - previousIndex)
      omega)
    (fun offset within => by
      simpa using lt_of_lt_of_le within (Nat.min_le_left _ _))
    sameOld samePayload
  have rangeFalse :
      (logRangeEqualTerm width true oldEntries payloadEntries previous (.integer 0)
          (logRangeMinTerm payloadLength
            (intMaxTerm (.integer 0) (.sub oldLength previous)))).eval
          assignment locals = false <->
        Not (NativeArrayLogRanges.EqualRange Entry.term oldLog payload
          previousIndex 0 overlap) := by
    constructor
    · intro rejected accepted
      have held := range.mpr accepted
      rw [rejected] at held
      contradiction
    · intro rejected
      apply Bool.eq_false_iff.mpr
      intro held
      exact rejected (range.mp held)
  simp only [appendTermConflictTerm, Term.eval, Bool.and_eq_true, Bool.not_eq_true',
    decide_eq_false_iff_not, samePayloadLength, Int.ofNat_eq_zero]
  rw [rangeFalse]
  rfl

theorem append_no_conflict_extension_term_correct {context : List Ty} {width : PNat}
    (assignment : Assignment) (locals : Locals context)
    (oldLength : Term context .int)
    (oldEntries : Term context (.array .int (entryTy width)))
    (payloadLength : Term context .int)
    (payloadEntries : Term context (.array .int (entryTy width)))
    (previous : Term context .int)
    (oldLog payload : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (previousIndex : Nat)
    (sameOldLength : oldLength.eval assignment locals = (oldLog.length : Int))
    (samePayloadLength : payloadLength.eval assignment locals = (payload.length : Int))
    (samePrevious : previous.eval assignment locals = (previousIndex : Int))
    (sameOld : forall index, index < oldLog.length ->
      modelEntry (oldEntries.eval assignment locals (index : Int)) = oldLog.entries index)
    (samePayload : forall index, index < payload.length ->
      modelEntry (payloadEntries.eval assignment locals (index : Int)) = payload.entries index) :
    (appendNoConflictExtensionTerm width oldLength oldEntries payloadLength payloadEntries previous).eval
        assignment locals = true <->
      NativeArrayLogRanges.NoConflictExtension oldLog payload previousIndex := by
  let overlap := oldLog.length - previousIndex
  have overlapEval :
      (intMaxTerm (.integer 0) (.sub oldLength previous)).eval assignment locals =
        (overlap : Int) := by
    simp only [int_max_zero_eval, Term.eval, sameOldLength, samePrevious, overlap]
    rw [Int.toNat_sub]
  by_cases nonempty : payload.length ≠ 0
  · by_cases previousWithin : previousIndex <= oldLog.length
    · by_cases grows : oldLog.length < previousIndex + payload.length
      · have range := log_range_entries_correct assignment locals oldEntries payloadEntries
          previous (.integer 0) (intMaxTerm (.integer 0) (.sub oldLength previous))
          oldLog payload previousIndex 0 overlap samePrevious rfl overlapEval
          (fun offset within => by omega)
          (fun offset within => by omega)
          sameOld samePayload
        have previousBoundInt : (previousIndex : Int) <= oldLog.length := by
          exact_mod_cast previousWithin
        have growsInt :
            Not ((previousIndex : Int) + payload.length <= oldLog.length) := by
          omega
        simp [appendNoConflictExtensionTerm, all, Term.eval, sameOldLength,
          samePayloadLength, samePrevious, NativeArrayLogRanges.NoConflictExtension,
          nonempty, previousWithin, previousBoundInt, grows, growsInt, range, overlap, lt]
      · have notGrowsInt :
            Not (Not ((previousIndex : Int) + payload.length <= oldLog.length)) := by
          push_neg
          omega
        simp [appendNoConflictExtensionTerm, all, Term.eval, sameOldLength,
          samePayloadLength, samePrevious, NativeArrayLogRanges.NoConflictExtension,
          nonempty, previousWithin, grows, notGrowsInt, lt]
    · have notPreviousInt : Not ((previousIndex : Int) <= oldLog.length) := by
        exact_mod_cast previousWithin
      simp [appendNoConflictExtensionTerm, all, Term.eval, sameOldLength,
        samePayloadLength, samePrevious, NativeArrayLogRanges.NoConflictExtension,
        nonempty, previousWithin, notPreviousInt, lt]
  · have empty : payload.length = 0 := not_ne_iff.mp nonempty
    simp [appendNoConflictExtensionTerm, all, Term.eval, sameOldLength,
      samePayloadLength, samePrevious, NativeArrayLogRanges.NoConflictExtension, empty]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
