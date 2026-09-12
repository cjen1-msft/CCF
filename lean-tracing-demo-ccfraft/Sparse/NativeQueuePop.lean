-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeQueueStore

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def queuePopLengths {context : List Ty} {width : PNat} (columns : Columns)
    (destination source : Fin width) : Term context (.array .int (.array .int .int)) :=
  let length := queueScalarTerm columns.queueLength
    (.integer destination.val) (.integer source.val)
  storePair (.free _ columns.queueLength) (.integer destination.val) (.integer source.val)
    (.ite (.le (.integer 1) length) (.sub length (.integer 1)) (.integer 0))

def queuePopHeads {context : List Ty} {width : PNat} (columns : Columns)
    (destination source : Fin width) : Term context (.array .int (.array .int .int)) :=
  storePair (.free _ columns.queueHead) (.integer destination.val) (.integer source.val)
    (.add (queueScalarTerm columns.queueHead (.integer destination.val) (.integer source.val))
      (.integer 1))

def popQueue {width : PNat} (destination source : Fin width) : EncodeM width Unit := do
  let before <- get
  let nextLength <- define (queuePopLengths before.toColumns destination source)
  let nextHead <- define (queuePopHeads before.toColumns destination source)
  modify fun state => { state with queueLength := nextLength, queueHead := nextHead }

theorem queue_pop_lengths_eval {context : List Ty} {width : PNat} (columns : Columns)
    (destination source readDestination readSource : Fin width) (assignment : Assignment)
    (locals : Locals context) :
    (queuePopLengths columns destination source).eval assignment locals
        readDestination.val readSource.val =
      if readDestination = destination /\ readSource = source then
        (((assignment (.array .int (.array .int .int)) columns.queueLength
          destination.val source.val).toNat - 1 : Nat) : Int)
      else assignment (.array .int (.array .int .int)) columns.queueLength
        readDestination.val readSource.val := by
  rw [queuePopLengths, store_pair_eval]
  have naturalSubOne (value : Int) :
      (if (1 : Int) <= value then max value 0 - 1 else 0) =
        ((value.toNat - 1 : Nat) : Int) := by
    by_cases one : (1 : Int) <= value
    · have nonnegative : 0 <= value := by omega
      rw [if_pos one, max_eq_left nonnegative]
      have normalized : (value.toNat : Int) = value := Int.toNat_of_nonneg nonnegative
      omega
    · have nonpositive : value <= 0 := by omega
      rw [if_neg one, Int.toNat_of_nonpos nonpositive]
      rfl
  by_cases same : readDestination = destination /\ readSource = source
  · obtain ⟨rfl, rfl⟩ := same
    simp [Term.eval, queue_scalar_correct, naturalSubOne]
  · have different :
        ¬((readDestination.val : Int) = (destination.val : Int) /\
          (readSource.val : Int) = (source.val : Int)) := by
      rintro ⟨sameDestination, sameSource⟩
      apply same
      constructor <;> apply Fin.ext <;> omega
    simp only [Term.eval, if_neg different, if_neg same]

theorem queue_pop_heads_eval {context : List Ty} {width : PNat} (columns : Columns)
    (destination source readDestination readSource : Fin width) (assignment : Assignment)
    (locals : Locals context) :
    (queuePopHeads columns destination source).eval assignment locals
        readDestination.val readSource.val =
      if readDestination = destination /\ readSource = source then
        (((assignment (.array .int (.array .int .int)) columns.queueHead
          destination.val source.val).toNat + 1 : Nat) : Int)
      else assignment (.array .int (.array .int .int)) columns.queueHead
        readDestination.val readSource.val := by
  rw [queuePopHeads, store_pair_eval]
  by_cases same : readDestination = destination /\ readSource = source
  · obtain ⟨rfl, rfl⟩ := same
    simp [Term.eval, queue_scalar_correct]
  · have different :
        ¬((readDestination.val : Int) = (destination.val : Int) /\
          (readSource.val : Int) = (source.val : Int)) := by
      rintro ⟨sameDestination, sameSource⟩
      apply same
      constructor <;> apply Fin.ext <;> omega
    simp only [Term.eval, if_neg different, if_neg same]

theorem queue_pop_columns_rows {width : PNat} (assignment : Assignment) (columns : Columns)
    (destination source readDestination readSource : Fin width)
    (nextLength nextHead : Nat)
    (lengthBinding : assignment (.array .int (.array .int .int)) nextLength =
      (queuePopLengths columns destination source).eval assignment Locals.empty)
    (headBinding : assignment (.array .int (.array .int .int)) nextHead =
      (queuePopHeads columns destination source).eval assignment Locals.empty) :
    (queueRow assignment { columns with queueLength := nextLength, queueHead := nextHead }
      readDestination readSource).decode =
      if readDestination = destination /\ readSource = source then
        (queueRow assignment columns readDestination readSource).decode.tail
      else (queueRow assignment columns readDestination readSource).decode := by
  simp only [queueRow, lengthBinding, headBinding]
  rw [queue_pop_lengths_eval columns destination source readDestination readSource assignment Locals.empty,
    queue_pop_heads_eval columns destination source readDestination readSource assignment Locals.empty]
  by_cases same : readDestination = destination /\ readSource = source
  · obtain ⟨rfl, rfl⟩ := same
    simp only [and_self, if_true, Int.toNat_natCast]
    simpa [modelQueue, NativeArrayQueue.Queue.pop] using
      (NativeArrayQueue.Queue.pop_correct
        (modelQueue readSource
          (assignment (.array .int (.array .int .int)) columns.queueHead
            readDestination.val readSource.val).toNat
          (assignment (.array .int (.array .int .int)) columns.queueLength
            readDestination.val readSource.val).toNat
          (assignment (queueCellsTy width) columns.queueCells
            readDestination.val readSource.val)))
  · simp only [if_neg same]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
