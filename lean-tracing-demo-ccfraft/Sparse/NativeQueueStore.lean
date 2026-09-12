-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeQueuePush

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def storePair {context : List Ty} {value : Ty}
    (array : Term context (.array .int (.array .int value)))
    (destination source : Term context .int) (replacement : Term context value) :
    Term context (.array .int (.array .int value)) :=
  .store array destination (.store (.select array destination) source replacement)

theorem store_pair_eval {context : List Ty} {value : Ty}
    (array : Term context (.array .int (.array .int value)))
    (destination source : Term context .int) (replacement : Term context value)
    (assignment : Assignment) (locals : Locals context) (readDestination readSource : Int) :
    (storePair array destination source replacement).eval assignment locals readDestination readSource =
      if readDestination = destination.eval assignment locals /\ readSource = source.eval assignment locals then
        replacement.eval assignment locals
      else array.eval assignment locals readDestination readSource := by
  by_cases sameDestination : readDestination = destination.eval assignment locals <;>
    by_cases sameSource : readSource = source.eval assignment locals <;>
      simp [storePair, Term.eval, sameDestination, sameSource]

def queuePushLengths {context : List Ty} {width : PNat} (columns : Columns)
    (destination source : Fin width) : Term context (.array .int (.array .int .int)) :=
  storePair (.free _ columns.queueLength) (.integer destination.val) (.integer source.val)
    (.add (queueScalarTerm columns.queueLength (.integer destination.val) (.integer source.val)) (.integer 1))

def queuePushPackets {context : List Ty} {width : PNat} (columns : Columns)
    (destination source : Fin width) (packet : Term context (packetTy width)) :
    Term context (queueCellsTy width) :=
  storePair (.free _ columns.queueCells) (.integer destination.val) (.integer source.val)
    (queuePushCells (queueCellsTerm columns.queueCells (.integer destination.val) (.integer source.val))
      (queueScalarTerm columns.queueHead (.integer destination.val) (.integer source.val))
      (queueScalarTerm columns.queueLength (.integer destination.val) (.integer source.val)) packet)

def pushQueue {width : PNat} (destination source : Fin width) (packet : Expr (packetTy width)) :
    EncodeM width Unit := do
  let before <- get
  if packet.symbols.all (fun symbol => symbol.2 < before.next) then
    let nextLength <- define (queuePushLengths before.toColumns destination source)
    let nextPackets <- define (queuePushPackets before.toColumns destination source packet)
    modify fun state => { state with queueLength := nextLength, queueCells := nextPackets }
  else
    throw "internal encoder error: packet references an unallocated SMT symbol"

theorem queue_push_lengths_eval {context : List Ty} {width : PNat} (columns : Columns)
    (destination source readDestination readSource : Fin width) (assignment : Assignment)
    (locals : Locals context) :
    (queuePushLengths columns destination source).eval assignment locals readDestination.val readSource.val =
      if readDestination = destination /\ readSource = source then
        ((assignment (.array .int (.array .int .int)) columns.queueLength destination.val source.val).toNat : Int) + 1
      else assignment (.array .int (.array .int .int)) columns.queueLength readDestination.val readSource.val := by
  simp [queuePushLengths, store_pair_eval, queue_scalar_correct, Term.eval, Fin.ext_iff]

theorem queue_push_packets_eval {context : List Ty} {width : PNat} (columns : Columns)
    (destination source readDestination readSource : Fin width) (packet : Term context (packetTy width))
    (assignment : Assignment) (locals : Locals context) :
    (queuePushPackets columns destination source packet).eval assignment locals readDestination.val readSource.val =
      if readDestination = destination /\ readSource = source then
        (queuePushCells (queueCellsTerm columns.queueCells (.integer destination.val) (.integer source.val))
          (queueScalarTerm columns.queueHead (.integer destination.val) (.integer source.val))
          (queueScalarTerm columns.queueLength (.integer destination.val) (.integer source.val)) packet).eval
            assignment locals
      else assignment (queueCellsTy width) columns.queueCells readDestination.val readSource.val := by
  simp [queuePushPackets, store_pair_eval, Term.eval, Fin.ext_iff, queueCellsTy]

theorem queue_push_columns_rows {width : PNat} (assignment : Assignment) (columns : Columns)
    (destination source readDestination readSource : Fin width)
    (packet : Expr (packetTy width)) (expected : Message (Fin width) Nat)
    (nextLength nextPackets : Nat)
    (lengthBinding : assignment (.array .int (.array .int .int)) nextLength =
      (queuePushLengths columns destination source).eval assignment Locals.empty)
    (packetBinding : assignment (queueCellsTy width) nextPackets =
      (queuePushPackets columns destination source packet).eval assignment Locals.empty)
    (samePacket : packet.eval assignment Locals.empty = packetValue expected)
    (sameSource : expected.source = source) :
    (queueRow assignment { columns with queueLength := nextLength, queueCells := nextPackets }
      readDestination readSource).decode =
      if readDestination = destination /\ readSource = source then
        (queueRow assignment columns readDestination readSource).decode ++ [expected]
      else (queueRow assignment columns readDestination readSource).decode := by
  simp only [queueRow, lengthBinding, packetBinding]
  rw [queue_push_lengths_eval columns destination source readDestination readSource assignment Locals.empty,
    queue_push_packets_eval columns destination source readDestination readSource packet assignment Locals.empty]
  by_cases same : readDestination = destination /\ readSource = source
  · obtain ⟨rfl, rfl⟩ := same
    simp only [and_self, if_true]
    have nextCount (value : Int) : ((value.toNat : Int) + 1).toNat = value.toNat + 1 := by omega
    rw [nextCount]
    apply queue_push_cells_correct readSource _ _ expected _ _ _ packet assignment Locals.empty
      _ _ samePacket sameSource
    · exact queue_scalar_correct _ _ _ _ _
    · exact queue_scalar_correct _ _ _ _ _
  · simp only [if_neg same]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
