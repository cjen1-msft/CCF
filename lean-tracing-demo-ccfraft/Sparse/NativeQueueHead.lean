-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeQueueColumns
import Sparse.NativeArrayVote

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def queueHeadPacketTerm {context : List Ty} {width : PNat} (columns : Columns)
    (source destination : Fin width) : Term context (packetTy width) :=
  queuePacketTerm source
    (.select (queueCellsTerm columns.queueCells (.integer destination.val) (.integer source.val))
      (queueScalarTerm columns.queueHead (.integer destination.val) (.integer source.val)))

theorem queue_head_packet_term_eval {context : List Ty} {width : PNat} (columns : Columns)
    (source destination : Fin width) (assignment : Assignment) (locals : Locals context) :
    (queueHeadPacketTerm columns source destination).eval assignment locals =
      packetValue ((queueRow assignment columns destination source).cells
        (queueRow assignment columns destination source).head) := by
  simp [queueHeadPacketTerm, queue_packet_term_correct, queueCellsTerm, Term.eval,
    queue_scalar_correct, queueRow, modelQueue, queueCellsTy]

def packetResponseTerm {context : List Ty} {width : PNat}
    (payload : Term context (packetPayloadTy width)) : Term context .bool :=
  .cases payload (.boolean false)
    (.cases (.bound .here) (.boolean true)
      (.cases (.bound .here) (.boolean false)
        (.cases (.bound .here) (.boolean true)
          (.cases (.bound .here) (.boolean false)
            (.cases (.bound .here) (.boolean true) (.boolean false))))))

def packetSourceAllowedTerm {context : List Ty} {width : PNat}
    (packet : Term context (packetTy width)) (sourceAllocated : Term context .bool) : Term context .bool :=
  implies (packetResponseTerm (.snd packet)) sourceAllocated

theorem packet_source_allowed_term_correct {context : List Ty} {width : PNat}
    (value : Term context (packetTy width)) (sourceAllocated : Term context .bool)
    (assignment : Assignment) (locals : Locals context)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat) (packet : Message (Fin width) Nat)
    (samePacket : value.eval assignment locals = packetValue packet)
    (sameAllocation : sourceAllocated.eval assignment locals = (arrays packet.source).isSome) :
    (packetSourceAllowedTerm value sourceAllocated).eval assignment locals = true <->
      NativeArrayVote.sourceAllowed arrays packet := by
  cases packet <;>
    simp [packetSourceAllowedTerm, packetResponseTerm, implies, Term.eval, samePacket,
      sameAllocation, packetValue, packetPayloadValue, NativeArrayVote.sourceAllowed, Message.source, Locals.cons]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
