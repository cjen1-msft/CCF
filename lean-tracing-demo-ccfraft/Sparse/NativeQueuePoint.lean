-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeQueuePacket
import Sparse.NativeArrayQueue

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

noncomputable def modelQueue {width : PNat} (source : Fin width) (head length : Nat)
    (cells : Int -> (packetTy width).denote) : NativeArrayQueue.Queue (Message (Fin width) Nat) :=
  { head, length, cells := fun index => modelQueuePacket source (cells index) }

theorem model_queue_source {width : PNat} (source : Fin width) (head length : Nat)
    (cells : Int -> (packetTy width).denote) (packet : Message (Fin width) Nat)
    (member : packet ∈ (modelQueue source head length cells).decode) :
    packet.source = source := by
  simp only [NativeArrayQueue.Queue.decode, List.mem_ofFn] at member
  obtain ⟨index, rfl⟩ := member
  exact model_queue_packet_source source _

theorem model_queue_complete {width : PNat} (source : Fin width)
    (queue : NativeArrayQueue.Queue (Message (Fin width) Nat))
    (valid : forall packet, packet ∈ queue.decode -> packet.source = source) :
    (modelQueue source queue.head queue.length (fun index => packetValue (queue.cells index.toNat))).decode =
      queue.decode := by
  unfold NativeArrayQueue.Queue.decode
  apply congrArg List.ofFn
  funext index
  change modelQueuePacket source (packetValue (queue.cells (queue.head + index.val))) =
    queue.cells (queue.head + index.val)
  apply model_queue_packet_value
  apply valid
  exact List.mem_ofFn.mpr ⟨index, rfl⟩

def queuePoint {context : List Ty} {width : PNat} (source : Fin width)
    (head length : Term context .int) (cells : Term context (.array .int (packetTy width)))
    (index : Nat) (expected : Message (Fin width) Nat) : Term context .bool :=
  .and (lt (.integer index) length)
    (queuePacketMatches source (.select cells (.add head (.integer index))) expected)

theorem queue_point_correct {context : List Ty} {width : PNat} (source : Fin width)
    (head length : Term context .int) (cells : Term context (.array .int (packetTy width)))
    (index : Nat) (expected : Message (Fin width) Nat) (assignment : Assignment) (locals : Locals context)
    (headNatural : 0 <= head.eval assignment locals) (lengthNatural : 0 <= length.eval assignment locals) :
    (queuePoint source head length cells index expected).eval assignment locals = true <->
      (modelQueue source (head.eval assignment locals).toNat (length.eval assignment locals).toNat
        (cells.eval assignment locals)).decode[index]? = some expected := by
  rw [<- NativeArrayQueue.Queue.point_correct]
  simp only [queuePoint, Term.eval, Bool.and_eq_true]
  rw [queue_packet_matches_correct]
  simp only [lt, Term.eval, Bool.not_eq_true', decide_eq_false_iff_not, not_le,
    modelQueue, Int.natCast_add, Int.toNat_of_nonneg headNatural]
  have bounds : (index : Int) < length.eval assignment locals <->
      index < (length.eval assignment locals).toNat := by
    rw [<- Int.ofNat_lt, Int.toNat_of_nonneg lengthNatural]
  rw [bounds]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
