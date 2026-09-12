-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeQueueColumns

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def queuePushCells {context : List Ty} {width : PNat}
    (cells : Term context (.array .int (packetTy width))) (head length : Term context .int)
    (packet : Term context (packetTy width)) : Term context (.array .int (packetTy width)) :=
  .store cells (.add head length) packet

theorem model_queue_push {width : PNat} (source : Fin width) (head length : Nat)
    (cells : Int -> (packetTy width).denote) (packet : Message (Fin width) Nat)
    (sameSource : packet.source = source) :
    modelQueue source head (length + 1)
        (Function.update cells ((head + length : Nat) : Int) (packetValue packet)) =
      (modelQueue source head length cells).push packet := by
  classical
  unfold modelQueue NativeArrayQueue.Queue.push
  congr 1
  funext index
  by_cases same : index = head + length
  · subst index
    simp [model_queue_packet_value source packet sameSource]
  · have different : (index : Int) ≠ ((head + length : Nat) : Int) := by exact_mod_cast same
    simp only [Function.update_apply, same, different, if_false]

theorem queue_push_cells_correct {context : List Ty} {width : PNat}
    (source : Fin width) (head length : Nat) (packet : Message (Fin width) Nat)
    (cells : Term context (.array .int (packetTy width)))
    (headTerm lengthTerm : Term context .int) (packetTerm : Term context (packetTy width))
    (assignment : Assignment) (locals : Locals context)
    (sameHead : headTerm.eval assignment locals = (head : Int))
    (sameLength : lengthTerm.eval assignment locals = (length : Int))
    (samePacket : packetTerm.eval assignment locals = packetValue packet)
    (sameSource : packet.source = source) :
    (modelQueue source head (length + 1)
      ((queuePushCells cells headTerm lengthTerm packetTerm).eval assignment locals)).decode =
      (modelQueue source head length (cells.eval assignment locals)).decode ++ [packet] := by
  have updated : (queuePushCells cells headTerm lengthTerm packetTerm).eval assignment locals =
      Function.update (cells.eval assignment locals) ((head + length : Nat) : Int) (packetValue packet) := by
    funext index
    simp only [queuePushCells, Term.eval, Function.update_apply,
      sameHead, sameLength, samePacket, Int.natCast_add]
  rw [updated]
  rw [model_queue_push source head length _ packet sameSource, NativeArrayQueue.Queue.push_correct]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
