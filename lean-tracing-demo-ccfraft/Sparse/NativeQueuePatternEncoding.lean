-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativePacketPatternEncoding
import Sparse.NativeQueuePattern

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem queue_pattern_baseline_eval {context : List Ty} {width : PNat}
    (source : Fin width) (head length : Term context .int)
    (cells : Term context (.array .int (packetTy width))) (index : Nat)
    (expected : NativePacketPattern.Pattern (Fin width) Nat)
    (assignment : Assignment) (locals : Locals context) :
    (queuePattern source head length cells index expected).eval assignment locals =
      (Term.and (lt (.integer index) length)
        (packetPatternTerm expected
          (queuePacketTerm source
            (.select cells (.add head (.integer index)))))).eval assignment locals := by
  let value : Term context (packetTy width) :=
    .select cells (.add head (.integer index))
  let raw := value.eval assignment locals
  let message := modelQueuePacket source raw
  have normalizedEval :
      (queuePacketTerm source value).eval assignment locals = packetValue message := by
    simpa [raw, message] using
      queue_packet_term_correct source value assignment locals
  have normalizedMatch :=
    packet_pattern_term_correct expected (queuePacketTerm source value)
      assignment locals message normalizedEval
  have domain :
      (queuePacketDomain (.integer source.val) value).eval assignment locals = true <->
        QueuePacketValid source raw := by
    simpa [raw] using
      queue_packet_domain_correct (.integer source.val) value assignment locals
  by_cases valid : QueuePacketValid source raw
  · have domainTrue := domain.mpr valid
    have rawEval : value.eval assignment locals = packetValue message := by
      exact (packet_value_model raw valid.1).symm.trans
        (congrArg packetValue (model_queue_packet_exact source raw valid).symm)
    have rawMatch :=
      packet_pattern_term_correct expected value assignment locals message rawEval
    simp only [queuePattern, value, Term.eval, domainTrue, ↓reduceIte]
    rw [rawMatch, normalizedMatch]
  · have domainFalse :
        (queuePacketDomain (.integer source.val) value).eval assignment locals = false :=
      Bool.eq_false_iff.mpr (fun accepted => valid (domain.mp accepted))
    have messageDefault : message = defaultQueuePacket source := by
      simp [message, raw, modelQueuePacket, valid]
    simp only [queuePattern, value, Term.eval, domainFalse, Bool.false_eq_true,
      ↓reduceIte]
    rw [normalizedMatch, messageDefault]

theorem queue_pattern_correct {context : List Ty} {width : PNat}
    (source : Fin width) (head length : Term context .int)
    (cells : Term context (.array .int (packetTy width))) (index : Nat)
    (expected : NativePacketPattern.Pattern (Fin width) Nat)
    (assignment : Assignment) (locals : Locals context)
    (headNatural : 0 <= head.eval assignment locals)
    (lengthNatural : 0 <= length.eval assignment locals) :
    (queuePattern source head length cells index expected).eval assignment locals = true <->
      exists message,
        (modelQueue source (head.eval assignment locals).toNat
          (length.eval assignment locals).toNat
          (cells.eval assignment locals)).decode[index]? = some message /\
        expected.matches message = true := by
  let value : Term context (packetTy width) :=
    .select cells (.add head (.integer index))
  let message := modelQueuePacket source (value.eval assignment locals)
  have normalizedEval :
      (queuePacketTerm source value).eval assignment locals = packetValue message := by
    simpa [message] using queue_packet_term_correct source value assignment locals
  have normalizedMatch :=
    packet_pattern_term_correct expected (queuePacketTerm source value)
      assignment locals message normalizedEval
  rw [queue_pattern_baseline_eval]
  simp only [Term.eval, Bool.and_eq_true]
  rw [normalizedMatch]
  simp only [lt, Term.eval, Bool.not_eq_true', decide_eq_false_iff_not, not_le]
  have bounds : (index : Int) < length.eval assignment locals <->
      index < (length.eval assignment locals).toNat := by
    rw [<- Int.ofNat_lt, Int.toNat_of_nonneg lengthNatural]
  rw [bounds]
  let queue :=
    modelQueue source (head.eval assignment locals).toNat
      (length.eval assignment locals).toNat (cells.eval assignment locals)
  have selected : queue.cells (queue.head + index) = message := by
    simp [queue, modelQueue, message, value, Term.eval,
      Int.toNat_of_nonneg headNatural]
  constructor
  · rintro ⟨live, matched⟩
    refine ⟨message, ?_, matched⟩
    exact (NativeArrayQueue.Queue.point_correct queue index message).mp
      ⟨live, selected⟩
  · rintro ⟨observed, point, matched⟩
    have exactPoint :=
      (NativeArrayQueue.Queue.point_correct queue index observed).mpr point
    have same : observed = message := exactPoint.2.symm.trans selected
    subst observed
    exact ⟨exactPoint.1, matched⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
