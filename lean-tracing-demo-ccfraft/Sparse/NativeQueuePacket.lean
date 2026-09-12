-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeQueueDomain
import Sparse.NativePacketMatch

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def defaultQueuePacket {width : PNat} (source : Fin width) : Message (Fin width) Nat :=
  .proposeVoteRequest { term := 0, source, destination := source }

def QueuePacketValid {width : PNat} (source : Fin width) (value : (packetTy width).denote) : Prop :=
  PacketValueValid value /\ value.1.2.1 = (source.val : Int)

noncomputable def modelQueuePacket {width : PNat} (source : Fin width) (value : (packetTy width).denote) :
    Message (Fin width) Nat := by
  classical
  exact if valid : QueuePacketValid source value then modelPacket value valid.1 else defaultQueuePacket source

def defaultQueuePacketTerm {context : List Ty} {width : PNat} (source : Fin width) :
    Term context (packetTy width) :=
  .pair (packetHeaderTerm (0, source, source)) (.inr (.inr (.inr (.inr (.inr (.inr .unit))))))

def queuePacketTerm {context : List Ty} {width : PNat} (source : Fin width)
    (value : Term context (packetTy width)) : Term context (packetTy width) :=
  .ite (queuePacketDomain (.integer source.val) value) value (defaultQueuePacketTerm source)

def queuePacketMatches {context : List Ty} {width : PNat} (source : Fin width)
    (value : Term context (packetTy width)) (expected : Message (Fin width) Nat) : Term context .bool :=
  if expected = defaultQueuePacket source then
    .or (.not (queuePacketDomain (.integer source.val) value)) (packetMatches value expected)
  else
    .and (queuePacketDomain (.integer source.val) value) (packetMatches value expected)

theorem model_queue_packet_exact {width : PNat} (source : Fin width) (value : (packetTy width).denote)
    (valid : QueuePacketValid source value) :
    modelQueuePacket source value = modelPacket value valid.1 := by
  simp only [modelQueuePacket, dif_pos valid]

theorem model_queue_packet_source {width : PNat} (source : Fin width) (value : (packetTy width).denote) :
    (modelQueuePacket source value).source = source := by
  classical
  unfold modelQueuePacket
  split_ifs with valid
  · have same := congrArg (fun packet : (packetTy width).denote => packet.1.2.1)
      (packet_value_model value valid.1)
    apply Fin.ext
    have encoded : ((modelPacket value valid.1).source.val : Int) = (source.val : Int) :=
      same.trans valid.2
    exact_mod_cast encoded
  · rfl

theorem model_queue_packet_value {width : PNat} (source : Fin width) (packet : Message (Fin width) Nat)
    (sameSource : packet.source = source) :
    modelQueuePacket source (packetValue packet) = packet := by
  have valid : QueuePacketValid source (packetValue packet) :=
    ⟨packet_value_valid packet, by simp [packetValue, packetHeaderValue, sameSource]⟩
  rw [model_queue_packet_exact source _ valid, model_packet_value]

theorem default_queue_packet_term_eval {context : List Ty} {width : PNat} (source : Fin width)
    (assignment : Assignment) (locals : Locals context) :
    (defaultQueuePacketTerm source).eval assignment locals = packetValue (defaultQueuePacket source) := rfl

theorem queue_packet_term_correct {context : List Ty} {width : PNat} (source : Fin width)
    (value : Term context (packetTy width)) (assignment : Assignment) (locals : Locals context) :
    (queuePacketTerm source value).eval assignment locals =
      packetValue (modelQueuePacket source (value.eval assignment locals)) := by
  classical
  have domain : (queuePacketDomain (.integer source.val) value).eval assignment locals = true <->
      QueuePacketValid source (value.eval assignment locals) :=
    queue_packet_domain_correct (.integer source.val) value assignment locals
  by_cases valid : QueuePacketValid source (value.eval assignment locals)
  · simp only [queuePacketTerm, Term.eval, domain.mpr valid, ↓reduceIte]
    exact (packet_value_model _ valid.1).symm.trans
      (congrArg packetValue (model_queue_packet_exact source _ valid).symm)
  · have invalid := Bool.eq_false_iff.mpr (fun holds => valid (domain.mp holds))
    simp only [queuePacketTerm, Term.eval, invalid, Bool.false_eq_true, ↓reduceIte,
      default_queue_packet_term_eval, modelQueuePacket, dif_neg valid]

theorem queue_packet_matches_correct {context : List Ty} {width : PNat} (source : Fin width)
    (value : Term context (packetTy width)) (expected : Message (Fin width) Nat)
    (assignment : Assignment) (locals : Locals context) :
    (queuePacketMatches source value expected).eval assignment locals = true <->
      modelQueuePacket source (value.eval assignment locals) = expected := by
  classical
  have domain : (queuePacketDomain (.integer source.val) value).eval assignment locals = true <->
      QueuePacketValid source (value.eval assignment locals) :=
    queue_packet_domain_correct (.integer source.val) value assignment locals
  by_cases valid : QueuePacketValid source (value.eval assignment locals)
  · rw [model_queue_packet_exact source _ valid]
    have observed := packet_matches_correct value expected assignment locals valid.1
    by_cases same : expected = defaultQueuePacket source <;>
      simpa [queuePacketMatches, same, Term.eval, domain.mpr valid] using observed
  · have invalid := Bool.eq_false_iff.mpr (fun holds => valid (domain.mp holds))
    simp only [modelQueuePacket, dif_neg valid]
    by_cases same : expected = defaultQueuePacket source <;>
      simp [queuePacketMatches, same, Term.eval, invalid, eq_comm]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
