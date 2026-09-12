-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativePacketDomain

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def queuePacketDomain {context : List Ty} {width : PNat}
    (source : Term context .int) (packet : Term context (packetTy width)) : Term context .bool :=
  .and (packetDomain packet) (.equal (packetSource packet) source)

theorem queue_packet_domain_correct {context : List Ty} {width : PNat}
    (source : Term context .int) (packet : Term context (packetTy width))
    (assignment : Assignment) (locals : Locals context) :
    (queuePacketDomain source packet).eval assignment locals = true <->
      PacketValueValid (packet.eval assignment locals) /\
        (packet.eval assignment locals).1.2.1 = source.eval assignment locals := by
  simp only [queuePacketDomain, Term.eval, Bool.and_eq_true]
  rw [packet_domain_correct]
  simp only [packetSource, Term.eval, decide_eq_true_eq]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
