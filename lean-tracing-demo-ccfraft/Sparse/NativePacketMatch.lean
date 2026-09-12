-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativePacketDomain
import Sparse.NativePacketTerm

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def packetMatches {context : List Ty} {width : PNat}
    (value : Term context (packetTy width)) (expected : Message (Fin width) Nat) : Term context .bool :=
  .equal value (packetTerm expected)

theorem packet_matches_correct {context : List Ty} {width : PNat}
    (value : Term context (packetTy width)) (expected : Message (Fin width) Nat)
    (assignment : Assignment) (locals : Locals context)
    (valid : PacketValueValid (value.eval assignment locals)) :
    (packetMatches value expected).eval assignment locals = true <->
      modelPacket (value.eval assignment locals) valid = expected := by
  simp only [packetMatches, Term.eval, packet_term_eval, decide_eq_true_eq]
  exact model_packet_eq_iff _ _ valid

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
