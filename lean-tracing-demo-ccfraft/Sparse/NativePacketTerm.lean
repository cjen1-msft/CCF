-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeLogTerm
import Sparse.NativePacketValue

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def packetPayloadTerm {context : List Ty} {width : PNat} :
    Message (Fin width) Nat -> Term context (packetPayloadTy width)
  | .appendEntriesRequest request =>
    .inl (.pair (.integer request.prevLogIndex) (.pair (.integer request.prevLogTerm)
      (.pair (.integer request.leaderCommit) (logTerm request.entries))))
  | .appendEntriesResponse response =>
    .inr (.inl (.pair (.boolean response.success) (.integer response.lastLogIndex)))
  | .requestVoteRequest request =>
    .inr (.inr (.inl (.pair (.integer request.lastCommittableTerm) (.integer request.lastCommittableIndex))))
  | .requestVoteResponse response => .inr (.inr (.inr (.inl (.boolean response.voteGranted))))
  | .requestPreVote request =>
    .inr (.inr (.inr (.inr (.inl
      (.pair (.integer request.lastCommittableTerm) (.integer request.lastCommittableIndex))))))
  | .requestPreVoteResponse response => .inr (.inr (.inr (.inr (.inr (.inl (.boolean response.voteGranted))))))
  | .proposeVoteRequest _ => .inr (.inr (.inr (.inr (.inr (.inr .unit)))))

def packetTerm {context : List Ty} {width : PNat} (packet : Message (Fin width) Nat) :
    Term context (packetTy width) :=
  .pair (packetHeaderTerm (packet.term, packet.source, packet.destination)) (packetPayloadTerm packet)

theorem packet_payload_term_eval {context : List Ty} {width : PNat}
    (packet : Message (Fin width) Nat) (assignment : Assignment) (locals : Locals context) :
    (packetPayloadTerm packet).eval assignment locals = packetPayloadValue packet := by
  cases packet <;> simp [packetPayloadTerm, packetPayloadValue, Term.eval, log_term_eval]

theorem packet_term_eval {context : List Ty} {width : PNat}
    (packet : Message (Fin width) Nat) (assignment : Assignment) (locals : Locals context) :
    (packetTerm packet).eval assignment locals = packetValue packet := by
  simp [packetTerm, packetValue, Term.eval, packet_header_term_eval, packet_payload_term_eval]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
