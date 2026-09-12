-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativePacketValue

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def naturalPairDomain {context : List Ty} (value : Term context (.pair .int .int)) : Term context .bool :=
  .and (.le (.integer 0) (.fst value)) (.le (.integer 0) (.snd value))

def appendPayloadDomain {context : List Ty} {width : PNat} (value : Term context (appendPayloadTy width)) :
    Term context .bool :=
  all [.le (.integer 0) (.fst value), .le (.integer 0) (.fst (.snd value)),
    .le (.integer 0) (.fst (.snd (.snd value))), logDomain (.snd (.snd (.snd value)))]

def packetPayloadDomain {context : List Ty} {width : PNat} (value : Term context (packetPayloadTy width)) :
    Term context .bool :=
  .cases value (appendPayloadDomain (.bound .here))
    (.cases (.bound .here) (.le (.integer 0) (.snd (.bound .here)))
      (.cases (.bound .here) (naturalPairDomain (.bound .here))
        (.cases (.bound .here) (.boolean true)
          (.cases (.bound .here) (naturalPairDomain (.bound .here))
            (.cases (.bound .here) (.boolean true) (.boolean true))))))

def packetDomain {context : List Ty} {width : PNat} (value : Term context (packetTy width)) :
    Term context .bool :=
  .and (packetHeaderDomain width (.fst value)) (packetPayloadDomain (.snd value))

def packetSource {context : List Ty} {width : PNat} (value : Term context (packetTy width)) :
    Term context .int :=
  .fst (.snd (.fst value))

theorem append_payload_domain_correct {context : List Ty} {width : PNat}
    (value : Term context (appendPayloadTy width)) (assignment : Assignment) (locals : Locals context) :
    (appendPayloadDomain value).eval assignment locals = true <->
      (0 <= (value.eval assignment locals).1 /\ 0 <= (value.eval assignment locals).2.1 /\
        0 <= (value.eval assignment locals).2.2.1 /\ LogValueValid (value.eval assignment locals).2.2.2) := by
  simp only [appendPayloadDomain, all, List.foldr_cons, List.foldr_nil, Term.eval,
    Bool.and_eq_true, decide_eq_true_eq, and_true]
  rw [log_domain_correct]
  rfl

theorem packet_payload_domain_correct {context : List Ty} {width : PNat}
    (value : Term context (packetPayloadTy width)) (assignment : Assignment) (locals : Locals context) :
    (packetPayloadDomain value).eval assignment locals = true <->
      PacketPayloadValid (value.eval assignment locals) := by
  generalize observed : value.eval assignment locals = payload
  rcases payload with append | response | vote | granted | preVote | preGranted | proposal
  · simp only [packetPayloadDomain, Term.eval, observed, PacketPayloadValid]
    simpa only [Term.eval, Locals.cons] using
      append_payload_domain_correct (Term.bound .here) assignment (locals.cons append)
  all_goals
    simp [packetPayloadDomain, Term.eval, observed, PacketPayloadValid, naturalPairDomain, Locals.cons]

theorem packet_domain_correct {context : List Ty} {width : PNat}
    (value : Term context (packetTy width)) (assignment : Assignment) (locals : Locals context) :
    (packetDomain value).eval assignment locals = true <-> PacketValueValid (value.eval assignment locals) := by
  simp only [packetDomain, Term.eval, Bool.and_eq_true]
  rw [packet_header_domain_correct, packet_payload_domain_correct]
  constructor
  · exact fun valid => ⟨valid.1, valid.2⟩
  · exact fun valid => ⟨valid.header, valid.payload⟩

theorem packet_source_model {context : List Ty} {width : PNat}
    (value : Term context (packetTy width)) (assignment : Assignment) (locals : Locals context)
    (valid : PacketValueValid (value.eval assignment locals)) :
    (packetSource value).eval assignment locals = ((modelPacket (value.eval assignment locals) valid).source.val : Int) := by
  have same := congrArg (fun packet : (packetTy width).denote => packet.1.2.1)
    (packet_value_model (value.eval assignment locals) valid)
  exact same.symm

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
