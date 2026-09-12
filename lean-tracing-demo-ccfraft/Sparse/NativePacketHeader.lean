-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeEncodeProofs

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def packetHeaderTy : Ty := .pair .int (.pair .int .int)

def packetHeaderValue {width : PNat} (header : Nat × Fin width × Fin width) : packetHeaderTy.denote :=
  (header.1, header.2.1.val, header.2.2.val)

def PacketHeaderValid (width : PNat) (value : packetHeaderTy.denote) : Prop :=
  0 <= value.1 /\ (nodeValue? width value.2.1).isSome = true /\
    (nodeValue? width value.2.2).isSome = true

def modelPacketHeader {width : PNat} (value : packetHeaderTy.denote)
    (valid : PacketHeaderValid width value) : Nat × Fin width × Fin width :=
  (value.1.toNat, (nodeValue? width value.2.1).get valid.2.1, (nodeValue? width value.2.2).get valid.2.2)

def packetHeaderTerm {context : List Ty} {width : PNat} (header : Nat × Fin width × Fin width) :
    Term context packetHeaderTy :=
  .pair (.integer header.1) (.pair (.integer header.2.1.val) (.integer header.2.2.val))

def packetHeaderDomain {context : List Ty} (width : PNat) (value : Term context packetHeaderTy) :
    Term context .bool :=
  .and (.le (.integer 0) (.fst value))
    (.and (optionalNodeDomain width (.inr (.fst (.snd value))))
      (optionalNodeDomain width (.inr (.snd (.snd value)))))

theorem packet_header_domain_correct {context : List Ty} (width : PNat)
    (value : Term context packetHeaderTy) (assignment : Assignment) (locals : Locals context) :
    (packetHeaderDomain width value).eval assignment locals = true <->
      PacketHeaderValid width (value.eval assignment locals) := by
  simp only [packetHeaderDomain, Term.eval, Bool.and_eq_true, decide_eq_true_eq]
  rw [optional_node_domain_correct, optional_node_domain_correct]
  simp [PacketHeaderValid, Term.eval, optionalDecode]

@[simp] theorem packet_header_value_valid {width : PNat} (header : Nat × Fin width × Fin width) :
    PacketHeaderValid width (packetHeaderValue header) := by
  simp [PacketHeaderValid, packetHeaderValue]

@[simp] theorem model_packet_header_value {width : PNat} (header : Nat × Fin width × Fin width)
    (valid : PacketHeaderValid width (packetHeaderValue header)) :
    modelPacketHeader (packetHeaderValue header) valid = header := by
  rcases header with ⟨term, source, destination⟩
  simp [modelPacketHeader, packetHeaderValue]

theorem packet_header_value_model {width : PNat} (value : packetHeaderTy.denote)
    (valid : PacketHeaderValid width value) :
    packetHeaderValue (modelPacketHeader value valid) = value := by
  apply Prod.ext
  · exact Int.toNat_of_nonneg valid.1
  · apply Prod.ext
    · exact node_value_exact value.2.1 _ (Option.some_get valid.2.1).symm
    · exact node_value_exact value.2.2 _ (Option.some_get valid.2.2).symm

theorem packet_header_term_eval {context : List Ty} {width : PNat}
    (header : Nat × Fin width × Fin width) (assignment : Assignment) (locals : Locals context) :
    (packetHeaderTerm header).eval assignment locals = packetHeaderValue header := rfl

theorem model_packet_header_eq_iff {width : PNat} (value : packetHeaderTy.denote)
    (header : Nat × Fin width × Fin width) (valid : PacketHeaderValid width value) :
    value = packetHeaderValue header <-> modelPacketHeader value valid = header := by
  constructor
  · intro same
    subst value
    exact model_packet_header_value header valid
  · intro same
    rw [<- same, packet_header_value_model value valid]

theorem packet_header_literal_correct {context : List Ty} {width : PNat}
    (value : Term context packetHeaderTy) (header : Nat × Fin width × Fin width)
    (assignment : Assignment) (locals : Locals context)
    (valid : PacketHeaderValid width (value.eval assignment locals)) :
    (Term.equal value (packetHeaderTerm header)).eval assignment locals = true <->
      modelPacketHeader (value.eval assignment locals) valid = header := by
  simp only [Term.eval, decide_eq_true_eq, packet_header_term_eval]
  exact model_packet_header_eq_iff _ header valid

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
