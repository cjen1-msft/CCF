-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeEncode
import Sparse.NativeArrayCheckQuorum

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def decodeBits {width : PNat} (bits : BitVec width) : Finset (Fin width) :=
  Finset.univ.filter fun node => bits.getLsbD node.val = true

@[simp] theorem decode_bits_member {width : PNat} (bits : BitVec width) (node : Fin width) :
    node ∈ decodeBits bits <-> bits.getLsbD node.val = true := by
  simp [decodeBits]

@[simp] theorem decode_bits_zero (width : PNat) : decodeBits (0 : BitVec width) = ∅ := by
  ext node
  simp

theorem decode_bits_empty_iff {width : PNat} (bits : BitVec width) :
    decodeBits bits = ∅ <-> bits = 0 := by
  constructor
  · intro empty
    apply BitVec.eq_of_getLsbD_eq
    intro index within
    have absent : (⟨index, within⟩ : Fin width) ∉ decodeBits bits := by rw [empty]; simp
    simpa using absent
  · rintro rfl
    exact decode_bits_zero width

theorem decode_bits_erase {width : PNat} (bits : BitVec width) (node : Fin width) :
    decodeBits (bits &&& ~~~(BitVec.ofNat width (2 ^ node.val))) = (decodeBits bits).erase node := by
  ext peer
  rw [decode_bits_member, Finset.mem_erase, decode_bits_member]
  simp only [BitVec.getLsbD_and, BitVec.getLsbD_not, BitVec.getLsbD_ofNat,
    Nat.testBit_two_pow, peer.isLt, decide_true, Bool.true_and, Bool.and_eq_true,
    Bool.not_eq_true', decide_eq_false_iff_not]
  simp only [Fin.ext_iff, ne_eq, eq_comm, and_comm]

theorem other_bits_correct {width : PNat} (bits : BitVec width) (node : Fin width) :
    bits &&& ~~~(BitVec.ofNat width (2 ^ node.val)) ≠ 0 <->
      ((decodeBits bits).erase node).Nonempty := by
  rw [Finset.nonempty_iff_ne_empty, <- decode_bits_erase]
  exact (not_congr (decode_bits_empty_iff _)).symm

def decodeContent {width : PNat} :
    (contentTy width).denote -> EntryContent (Fin width) Nat
  | .inl _ => .signature
  | .inr (.inl tx) => .transaction tx.toNat
  | .inr (.inr (.inl nodes)) => .reconfiguration (decodeBits nodes)
  | .inr (.inr (.inr nodes)) => .retiredCommitted (decodeBits nodes)

theorem configuration_selector_correct {context : List Ty} {width : PNat}
    (content : Term context (contentTy width)) (assignment : Assignment) (locals : Locals context) :
    (isConfiguration content).eval assignment locals = true <->
      decodeContent (content.eval assignment locals) =
        .reconfiguration (decodeBits ((members content).eval assignment locals)) := by
  cases decoded : content.eval assignment locals with
  | inl payload => simp [isConfiguration, members, Term.eval, decoded, decodeContent]
  | inr rest =>
    cases rest with
    | inl tx => simp [isConfiguration, members, Term.eval, decoded, decodeContent, Locals.cons]
    | inr more =>
      cases more <;> simp [isConfiguration, members, Term.eval, decoded, decodeContent, Locals.cons]

theorem asserted_read_specialization {context : List Ty} {sort : Ty} (column node : Nat)
    (default : Term context sort) (assignment : Assignment) (locals : Locals context)
    (continuation : sort.denote -> Prop) :
    ((allocated node).eval assignment locals = true /\
      continuation ((read column node default).eval assignment locals)) <->
    ((allocated node).eval assignment locals = true /\
      continuation (assignment (.array .int sort) column node)) := by
  cases observed : (allocated node : Term context .bool).eval assignment locals <;>
    simp [read, Term.eval, <- observed]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
