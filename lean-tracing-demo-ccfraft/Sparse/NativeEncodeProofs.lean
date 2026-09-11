-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeEncode
import Sparse.NativeArrayCheckQuorum

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem implies_eval {context : List Ty} (premise conclusion : Term context .bool)
    (assignment : Assignment) (locals : Locals context) :
    (implies premise conclusion).eval assignment locals = true <->
      (premise.eval assignment locals = true -> conclusion.eval assignment locals = true) := by
  cases first : premise.eval assignment locals <;>
    cases second : conclusion.eval assignment locals <;> simp [implies, Term.eval, first, second]

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

theorem configuration_decoding {context : List Ty} {width : PNat}
    (content : Term context (contentTy width)) (assignment : Assignment) (locals : Locals context)
    (nodes : Finset (Fin width)) :
    decodeContent (content.eval assignment locals) = .reconfiguration nodes <->
      (isConfiguration content).eval assignment locals = true /\
        decodeBits ((members content).eval assignment locals) = nodes := by
  cases decoded : content.eval assignment locals with
  | inl payload => simp [isConfiguration, members, Term.eval, decoded, decodeContent]
  | inr rest =>
    cases rest with
    | inl tx => simp [isConfiguration, members, Term.eval, decoded, decodeContent, Locals.cons]
    | inr more =>
      cases more <;> simp [isConfiguration, members, Term.eval, decoded, decodeContent, Locals.cons]

theorem configuration_selector_correct {context : List Ty} {width : PNat}
    (content : Term context (contentTy width)) (assignment : Assignment) (locals : Locals context) :
    (isConfiguration content).eval assignment locals = true <->
      decodeContent (content.eval assignment locals) =
        .reconfiguration (decodeBits ((members content).eval assignment locals)) := by
  simpa using (configuration_decoding content assignment locals
    (decodeBits ((members content).eval assignment locals))).symm

theorem configuration_exists {context : List Ty} {width : PNat}
    (content : Term context (contentTy width)) (assignment : Assignment) (locals : Locals context) :
    (isConfiguration content).eval assignment locals = true <->
      exists nodes, decodeContent (content.eval assignment locals) = .reconfiguration nodes := by
  simp only [configuration_decoding, exists_and_left, exists_eq', and_true]

theorem asserted_read_specialization {context : List Ty} {sort : Ty} (column node : Nat)
    (default : Term context sort) (assignment : Assignment) (locals : Locals context)
    (continuation : sort.denote -> Prop) :
    ((allocated node).eval assignment locals = true /\
      continuation ((read column node default).eval assignment locals)) <->
    ((allocated node).eval assignment locals = true /\
      continuation (assignment (.array .int sort) column node)) := by
  cases observed : (allocated node : Term context .bool).eval assignment locals <;>
    simp [read, Term.eval, <- observed]

theorem definition_preserves_satisfiability {width : PNat} {sort : Ty}
    (state : Encoding width) (value : Expr sort)
    (known : value.symbols.all (fun symbol => symbol.2 < state.next) = true) :
    (exists assignment, Holds state.assertions.toList assignment) <->
      (exists assignment, Holds state.assertions.toList assignment /\
        (Term.equal (.free sort state.next) value).eval assignment Locals.empty = true) := by
  apply fresh_binding_exists
  · intro formula member occurs
    have bound := state.symbolsBounded formula (by simpa using member) (sort, state.next) occurs
    exact Nat.lt_irrefl _ bound
  · intro occurs
    have bound := List.all_eq_true.mp known (sort, state.next) occurs
    simp at bound

private def initial : Encoding ⟨1, by decide⟩ :=
  { bootstrap := 1, symbolsBounded := by simp }

example : (assertion (.free .bool initial.next)).run initial =
    .error "internal encoder error: assertion references an unallocated SMT symbol" := by
  rfl

example : (define (.free .int initial.next)).run initial =
    .error "internal encoder error: definition references an unallocated SMT symbol" := by
  rfl

example : ((define (.integer 42)).run initial).map
    (fun (id, state) => (id, state.next, state.assertions.size)) = .ok (initial.next, initial.next + 1, 1) := by
  rfl

example : ((assertion (.forall_ .bool (.bound .here))).run initial).map
    (fun (_, state) => state.assertions.size) = .ok 1 := by
  rfl

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
