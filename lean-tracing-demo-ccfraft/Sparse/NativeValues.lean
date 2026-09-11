-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Model
import Sparse.NativeSmt

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def contentTy (width : PNat) : Ty :=
  .sum .unit (.sum .int (.sum (.bits width) (.bits width)))

def entryTy (width : PNat) : Ty := .pair .int (contentTy width)

def roleCode : Role -> Int
  | .none => 0
  | .follower => 1
  | .preVoteCandidate => 2
  | .candidate => 3
  | .leader => 4

theorem role_code_eq (left right : Role) : roleCode left = roleCode right <-> left = right := by
  cases left <;> cases right <;> simp [roleCode]

theorem role_code_leader (role : Role) : roleCode role = 4 <-> role = .leader := by
  simpa only [roleCode] using role_code_eq role .leader

def decodeRole (value : Fin 5) : Role :=
  ![Role.none, Role.follower, Role.preVoteCandidate, Role.candidate, Role.leader] value

theorem role_code_decode (value : Fin 5) : roleCode (decodeRole value) = (value.val : Int) := by
  fin_cases value <;> rfl

theorem role_code_bounds (role : Role) : 0 <= roleCode role /\ roleCode role <= 4 := by
  cases role <;> decide +kernel

def decodeBits {width : PNat} (bits : BitVec width) : Finset (Fin width) :=
  Finset.univ.filter fun node => bits.getLsbD node.val = true

def encodeBits {width : PNat} (nodes : Finset (Fin width)) : BitVec width :=
  (BitVec.ofBoolListLE
    (List.ofFn fun node : Fin width => decide (node ∈ nodes))).cast List.length_ofFn

@[simp] theorem decode_bits_member {width : PNat} (bits : BitVec width) (node : Fin width) :
    node ∈ decodeBits bits <-> bits.getLsbD node.val = true := by
  simp [decodeBits]

@[simp] theorem encode_bits_bit {width : PNat} (nodes : Finset (Fin width)) (node : Fin width) :
    (encodeBits nodes).getLsbD node.val = decide (node ∈ nodes) := by
  rw [encodeBits, BitVec.getLsbD_cast, BitVec.getLsbD_ofBoolListLE, List.getD_eq_getElem?_getD]
  simp only [List.getElem?_ofFn, dif_pos node.isLt, Option.getD_some]

@[simp] theorem decode_encode_bits {width : PNat} (nodes : Finset (Fin width)) :
    decodeBits (encodeBits nodes) = nodes := by
  ext node
  rw [decode_bits_member, encode_bits_bit, decide_eq_true_eq]

@[simp] theorem encode_decode_bits {width : PNat} (bits : BitVec width) :
    encodeBits (decodeBits bits) = bits := by
  apply BitVec.eq_of_getLsbD_eq
  intro index within
  simpa using encode_bits_bit (decodeBits bits) ⟨index, within⟩

@[simp] theorem encode_bits_empty {width : PNat} :
    encodeBits (∅ : Finset (Fin width)) = 0 := by
  simpa [decodeBits] using encode_decode_bits (0 : BitVec width)

theorem encode_bits_eq {width : PNat} (left right : Finset (Fin width)) :
    encodeBits left = encodeBits right <-> left = right :=
  ⟨fun equal => by simpa using congrArg decodeBits equal, congrArg encodeBits⟩

def decodeContent {width : PNat} :
    (contentTy width).denote -> EntryContent (Fin width) Nat
  | .inl _ => .signature
  | .inr (.inl tx) => .transaction tx.toNat
  | .inr (.inr (.inl nodes)) => .reconfiguration (decodeBits nodes)
  | .inr (.inr (.inr nodes)) => .retiredCommitted (decodeBits nodes)

def contentValue {width : PNat} :
    EntryContent (Fin width) Nat -> (contentTy width).denote
  | .signature => .inl ()
  | .transaction tx => .inr (.inl tx)
  | .reconfiguration nodes => .inr (.inr (.inl (encodeBits nodes)))
  | .retiredCommitted nodes => .inr (.inr (.inr (encodeBits nodes)))

def ContentValid {width : PNat} : (contentTy width).denote -> Prop
  | .inr (.inl tx) => 0 <= tx
  | _ => True

@[simp] theorem decode_content_value {width : PNat} (content : EntryContent (Fin width) Nat) :
    decodeContent (contentValue content) = content := by
  cases content <;> simp [decodeContent, contentValue]

theorem content_value_decode {width : PNat} (value : (contentTy width).denote)
    (valid : ContentValid value) : contentValue (decodeContent value) = value := by
  cases value with
  | inl payload => cases payload; rfl
  | inr rest =>
    cases rest with
    | inl tx =>
      have nonnegative : 0 <= tx := valid
      simp [contentValue, decodeContent, Int.toNat_of_nonneg nonnegative]
    | inr more => cases more <;> simp [contentValue, decodeContent]

@[simp] theorem content_value_valid {width : PNat} (content : EntryContent (Fin width) Nat) :
    ContentValid (contentValue content) := by
  cases content <;> simp [ContentValid, contentValue]

def modelEntry {width : PNat} (value : (entryTy width).denote) : Entry (Fin width) Nat :=
  { term := value.1.toNat, content := decodeContent value.2 }

def entryValue {width : PNat} (entry : Entry (Fin width) Nat) : (entryTy width).denote :=
  (entry.term, contentValue entry.content)

def EntryValid {width : PNat} (value : (entryTy width).denote) : Prop :=
  0 <= value.1 /\ ContentValid value.2

@[simp] theorem model_entry_value {width : PNat} (entry : Entry (Fin width) Nat) :
    modelEntry (entryValue entry) = entry := by
  cases entry
  simp [modelEntry, entryValue]

theorem entry_value_model {width : PNat} (value : (entryTy width).denote)
    (valid : EntryValid value) : entryValue (modelEntry value) = value := by
  rcases value with ⟨term, content⟩
  simp only [EntryValid] at valid
  simp [entryValue, modelEntry, Int.toNat_of_nonneg valid.1, content_value_decode content valid.2]

@[simp] theorem entry_value_valid {width : PNat} (entry : Entry (Fin width) Nat) :
    EntryValid (entryValue entry) := by
  simp [EntryValid, entryValue]

theorem model_entry_eq_iff {width : PNat} (value : (entryTy width).denote)
    (entry : Entry (Fin width) Nat) (valid : EntryValid value) :
    value = entryValue entry <-> modelEntry value = entry := by
  constructor
  · rintro rfl
    exact model_entry_value entry
  · intro same
    rw [<- same, entry_value_model value valid]

def contentTerm {context : List Ty} {width : PNat} :
    EntryContent (Fin width) Nat -> Term context (contentTy width)
  | .signature => .inl .unit
  | .transaction tx => .inr (.inl (.integer tx))
  | .reconfiguration nodes => .inr (.inr (.inl (.bits (encodeBits nodes))))
  | .retiredCommitted nodes => .inr (.inr (.inr (.bits (encodeBits nodes))))

def entryTerm {context : List Ty} {width : PNat} (entry : Entry (Fin width) Nat) :
    Term context (entryTy width) :=
  .pair (.integer entry.term) (contentTerm entry.content)

theorem content_term_eval {context : List Ty} {width : PNat}
    (content : EntryContent (Fin width) Nat) (assignment : Assignment) (locals : Locals context) :
    (contentTerm content).eval assignment locals = contentValue content := by
  cases content <;> rfl

theorem entry_term_eval {context : List Ty} {width : PNat}
    (entry : Entry (Fin width) Nat) (assignment : Assignment) (locals : Locals context) :
    (entryTerm entry).eval assignment locals = entryValue entry := by
  simp only [entryTerm, Term.eval, content_term_eval, entryValue]

def entryDomain {context : List Ty} {width : PNat}
    (entry : Term context (entryTy width)) : Term context .bool :=
  .and (.le (.integer 0) (.fst entry))
    (.cases (.snd entry) (.boolean true)
      (.cases (.bound .here) (.le (.integer 0) (.bound .here)) (.boolean true)))

theorem entry_domain_correct {context : List Ty} {width : PNat}
    (entry : Term context (entryTy width)) (assignment : Assignment) (locals : Locals context) :
    (entryDomain entry).eval assignment locals = true <-> EntryValid (entry.eval assignment locals) := by
  cases observed : entry.eval assignment locals with
  | mk term content =>
    cases content with
    | inl payload =>
      simp [entryDomain, Term.eval, observed, EntryValid, ContentValid]
    | inr rest =>
      cases rest with
      | inl tx =>
        simp [entryDomain, Term.eval, observed, EntryValid, ContentValid, Locals.cons]
      | inr more =>
        cases more <;> simp [entryDomain, Term.eval, observed, EntryValid, ContentValid, Locals.cons]

theorem entry_literal_eq_correct {context : List Ty} {width : PNat}
    (actual : Term context (entryTy width)) (expected : Entry (Fin width) Nat)
    (assignment : Assignment) (locals : Locals context)
    (valid : (entryDomain actual).eval assignment locals = true) :
    (Term.equal actual (entryTerm expected)).eval assignment locals = true <->
      modelEntry (actual.eval assignment locals) = expected := by
  simp only [Term.eval, decide_eq_true_eq, entry_term_eval]
  exact model_entry_eq_iff _ expected ((entry_domain_correct actual assignment locals).mp valid)

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
