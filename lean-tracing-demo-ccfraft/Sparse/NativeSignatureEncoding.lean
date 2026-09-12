-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeQuorumEncoding
import Sparse.NativeArrayVoteState
import Sparse.NativeRenaming

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def isSignature {context : List Ty} {width : PNat}
    (content : Term context (contentTy width)) : Term context .bool :=
  .cases content (.boolean true) (.boolean false)

def signatureAtTerm {context : List Ty} (width : PNat) (node : Nat)
    (index : Term context .int) : Term context .bool :=
  all [.le (.integer 1) index, .le index (length node),
    isSignature (.snd (entryAt width node (.sub index (.integer 1))))]

def signatureIndexTerm {context : List Ty} (width : PNat) (node : Nat)
    (index : Term context .int) : Term context .bool :=
  all [.le (.integer 0) index, .le index (length node),
    .or (.equal index (.integer 0)) (signatureAtTerm width node index),
    .forall_ .int (implies (lt (index.weaken .int) (.bound .here))
      (.not (signatureAtTerm width node (.bound .here))))]

theorem signature_content_correct {context : List Ty} {width : PNat}
    (content : Term context (contentTy width)) (assignment : Assignment) (locals : Locals context) :
    (isSignature content).eval assignment locals = true <->
      decodeContent (content.eval assignment locals) = .signature := by
  cases decoded : content.eval assignment locals with
  | inl payload => simp [isSignature, Term.eval, decoded, decodeContent]
  | inr rest =>
    rcases rest with tx | configuration | retired <;>
      simp [isSignature, Term.eval, decoded, decodeContent]

theorem signature_at_term_correct {context : List Ty} {width : PNat}
    (assignment : Assignment) (locals : Locals context) (node : Nat)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (committed index : Nat)
    (rep : ConfigurationLogRep assignment node log committed) (position : Term context .int)
    (same : position.eval assignment locals = (index : Int)) :
    (signatureAtTerm width node position).eval assignment locals = true <->
      NativeArrayVote.SignatureAt log index := by
  simp only [signatureAtTerm, all, List.foldr_cons, List.foldr_nil, Term.eval,
    Bool.and_eq_true, decide_eq_true_eq, and_true, same, rep.length_at]
  by_cases positive : 0 < index
  · by_cases within : index <= log.length
    · have natural : (index : Int) - 1 = ((index - 1 : Nat) : Int) := by omega
      have contents := rep.contents (index - 1) (by omega)
      dsimp only [entryTy] at contents
      rw [signature_content_correct]
      simp only [entryAt, Term.eval, same, natural]
      rw [contents]
      simp [NativeArrayVote.SignatureAt, positive, within, show (1 : Int) <= index by omega]
    · simp [NativeArrayVote.SignatureAt, within, show ¬ (index : Int) <= log.length by omega]
  · have zero : index = 0 := by omega
    simp [NativeArrayVote.SignatureAt, zero]

theorem signature_at_term_witness {context : List Ty} {width : PNat}
    (assignment : Assignment) (locals : Locals context) (node : Nat)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (committed : Nat)
    (rep : ConfigurationLogRep assignment node log committed) (position : Term context .int) :
    (signatureAtTerm width node position).eval assignment locals = true <->
      exists index : Nat, position.eval assignment locals = (index : Int) /\
        NativeArrayVote.SignatureAt log index := by
  constructor
  · intro accepted
    have bounds := accepted
    simp only [signatureAtTerm, all, List.foldr_cons, List.foldr_nil, Term.eval,
      Bool.and_eq_true, decide_eq_true_eq] at bounds
    have nonnegative : 0 <= position.eval assignment locals := le_trans (by decide) bounds.1
    have same := (Int.toNat_of_nonneg nonnegative).symm
    exact ⟨_, same, (signature_at_term_correct assignment locals node log committed _ rep position same).mp accepted⟩
  · rintro ⟨index, same, accepted⟩
    exact (signature_at_term_correct assignment locals node log committed index rep position same).mpr accepted

theorem signature_index_term_correct {context : List Ty} {width : PNat}
    (assignment : Assignment) (locals : Locals context) (node : Nat)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (committed index : Nat)
    (rep : ConfigurationLogRep assignment node log committed) (position : Term context .int)
    (same : position.eval assignment locals = (index : Int)) :
    (signatureIndexTerm width node position).eval assignment locals = true <->
      NativeArrayVote.SignatureIndex log index := by
  simp only [signatureIndexTerm, all, List.foldr_cons, List.foldr_nil, Term.eval,
    Bool.and_eq_true, Bool.or_eq_true, decide_eq_true_eq, and_true, same, rep.length_at]
  rw [signature_at_term_correct assignment locals node log committed index rep position same]
  simp only [Int.natCast_nonneg, true_and, Int.ofNat_le, Int.natCast_eq_zero]
  apply and_congr_right'
  apply and_congr_right'
  change (forall candidate : Int, _) <-> _
  constructor
  · intro excludes candidate lower _within signature
    have encoded := (signature_at_term_correct assignment (locals.cons (candidate : Int))
      node log committed candidate rep (.bound .here) rfl).mpr signature
    have rejected := (implies_eval _ _ assignment
      (locals.cons (sort := .int) (candidate : Int))).mp (excludes candidate)
    have before : (lt (position.weaken .int) (.bound .here)).eval assignment
        (locals.cons (candidate : Int)) = true := by
      simp [lt, Term.eval, Term.weaken_eval, same, Locals.cons, lower]
    simpa [Term.eval, encoded] using rejected before
  · intro excludes candidate
    apply (implies_eval _ _ assignment (locals.cons (sort := .int) candidate)).mpr
    intro lower
    simp only [lt, Term.eval, Term.weaken_eval, same, Locals.cons,
      Bool.not_eq_true', decide_eq_false_iff_not, not_le] at lower
    change Bool.not ((signatureAtTerm width node (.bound .here)).eval assignment
      (locals.cons (sort := .int) candidate)) = true
    rw [Bool.not_eq_true']
    apply Bool.eq_false_iff.mpr
    intro accepted
    obtain ⟨natural, sameCandidate, signature⟩ :=
      (signature_at_term_witness assignment (locals.cons candidate) node log committed rep (.bound .here)).mp accepted
    have less : index < natural := by
      change candidate = (natural : Int) at sameCandidate
      rw [sameCandidate] at lower
      exact Int.ofNat_lt.mp lower
    exact excludes natural less signature.2.1 signature

theorem signature_index_term_witness {context : List Ty} {width : PNat}
    (assignment : Assignment) (locals : Locals context) (node : Nat)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (committed : Nat)
    (rep : ConfigurationLogRep assignment node log committed) (position : Term context .int) :
    (signatureIndexTerm width node position).eval assignment locals = true <->
      exists index : Nat, position.eval assignment locals = (index : Int) /\
        NativeArrayVote.SignatureIndex log index := by
  constructor
  · intro accepted
    have bounds := accepted
    simp only [signatureIndexTerm, all, List.foldr_cons, List.foldr_nil, Term.eval,
      Bool.and_eq_true, decide_eq_true_eq] at bounds
    have same := (Int.toNat_of_nonneg bounds.1).symm
    exact ⟨_, same, (signature_index_term_correct assignment locals node log committed _ rep position same).mp accepted⟩
  · rintro ⟨index, same, accepted⟩
    exact (signature_index_term_correct assignment locals node log committed index rep position same).mpr accepted

theorem signature_index_model_correct {context : List Ty} {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (locals : Locals context) (node : Nat)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (committed index : Nat)
    (rep : ConfigurationLogRep assignment node log committed) (position : Term context .int)
    (same : position.eval assignment locals = (index : Int)) :
    (signatureIndexTerm width node position).eval assignment locals = true <->
      maxCommittableIndex log.decode = index :=
  (signature_index_term_correct assignment locals node log committed index rep position same).trans
    (NativeArrayVote.signature_index_correct log index)

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
