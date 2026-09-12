-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayRetirement
import Sparse.NativeFirstMatchEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def selectedLogEntry {context : List Ty} {width : PNat}
    (entries : Term context (.array .int (entryTy width))) :
    Term (.int :: context) (entryTy width) :=
  .select (entries.weaken .int) (.bound .here)

def signatureAfterRetirementPredicate {context : List Ty} {width : PNat}
    (entries : Term context (.array .int (entryTy width)))
    (retirement : Term context .int) : Term (.int :: context) .bool :=
  all [
    isSignature (.snd (selectedLogEntry entries)),
    lt (retirement.weaken .int) (.add (.integer 1) (.bound .here))]

def signatureAfterRetirementTerm {context : List Ty} (width : PNat)
    (limit : Term context .int) (entries : Term context (.array .int (entryTy width)))
    (retirement selected : Term context .int) : Term context .bool :=
  firstMatchTerm limit selected (signatureAfterRetirementPredicate entries retirement)

def retiredRecordPredicate {context : List Ty} {width : PNat}
    (entries : Term context (.array .int (entryTy width))) (node : Fin width) :
    Term (.int :: context) .bool :=
  let content := (selectedLogEntry entries).snd
  .cases content (.boolean false)
    (.cases (.bound .here) (.boolean false)
      (.cases (.bound .here) (.boolean false) (.bit (.bound .here) node)))

def retiredRecordTerm {context : List Ty} (width : PNat)
    (limit : Term context .int) (entries : Term context (.array .int (entryTy width)))
    (node : Fin width) (selected : Term context .int) : Term context .bool :=
  firstMatchTerm limit selected (retiredRecordPredicate entries node)

theorem selected_log_entry_eval {context : List Ty} {width : PNat}
    (assignment : Assignment) (locals : Locals context)
    (entries : Term context (.array .int (entryTy width))) (candidate : Int) :
    (selectedLogEntry entries).eval assignment (locals.cons candidate) =
      entries.eval assignment locals candidate := by
  simp [selectedLogEntry, Term.eval, Term.weaken_eval, Locals.cons]

theorem signature_after_retirement_predicate_eval {context : List Ty} {width : PNat}
    (assignment : Assignment) (locals : Locals context)
    (entries : Term context (.array .int (entryTy width)))
    (retirement : Term context .int) (candidate : Nat) (retirementIndex : Nat)
    (sameRetirement : retirement.eval assignment locals = (retirementIndex : Int)) :
    (signatureAfterRetirementPredicate entries retirement).eval assignment
        (locals.cons (candidate : Int)) =
      decide (retirementIndex < 1 + candidate /\
        (modelEntry (entries.eval assignment locals (candidate : Int))).content = .signature) := by
  apply Bool.eq_iff_iff.mpr
  simp only [signatureAfterRetirementPredicate, all, List.foldr_cons, List.foldr_nil,
    Term.eval, Bool.and_eq_true, and_true, decide_eq_true_eq]
  rw [signature_content_correct]
  simp only [Term.eval]
  rw [selected_log_entry_eval]
  simp only [Locals.cons, lt, Term.eval, Term.weaken_eval, sameRetirement,
    Bool.not_eq_true', decide_eq_false_iff_not, not_le, modelEntry]
  have sameOrder : (retirementIndex : Int) < 1 + (candidate : Int) <->
      retirementIndex < 1 + candidate := by
    norm_cast
  rw [sameOrder, and_comm]

theorem retired_record_predicate_eval {context : List Ty} {width : PNat}
    (assignment : Assignment) (locals : Locals context)
    (entries : Term context (.array .int (entryTy width))) (node : Fin width)
    (candidate : Int) :
    (retiredRecordPredicate entries node).eval assignment (locals.cons candidate) =
      Sparse.RetirementScan.namesRetiredNode node
        (modelEntry (entries.eval assignment locals candidate)) := by
  rcases decoded : entries.eval assignment locals candidate with ⟨term, content⟩
  cases content with
  | inl payload =>
    cases payload
    simp [retiredRecordPredicate, selectedLogEntry, Term.eval, Term.weaken_eval,
      Locals.cons, decoded, modelEntry, decodeContent, Sparse.RetirementScan.namesRetiredNode]
  | inr rest =>
    cases rest with
    | inl transaction =>
      simp [retiredRecordPredicate, selectedLogEntry, Term.eval, Term.weaken_eval,
        Locals.cons, decoded, modelEntry, decodeContent, Sparse.RetirementScan.namesRetiredNode]
    | inr tagged =>
      cases tagged with
      | inl configuration =>
        simp [retiredRecordPredicate, selectedLogEntry, Term.eval, Term.weaken_eval,
          Locals.cons, decoded, modelEntry, decodeContent, Sparse.RetirementScan.namesRetiredNode]
      | inr retired =>
        simp [retiredRecordPredicate, selectedLogEntry, Term.eval, Term.weaken_eval,
          Locals.cons, decoded, modelEntry, decodeContent, Sparse.RetirementScan.namesRetiredNode]

theorem signature_after_retirement_term_correct {context : List Ty} {width : PNat}
    (assignment : Assignment) (locals : Locals context)
    (limit : Term context .int) (entries : Term context (.array .int (entryTy width)))
    (retirement selected : Term context .int)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (retirementIndex : Nat)
    (position : Option Nat)
    (sameLimit : limit.eval assignment locals = (log.length : Int))
    (sameSelected : selected.eval assignment locals = firstMatchValue position)
    (sameRetirement : retirement.eval assignment locals = (retirementIndex : Int))
    (sameEntries : forall index, index < log.length ->
      modelEntry (entries.eval assignment locals (index : Int)) = log.entries index) :
    (signatureAfterRetirementTerm width limit entries retirement selected).eval
        assignment locals = true <->
      retirementCommittableIndexInLog log.decode retirementIndex = position.map (1 + ·) := by
  rw [signatureAfterRetirementTerm]
  refine (first_match_term_correct assignment locals limit selected
    (signatureAfterRetirementPredicate entries retirement) log
    (fun index entry =>
      decide (retirementIndex < 1 + index /\ entry.content = .signature))
    position sameLimit sameSelected ?_).trans
      (NativeArrayRetirement.signature_scan_correct log retirementIndex position)
  intro index live
  rw [signature_after_retirement_predicate_eval assignment locals entries retirement index
    retirementIndex sameRetirement, sameEntries index live]

theorem retired_record_term_correct {context : List Ty} {width : PNat}
    (assignment : Assignment) (locals : Locals context)
    (limit : Term context .int) (entries : Term context (.array .int (entryTy width)))
    (node : Fin width) (selected : Term context .int)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (position : Option Nat)
    (sameLimit : limit.eval assignment locals = (log.length : Int))
    (sameSelected : selected.eval assignment locals = firstMatchValue position)
    (sameEntries : forall index, index < log.length ->
      modelEntry (entries.eval assignment locals (index : Int)) = log.entries index) :
    (retiredRecordTerm width limit entries node selected).eval assignment locals = true <->
      retiredCommittedIndexInLog node log.decode = position.map (1 + ·) := by
  rw [retiredRecordTerm]
  refine (first_match_term_correct assignment locals limit selected
    (retiredRecordPredicate entries node) log
    (fun _ entry => Sparse.RetirementScan.namesRetiredNode node entry)
    position sameLimit sameSelected ?_).trans
      (NativeArrayRetirement.retired_index_scan_correct log node position)
  intro index live
  rw [retired_record_predicate_eval, sameEntries index live]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
