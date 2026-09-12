-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeVotePacket

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def normalizedContentTerm {context : List Ty} {width : PNat}
    (value : Term context (contentTy width)) : Term context (contentTy width) :=
  .cases value (.inl .unit)
    (.cases (.bound .here) (.inr (.inl (intMaxTerm (.integer 0) (.bound .here))))
      (.cases (.bound .here) (.inr (.inr (.inl (.bound .here)))) (.inr (.inr (.inr (.bound .here))))))

theorem normalized_content_term_correct {context : List Ty} {width : PNat}
    (value : Term context (contentTy width)) (assignment : Assignment) (locals : Locals context) :
    (normalizedContentTerm value).eval assignment locals =
      contentValue (decodeContent (value.eval assignment locals)) := by
  have natural (tx : Int) : max 0 tx = (tx.toNat : Int) := by
    simpa only [Term.eval, int_max_term_eval] using
      int_max_zero_eval (Term.integer (context := context) tx) assignment locals
  simp only [normalizedContentTerm, Term.eval]
  cases evaluated : value.eval assignment locals with
  | inl value => cases value; rfl
  | inr payload =>
    cases payload with
    | inl tx => simp [intMaxTerm, Term.eval, Locals.cons, decodeContent, contentValue, <- max_def, natural]
    | inr configuration =>
      cases configuration <;> simp [Locals.cons, decodeContent, contentValue]

def normalizedEntryTerm {context : List Ty} {width : PNat}
    (value : Term context (entryTy width)) : Term context (entryTy width) :=
  .pair (intMaxTerm (.integer 0) (.fst value)) (normalizedContentTerm (.snd value))

theorem normalized_entry_term_correct {context : List Ty} {width : PNat}
    (value : Term context (entryTy width)) (assignment : Assignment) (locals : Locals context) :
    (normalizedEntryTerm value).eval assignment locals =
      entryValue (modelEntry (value.eval assignment locals)) := by
  simp only [normalizedEntryTerm, Term.eval, int_max_zero_eval, normalized_content_term_correct,
    entryValue, modelEntry]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
