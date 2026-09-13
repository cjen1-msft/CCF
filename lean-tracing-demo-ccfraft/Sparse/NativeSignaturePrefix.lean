-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeLeaderLogPrefix
import Sparse.NativeSignature

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

structure SignaturePrefixTerms (width : PNat) where
  old : NodeRowTerms width
  entries : Expr (.array .int (entryTy width))
  length : Expr .int
  appended : NodeRowTerms width

def signaturePrefixTerms {width : PNat} (before : Encoding width)
    (source : Fin width) : SignaturePrefixTerms width :=
  let old := nodeRowSnapshot before.toColumns source
  let entries : Expr (.array .int (entryTy width)) := .free _ before.next
  let length : Expr .int := .free .int (before.next + 1)
  { old, entries, length
    appended := leaderLogRowTerms old length entries }

structure SignaturePrefixStates (width : PNat) where
  entriesDefined : Encoding width
  tailBefore : Encoding width

structure SignaturePrefixRuns {width : PNat} (source : Fin width)
    (before after : Encoding width) (states : SignaturePrefixStates width) : Prop where
  entriesRun :
    let terms := signaturePrefixTerms before source
    (define (leaderLogEntriesTerm terms.old (contentTerm .signature))).run before =
      .ok (before.next, states.entriesDefined)
  lengthRun :
    let terms := signaturePrefixTerms before source
    (define (.add terms.old.logLength (.integer 1))).run states.entriesDefined =
      .ok (before.next + 1, states.tailBefore)
  tailRun :
    let terms := signaturePrefixTerms before source
    (retirementTail before.bootstrap source terms.appended terms.old.commit
      (signatureGuards before.toColumns source)).run states.tailBefore = .ok ((), after)

structure SignaturePrefixResult {width : PNat} (source : Fin width)
    (before after : Encoding width) (states : SignaturePrefixStates width) : Prop where
  runs : SignaturePrefixRuns source before after states
  entriesNext : states.entriesDefined.next = before.next + 1
  entriesBootstrap : states.entriesDefined.bootstrap = before.bootstrap
  entriesColumns : states.entriesDefined.toColumns = before.toColumns
  tailBeforeNext : states.tailBefore.next = before.next + 2
  tailBeforeBootstrap : states.tailBefore.bootstrap = before.bootstrap
  tailBeforeColumns : states.tailBefore.toColumns = before.toColumns

private theorem signature_prefix_generic_result {width : PNat}
    (source : Fin width) (before after : Encoding width)
    (states : SignaturePrefixStates width)
    (result : SignaturePrefixResult source before after states) :
    LeaderLogPrefixResult source (contentTerm .signature) before states.tailBefore
      (leaderLogPrefixTerms before source).appended
      { entriesDefined := states.entriesDefined } := by
  constructor
  · constructor
    · simpa [signaturePrefixTerms, leaderLogPrefixTerms] using
        result.runs.entriesRun
    · simpa [signaturePrefixTerms, leaderLogPrefixTerms] using
        result.runs.lengthRun
  · rfl
  · exact result.entriesNext
  · exact result.entriesBootstrap
  · exact result.entriesColumns
  · exact result.tailBeforeNext
  · exact result.tailBeforeBootstrap
  · exact result.tailBeforeColumns

theorem sign_committable_messages_prefix {width : PNat} (source : Fin width)
    (before after : Encoding width)
    (run : (signCommittableMessages source).run before = .ok ((), after)) :
    exists states : SignaturePrefixStates width,
      SignaturePrefixResult source before after states := by
  rw [signCommittableMessages, get_bind_run] at run
  obtain ⟨appended, tailBefore, prefixRun, tailRun⟩ :=
    (bind_run _ _ _ _ _).mp run
  obtain ⟨prefixStates, prefixResult⟩ :=
    prepare_leader_log_success source (contentTerm .signature) before tailBefore
      appended prefixRun
  rw [prefixResult.outputTerms] at tailRun
  let states : SignaturePrefixStates width :=
    { entriesDefined := prefixStates.entriesDefined, tailBefore }
  refine ⟨states, ?_⟩
  constructor
  · constructor
    · simpa [states, signaturePrefixTerms, leaderLogPrefixTerms] using
        prefixResult.runs.entriesRun
    · simpa [states, signaturePrefixTerms, leaderLogPrefixTerms] using
        prefixResult.runs.lengthRun
    · simpa [states, signaturePrefixTerms, leaderLogPrefixTerms] using tailRun
  · exact prefixResult.entriesNext
  · exact prefixResult.entriesBootstrap
  · exact prefixResult.entriesColumns
  · exact prefixResult.afterNext
  · exact prefixResult.afterBootstrap
  · exact prefixResult.afterColumns

structure SignaturePrefixFacts {width : PNat} (before : Encoding width)
    (source : Fin width) (assignment : Assignment) : Prop where
  priorHolds : Holds before.assertions.toList assignment
  entries :
    let terms := signaturePrefixTerms before source
    terms.entries.eval assignment Locals.empty =
      (leaderLogEntriesTerm terms.old (contentTerm .signature)).eval
        assignment Locals.empty
  length :
    let terms := signaturePrefixTerms before source
    terms.length.eval assignment Locals.empty =
      (.add terms.old.logLength (.integer 1) : Expr .int).eval
        assignment Locals.empty

theorem signature_prefix_facts {width : PNat} (source : Fin width)
    (before after : Encoding width) (states : SignaturePrefixStates width)
    (result : SignaturePrefixResult source before after states)
    (assignment : Assignment)
    (holds : Holds states.tailBefore.assertions.toList assignment) :
    SignaturePrefixFacts before source assignment := by
  have generic :=
    leader_log_prefix_facts source (contentTerm .signature) before
      states.tailBefore (leaderLogPrefixTerms before source).appended
      { entriesDefined := states.entriesDefined }
      (signature_prefix_generic_result source before after states result)
      assignment holds
  exact {
    priorHolds := generic.priorHolds
    entries := by
      simpa [signaturePrefixTerms, leaderLogPrefixTerms] using generic.entries
    length := by
      simpa [signaturePrefixTerms, leaderLogPrefixTerms] using generic.length }

theorem signature_prefix_row_rep {width : PNat} (source : Fin width)
    (before : Encoding width) (assignment : Assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (facts : SignaturePrefixFacts before source assignment) :
    (signaturePrefixTerms before source).appended.Rep assignment
      (NativeArrayLeaderLogWrite.appendRow
        (NativeArrayCheckQuorum.get frame.nodes source) .signature) := by
  have genericFacts :
      LeaderLogPrefixFacts before source (contentTerm .signature) assignment := {
    priorHolds := facts.priorHolds
    entries := by
      simpa [signaturePrefixTerms, leaderLogPrefixTerms] using facts.entries
    length := by
      simpa [signaturePrefixTerms, leaderLogPrefixTerms] using facts.length }
  simpa [signaturePrefixTerms, leaderLogPrefixTerms] using
    leader_log_prefix_row_rep source (contentTerm .signature) .signature before
      assignment frame rep genericFacts
      (by simp [content_term_eval, contentValue, decodeContent])

theorem signature_prefix_assignment {width : PNat} (source : Fin width)
    (before after : Encoding width) (states : SignaturePrefixStates width)
    (result : SignaturePrefixResult source before after states)
    (assignment : Assignment)
    (holds : Holds before.assertions.toList assignment)
    (valid : ReferencesValid before)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame) :
    exists extended : Assignment,
      assignment.AgreesBelow before.next extended /\
      Holds states.tailBefore.assertions.toList extended /\
      FrameColumnsRep extended before.toColumns frame /\
      let terms := signaturePrefixTerms before source
      let old := NativeArrayCheckQuorum.get frame.nodes source
      let appended := NativeArrayLeaderLogWrite.appendRow old .signature
      terms.appended.Rep extended appended /\
        terms.appended.Bounded states.tailBefore.next := by
  obtain ⟨extended, agreement, prefixHolds, extendedRep, appendedRep,
      appendedBounded⟩ :=
    prepare_leader_log_assignment source (contentTerm .signature) .signature
      before states.tailBefore (leaderLogPrefixTerms before source).appended
      { entriesDefined := states.entriesDefined }
      (signature_prefix_generic_result source before after states result)
      assignment holds valid frame rep
      (by simp [contentTerm, Term.symbols])
      (by simp [content_term_eval, contentValue, decodeContent])
  exact ⟨extended, agreement, prefixHolds, extendedRep,
    by simpa [signaturePrefixTerms, leaderLogPrefixTerms] using appendedRep,
    by simpa [signaturePrefixTerms, leaderLogPrefixTerms] using appendedBounded⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
