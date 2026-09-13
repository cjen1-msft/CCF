-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeNodeRowWritesEncoding
import Sparse.NativeSignature
import Sparse.NativeSignatureTermsEncoding

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

theorem sign_committable_messages_prefix {width : PNat} (source : Fin width)
    (before after : Encoding width)
    (run : (signCommittableMessages source).run before = .ok ((), after)) :
    exists states : SignaturePrefixStates width,
      SignaturePrefixResult source before after states := by
  rw [signCommittableMessages, get_bind_run] at run
  obtain ⟨entriesId, entriesDefined, entriesRun, run⟩ :=
    (bind_run _ _ _ _ _).mp run
  obtain ⟨lengthId, tailBefore, lengthRun, tailRun⟩ :=
    (bind_run _ _ _ _ _).mp run
  obtain ⟨entriesEq, entriesNext, entriesBootstrap, entriesColumns, _⟩ :=
    define_success _ before entriesDefined entriesId entriesRun
  obtain ⟨lengthEq, lengthNext, lengthBootstrap, lengthColumns, _⟩ :=
    define_success _ entriesDefined tailBefore lengthId lengthRun
  have ids : entriesId = before.next /\ lengthId = before.next + 1 := by
    constructor <;> omega
  rcases ids with ⟨rfl, rfl⟩
  let states : SignaturePrefixStates width := { entriesDefined, tailBefore }
  refine ⟨states, ?_⟩
  constructor
  · constructor
    · simpa [signaturePrefixTerms] using entriesRun
    · simpa [signaturePrefixTerms] using lengthRun
    · simpa [signaturePrefixTerms] using tailRun
  · exact entriesNext
  · exact entriesBootstrap
  · exact entriesColumns
  · change tailBefore.next = before.next + 2
    omega
  · exact lengthBootstrap.trans entriesBootstrap
  · exact lengthColumns.trans entriesColumns

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
  let terms := signaturePrefixTerms before source
  have lengthParts :=
    define_holds (.add terms.old.logLength (.integer 1))
      states.entriesDefined states.tailBefore (before.next + 1)
      result.runs.lengthRun assignment holds
  have entriesParts :=
    define_holds (leaderLogEntriesTerm terms.old (contentTerm .signature))
      before states.entriesDefined before.next result.runs.entriesRun
      assignment lengthParts.1
  constructor
  · exact entriesParts.1
  · simpa [terms, signaturePrefixTerms, Term.eval] using entriesParts.2
  · simpa [terms, signaturePrefixTerms, Term.eval] using lengthParts.2

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
  let terms := signaturePrefixTerms before source
  obtain ⟨entriesAssignment, entriesAgreement, entriesHolds⟩ :=
    define_extension (leaderLogEntriesTerm terms.old (contentTerm .signature))
      before states.entriesDefined before.next result.runs.entriesRun assignment holds
  obtain ⟨extended, lengthAgreement, prefixHolds⟩ :=
    define_extension (.add terms.old.logLength (.integer 1))
      states.entriesDefined states.tailBefore (before.next + 1)
      result.runs.lengthRun entriesAssignment entriesHolds
  have agreement : assignment.AgreesBelow before.next extended :=
    entriesAgreement.trans
      (lengthAgreement.restrict (by rw [result.entriesNext]; omega))
  have extendedRep :=
    rep.agrees_below before assignment extended frame valid agreement
  let old := NativeArrayCheckQuorum.get frame.nodes source
  let appended := NativeArrayLeaderLogWrite.appendRow old .signature
  have oldRep :=
    node_row_snapshot_rep extended before.toColumns frame.nodes extendedRep.nodes source
  have facts := signature_prefix_facts source before after states result extended prefixHolds
  have appendedRep : terms.appended.Rep extended appended := by
    apply leader_log_row_terms_rep extended terms.old old (contentTerm .signature)
      .signature terms.length terms.entries oldRep
    · simp [content_term_eval, contentValue, decodeContent]
    · rw [facts.length]
      have oldLength :
          terms.old.logLength.eval extended Locals.empty = (old.log.length : Int) := by
        simpa [terms, old, signaturePrefixTerms] using oldRep.logLength
      change terms.old.logLength.eval extended Locals.empty + 1 =
        (old.log.length + 1 : Int)
      rw [oldLength]
    · exact facts.entries
  have oldBounded :=
    (node_row_snapshot_bounded before source valid).mono
      (show before.next <= states.tailBefore.next by
        rw [result.tailBeforeNext]
        omega)
  have appendedBounded : terms.appended.Bounded states.tailBefore.next := by
    refine { oldBounded with
      logLength := ?_
      logEntries := ?_ }
    · simp [terms, signaturePrefixTerms, leaderLogRowTerms, Term.symbols,
        result.tailBeforeNext]
    · simp [terms, signaturePrefixTerms, leaderLogRowTerms, Term.symbols,
        result.tailBeforeNext]
  exact ⟨extended, agreement, prefixHolds, extendedRep, appendedRep,
    appendedBounded⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
