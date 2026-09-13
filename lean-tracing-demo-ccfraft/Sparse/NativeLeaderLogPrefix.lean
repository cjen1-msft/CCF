-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeLeaderLogWrite
import Sparse.NativeNodeRowWritesEncoding
import Sparse.NativeSignatureTermsEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

structure LeaderLogPrefixTerms (width : PNat) where
  old : NodeRowTerms width
  entries : Expr (.array .int (entryTy width))
  length : Expr .int
  appended : NodeRowTerms width

def leaderLogPrefixTerms {width : PNat} (before : Encoding width)
    (source : Fin width) : LeaderLogPrefixTerms width :=
  let old := nodeRowSnapshot before.toColumns source
  let entries : Expr (.array .int (entryTy width)) := .free _ before.next
  let length : Expr .int := .free .int (before.next + 1)
  { old, entries, length
    appended := leaderLogRowTerms old length entries }

structure LeaderLogPrefixStates (width : PNat) where
  entriesDefined : Encoding width

structure LeaderLogPrefixRuns {width : PNat} (source : Fin width)
    (content : Expr (contentTy width)) (before after : Encoding width)
    (states : LeaderLogPrefixStates width) : Prop where
  entriesRun :
    let terms := leaderLogPrefixTerms before source
    (define (leaderLogEntriesTerm terms.old content)).run before =
      .ok (before.next, states.entriesDefined)
  lengthRun :
    let terms := leaderLogPrefixTerms before source
    (define (.add terms.old.logLength (.integer 1))).run states.entriesDefined =
      .ok (before.next + 1, after)

structure LeaderLogPrefixResult {width : PNat} (source : Fin width)
    (content : Expr (contentTy width)) (before after : Encoding width)
    (output : NodeRowTerms width) (states : LeaderLogPrefixStates width) : Prop where
  runs : LeaderLogPrefixRuns source content before after states
  outputTerms : output = (leaderLogPrefixTerms before source).appended
  entriesNext : states.entriesDefined.next = before.next + 1
  entriesBootstrap : states.entriesDefined.bootstrap = before.bootstrap
  entriesColumns : states.entriesDefined.toColumns = before.toColumns
  afterNext : after.next = before.next + 2
  afterBootstrap : after.bootstrap = before.bootstrap
  afterColumns : after.toColumns = before.toColumns

theorem prepare_leader_log_success {width : PNat} (source : Fin width)
    (content : Expr (contentTy width)) (before after : Encoding width)
    (output : NodeRowTerms width)
    (run : (prepareLeaderLog source content).run before = .ok (output, after)) :
    exists states : LeaderLogPrefixStates width,
      LeaderLogPrefixResult source content before after output states := by
  rw [prepareLeaderLog, get_bind_run] at run
  obtain ⟨entriesId, entriesDefined, entriesRun, run⟩ :=
    (bind_run _ _ _ _ _).mp run
  obtain ⟨lengthId, final, lengthRun, returned⟩ :=
    (bind_run _ _ _ _ _).mp run
  obtain ⟨entriesEq, entriesNext, entriesBootstrap, entriesColumns, _⟩ :=
    define_success _ before entriesDefined entriesId entriesRun
  obtain ⟨lengthEq, lengthNext, lengthBootstrap, lengthColumns, _⟩ :=
    define_success _ entriesDefined final lengthId lengthRun
  have ids : entriesId = before.next /\ lengthId = before.next + 1 := by
    constructor <;> omega
  rcases ids with ⟨rfl, rfl⟩
  have finalEq : final = after := congrArg Prod.snd (Except.ok.inj returned)
  subst final
  have outputTerms :
      output = (leaderLogPrefixTerms before source).appended := by
    simpa [leaderLogPrefixTerms] using
      (congrArg Prod.fst (Except.ok.inj returned)).symm
  let states : LeaderLogPrefixStates width := { entriesDefined }
  refine ⟨states, ?_⟩
  constructor
  · constructor
    · simpa [leaderLogPrefixTerms] using entriesRun
    · simpa [leaderLogPrefixTerms] using lengthRun
  · exact outputTerms
  · exact entriesNext
  · exact entriesBootstrap
  · exact entriesColumns
  · omega
  · exact lengthBootstrap.trans entriesBootstrap
  · exact lengthColumns.trans entriesColumns

structure LeaderLogPrefixFacts {width : PNat} (before : Encoding width)
    (source : Fin width) (content : Expr (contentTy width))
    (assignment : Assignment) : Prop where
  priorHolds : Holds before.assertions.toList assignment
  entries :
    let terms := leaderLogPrefixTerms before source
    terms.entries.eval assignment Locals.empty =
      (leaderLogEntriesTerm terms.old content).eval assignment Locals.empty
  length :
    let terms := leaderLogPrefixTerms before source
    terms.length.eval assignment Locals.empty =
      (.add terms.old.logLength (.integer 1) : Expr .int).eval
        assignment Locals.empty

theorem leader_log_prefix_facts {width : PNat} (source : Fin width)
    (content : Expr (contentTy width)) (before after : Encoding width)
    (output : NodeRowTerms width) (states : LeaderLogPrefixStates width)
    (result : LeaderLogPrefixResult source content before after output states)
    (assignment : Assignment)
    (holds : Holds after.assertions.toList assignment) :
    LeaderLogPrefixFacts before source content assignment := by
  let terms := leaderLogPrefixTerms before source
  have lengthParts :=
    define_holds (.add terms.old.logLength (.integer 1))
      states.entriesDefined after (before.next + 1)
      result.runs.lengthRun assignment holds
  have entriesParts :=
    define_holds (leaderLogEntriesTerm terms.old content)
      before states.entriesDefined before.next result.runs.entriesRun
      assignment lengthParts.1
  constructor
  · exact entriesParts.1
  · simpa [terms, leaderLogPrefixTerms, Term.eval] using entriesParts.2
  · simpa [terms, leaderLogPrefixTerms, Term.eval] using lengthParts.2

theorem leader_log_prefix_row_rep {width : PNat} (source : Fin width)
    (content : Expr (contentTy width))
    (concreteContent : EntryContent (Fin width) Nat)
    (before : Encoding width) (assignment : Assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (facts : LeaderLogPrefixFacts before source content assignment)
    (sameContent :
      decodeContent (content.eval assignment Locals.empty) = concreteContent) :
    (leaderLogPrefixTerms before source).appended.Rep assignment
      (NativeArrayLeaderLogWrite.appendRow
        (NativeArrayCheckQuorum.get frame.nodes source) concreteContent) := by
  let terms := leaderLogPrefixTerms before source
  let old := NativeArrayCheckQuorum.get frame.nodes source
  have oldRep : terms.old.Rep assignment old :=
    node_row_snapshot_rep assignment before.toColumns frame.nodes rep.nodes source
  apply leader_log_row_terms_rep assignment terms.old old content concreteContent
    terms.length terms.entries oldRep sameContent
  · rw [facts.length]
    change terms.old.logLength.eval assignment Locals.empty + 1 =
      (old.log.length + 1 : Int)
    rw [oldRep.logLength]
  · exact facts.entries

theorem prepare_leader_log_assignment {width : PNat} (source : Fin width)
    (content : Expr (contentTy width))
    (concreteContent : EntryContent (Fin width) Nat)
    (before after : Encoding width) (output : NodeRowTerms width)
    (states : LeaderLogPrefixStates width)
    (result : LeaderLogPrefixResult source content before after output states)
    (assignment : Assignment)
    (holds : Holds before.assertions.toList assignment)
    (valid : ReferencesValid before)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (contentBounded :
      content.symbols.all (fun symbol => symbol.2 < before.next) = true)
    (sameContent :
      decodeContent (content.eval assignment Locals.empty) = concreteContent) :
    exists extended : Assignment,
      assignment.AgreesBelow before.next extended /\
      Holds after.assertions.toList extended /\
      FrameColumnsRep extended before.toColumns frame /\
      let terms := leaderLogPrefixTerms before source
      let old := NativeArrayCheckQuorum.get frame.nodes source
      let appended := NativeArrayLeaderLogWrite.appendRow old concreteContent
      terms.appended.Rep extended appended /\
        terms.appended.Bounded after.next := by
  let terms := leaderLogPrefixTerms before source
  obtain ⟨entriesAssignment, entriesAgreement, entriesHolds⟩ :=
    define_extension (leaderLogEntriesTerm terms.old content)
      before states.entriesDefined before.next result.runs.entriesRun assignment holds
  obtain ⟨extended, lengthAgreement, prefixHolds⟩ :=
    define_extension (.add terms.old.logLength (.integer 1))
      states.entriesDefined after (before.next + 1)
      result.runs.lengthRun entriesAssignment entriesHolds
  have agreement : assignment.AgreesBelow before.next extended :=
    entriesAgreement.trans
      (lengthAgreement.restrict (by rw [result.entriesNext]; omega))
  have extendedRep :=
    rep.agrees_below before assignment extended frame valid agreement
  have contentEval :
      content.eval extended Locals.empty =
        content.eval assignment Locals.empty := by
    exact (content.eval_agrees_below assignment extended Locals.empty before.next
      (fun symbol member => by
        have bounded := List.all_eq_true.mp contentBounded symbol member
        simpa only [decide_eq_true_eq] using bounded)
      agreement).symm
  have extendedContent :
      decodeContent (content.eval extended Locals.empty) = concreteContent := by
    rw [contentEval]
    exact sameContent
  let old := NativeArrayCheckQuorum.get frame.nodes source
  let appended := NativeArrayLeaderLogWrite.appendRow old concreteContent
  have facts :=
    leader_log_prefix_facts source content before after output states result
      extended prefixHolds
  have appendedRep : terms.appended.Rep extended appended :=
    leader_log_prefix_row_rep source content concreteContent before extended frame
      extendedRep facts extendedContent
  have oldBounded :=
    (node_row_snapshot_bounded before source valid).mono
      (show before.next <= after.next by
        rw [result.afterNext]
        omega)
  have appendedBounded : terms.appended.Bounded after.next := by
    refine { oldBounded with
      logLength := ?_
      logEntries := ?_ }
    · simp [terms, leaderLogPrefixTerms, leaderLogRowTerms, Term.symbols,
        result.afterNext]
    · simp [terms, leaderLogPrefixTerms, leaderLogRowTerms, Term.symbols,
        result.afterNext]
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
