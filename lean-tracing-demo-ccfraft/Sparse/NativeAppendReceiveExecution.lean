-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendReceive
import Sparse.NativeAppendReceiveWritesEncoding
import Sparse.NativeRetirementCompletedConstraintsEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

structure AppendReceiveExecutionTerms (width : PNat) where
  packet : Expr (packetTy width)
  branches : AppendReceiveTerms
  payload : Expr (appendPayloadTy width)
  old : NodeRowTerms width
  spliced : Expr (.array .int (entryTy width))
  grows : Expr .bool
  logLength : Expr .int
  logEntries : Expr (.array .int (entryTy width))
  (commitSignature commit first retirement signature retired current best : Expr .int)
  consumes : Expr .bool
  completed : Expr (.bits width)
  (candidate values : NodeRowTerms width)
  response : Expr (packetTy width)

def appendReceiveExecutionTerms {width : PNat} (before : Encoding width)
    (source destination : Fin width) : AppendReceiveExecutionTerms width :=
  let packet : Expr (packetTy width) := .free _ before.next
  let branches := appendReceiveTerms before.toColumns destination packet
  let payload := appendRequestPayloadTerm packet
  let old := nodeRowSnapshot before.toColumns destination
  let spliced : Expr (.array .int (entryTy width)) := .free _ (before.next + 1)
  let grows : Expr .bool := .free .bool (before.next + 2)
  let logLength : Expr .int := .free .int (before.next + 3)
  let logEntries : Expr (.array .int (entryTy width)) := .free _ (before.next + 4)
  let commitSignature : Expr .int := .free .int (before.next + 5)
  let commit : Expr .int := .free .int (before.next + 6)
  let first : Expr .int := .free .int (before.next + 7)
  let retirement : Expr .int := .free .int (before.next + 8)
  let signature : Expr .int := .free .int (before.next + 9)
  let retired : Expr .int := .free .int (before.next + 10)
  let consumes := .not branches.stepDown
  let current : Expr .int := .free .int (before.next + 11)
  let completed : Expr (.bits width) := .free _ (before.next + 12)
  let best : Expr .int := .free .int (before.next + 13 + 3 * width)
  let candidate := appendReceiveCandidateRowTerms before.toColumns destination packet grows
    logLength logEntries commit
  { packet, branches, payload, old, spliced, grows, logLength, logEntries, commitSignature,
    commit, first, retirement, signature, retired, current, best, consumes, completed, candidate
    values := appendReceiveFinalRowTerms candidate branches.stepDown retirement signature retired
    response := appendReceiveResponseTerm before.toColumns source destination packet best }

structure AppendReceivePrefixConstraints {width : PNat} (before : Encoding width)
    (source destination : Fin width) (terms : AppendReceiveExecutionTerms width)
    (assignment : Assignment) : Prop where
  beforeHolds : Holds before.assertions.toList assignment
  guards : Holds (appendReceiveGuards before.toColumns source destination) assignment
  packet :
    assignment (packetTy width) before.next =
      (queueHeadPacketTerm before.toColumns source destination).eval assignment Locals.empty
  grows :
    assignment .bool (before.next + 2) =
      (Term.and terms.branches.acceptable (Term.not terms.branches.alreadyDone)).eval
        assignment Locals.empty
  splice :
    (implies terms.grows
      (logSpliceTerm width terms.old.logLength terms.old.logEntries terms.payload.snd.snd.snd.fst
        terms.payload.snd.snd.snd.snd terms.payload.fst terms.spliced)).eval
      assignment Locals.empty = true
  length :
    assignment .int (before.next + 3) =
      (Term.ite terms.grows
        (logSpliceLength terms.old.logLength terms.payload.snd.snd.snd.fst terms.payload.fst)
        terms.old.logLength).eval assignment Locals.empty
  entries :
    assignment (.array .int (entryTy width)) (before.next + 4) =
      (Term.ite terms.grows terms.spliced terms.old.logEntries).eval assignment Locals.empty
  boundedSignature :
    (implies terms.branches.acceptable
      (boundedSignatureTerm width terms.logLength terms.logEntries
        (logRangeMinTerm terms.payload.snd.snd.fst
          (.add terms.payload.fst terms.payload.snd.snd.snd.fst))
        terms.commitSignature)).eval assignment Locals.empty = true
  commit :
    assignment .int (before.next + 6) =
      (Term.ite terms.branches.acceptable
        (intMaxTerm terms.old.commit terms.commitSignature) terms.old.commit).eval
        assignment Locals.empty
  refresh :
    (implies terms.consumes
      (retirementRefreshConstraints width before.bootstrap terms.logLength terms.logEntries
        destination terms.first terms.retirement terms.signature terms.retired)).eval
      assignment Locals.empty = true
  current :
    (implies terms.consumes
      (currentConfigurationIndexTerm width terms.logLength terms.logEntries terms.commit
        terms.current)).eval assignment Locals.empty = true
  completed :
    Holds (retirementCompletedClauses before.bootstrap terms.consumes terms.logEntries
      (logRangeMinTerm terms.commit terms.logLength) terms.current
      (currentConfigurationMembersTerm width before.bootstrap terms.logEntries terms.current)
      (before.next + 12) (before.next + 12)) assignment
  nack :
    (implies
      (.and terms.branches.rejects
        (appendReceiveNackHint before.toColumns destination terms.packet))
      (nackMatchTerm width terms.old.logLength terms.old.logEntries terms.payload.fst
        terms.payload.snd.fst terms.best)).eval assignment Locals.empty = true

structure AppendReceiveSuffixStates (width : PNat) where
  firstFresh : Encoding width
  retirementFresh : Encoding width
  signatureFresh : Encoding width
  retiredFresh : Encoding width
  refreshAsserted : Encoding width
  currentFresh : Encoding width
  currentAsserted : Encoding width
  completedState : Encoding width
  bestFresh : Encoding width
  writerBefore : Encoding width

structure AppendReceiveSuffixRuns {width : PNat} (source destination : Fin width)
    (before commitDefined after : Encoding width) (states : AppendReceiveSuffixStates width) : Prop where
  firstRun : fresh.run commitDefined = .ok (before.next + 7, states.firstFresh)
  retirementRun : fresh.run states.firstFresh = .ok (before.next + 8, states.retirementFresh)
  signatureRun : fresh.run states.retirementFresh = .ok (before.next + 9, states.signatureFresh)
  retiredRun : fresh.run states.signatureFresh = .ok (before.next + 10, states.retiredFresh)
  refreshRun :
    let terms := appendReceiveExecutionTerms before source destination
    (assertion (implies terms.consumes
      (retirementRefreshConstraints width before.bootstrap terms.logLength terms.logEntries
        destination terms.first terms.retirement terms.signature terms.retired))).run
      states.retiredFresh = .ok ((), states.refreshAsserted)
  currentRun : fresh.run states.refreshAsserted = .ok (before.next + 11, states.currentFresh)
  currentAssertionRun :
    let terms := appendReceiveExecutionTerms before source destination
    (assertion (implies terms.consumes
      (currentConfigurationIndexTerm width terms.logLength terms.logEntries terms.commit
        terms.current))).run states.currentFresh = .ok ((), states.currentAsserted)
  completedRun :
    let terms := appendReceiveExecutionTerms before source destination
    (retirementCompletedConstraints before.bootstrap terms.consumes terms.logLength
      terms.logEntries terms.commit terms.current).run states.currentAsserted =
        .ok (before.next + 12, states.completedState)
  bestRun : fresh.run states.completedState =
    .ok (before.next + 13 + 3 * width, states.bestFresh)
  nackRun :
    let terms := appendReceiveExecutionTerms before source destination
    (assertion (implies (.and terms.branches.rejects
      (appendReceiveNackHint before.toColumns destination terms.packet))
      (nackMatchTerm width terms.old.logLength terms.old.logEntries terms.payload.fst
        terms.payload.snd.fst terms.best))).run states.bestFresh = .ok ((), states.writerBefore)
  writeRun :
    let terms := appendReceiveExecutionTerms before source destination
    (appendReceiveWrites source destination terms.branches.stepDown terms.values terms.response
      terms.completed).run states.writerBefore = .ok ((), after)

structure AppendReceiveMiddleStates (width : PNat) where
  lengthDefined : Encoding width
  entriesDefined : Encoding width
  commitSignatureFresh : Encoding width
  signatureAsserted : Encoding width
  commitDefined : Encoding width
  suffix : AppendReceiveSuffixStates width

structure AppendReceiveMiddleRuns {width : PNat} (source destination : Fin width)
    (before spliceAsserted after : Encoding width) (states : AppendReceiveMiddleStates width) : Prop where
  lengthRun :
    let terms := appendReceiveExecutionTerms before source destination
    (define (terms.grows.ite
      (logSpliceLength terms.old.logLength terms.payload.snd.snd.snd.fst terms.payload.fst)
      terms.old.logLength)).run spliceAsserted = .ok (before.next + 3, states.lengthDefined)
  entriesRun :
    let terms := appendReceiveExecutionTerms before source destination
    (define (terms.grows.ite terms.spliced terms.old.logEntries)).run states.lengthDefined =
      .ok (before.next + 4, states.entriesDefined)
  commitSignatureRun : fresh.run states.entriesDefined =
    .ok (before.next + 5, states.commitSignatureFresh)
  signatureRun :
    let terms := appendReceiveExecutionTerms before source destination
    (assertion (implies terms.branches.acceptable
      (boundedSignatureTerm width terms.logLength terms.logEntries
        (logRangeMinTerm terms.payload.snd.snd.fst
          (.add terms.payload.fst terms.payload.snd.snd.snd.fst))
        terms.commitSignature))).run states.commitSignatureFresh = .ok ((), states.signatureAsserted)
  commitRun :
    let terms := appendReceiveExecutionTerms before source destination
    (define (.ite terms.branches.acceptable
      (intMaxTerm terms.old.commit terms.commitSignature) terms.old.commit)).run
      states.signatureAsserted = .ok (before.next + 6, states.commitDefined)
  suffixRuns : AppendReceiveSuffixRuns source destination before states.commitDefined after states.suffix

structure AppendReceivePrefixStates (width : PNat) where
  guarded : Encoding width
  packetDefined : Encoding width
  splicedFresh : Encoding width
  growsDefined : Encoding width
  spliceAsserted : Encoding width
  middle : AppendReceiveMiddleStates width

structure AppendReceivePrefixRuns {width : PNat} (source destination : Fin width)
    (before after : Encoding width) (states : AppendReceivePrefixStates width) : Prop where
  guardsRun : (assertAll (appendReceiveGuards before.toColumns source destination)).run before =
    .ok ((), states.guarded)
  packetRun : (define (queueHeadPacketTerm before.toColumns source destination)).run states.guarded =
    .ok (before.next, states.packetDefined)
  splicedRun : fresh.run states.packetDefined = .ok (before.next + 1, states.splicedFresh)
  growsRun :
    let terms := appendReceiveExecutionTerms before source destination
    (define (.and terms.branches.acceptable (.not terms.branches.alreadyDone))).run
      states.splicedFresh = .ok (before.next + 2, states.growsDefined)
  spliceRun :
    let terms := appendReceiveExecutionTerms before source destination
    (assertion (implies terms.grows
      (logSpliceTerm width terms.old.logLength terms.old.logEntries
        terms.payload.snd.snd.snd.fst terms.payload.snd.snd.snd.snd terms.payload.fst
        terms.spliced))).run states.growsDefined = .ok ((), states.spliceAsserted)
  middleRuns : AppendReceiveMiddleRuns source destination before states.spliceAsserted after states.middle

structure AppendReceiveExecutionResult {width : PNat} (source destination : Fin width)
    (before after : Encoding width) (states : AppendReceivePrefixStates width) : Prop where
  runs : AppendReceivePrefixRuns source destination before after states
  writerBootstrap : states.middle.suffix.writerBefore.bootstrap = before.bootstrap
  writerColumns : states.middle.suffix.writerBefore.toColumns = before.toColumns
  writerNext : states.middle.suffix.writerBefore.next = before.next + 14 + 3 * width
  finalNext : after.next = before.next + 38 + 3 * width

theorem receive_append_success {width : PNat} (source destination : Fin width)
    (before after : Encoding width)
    (run : (receiveAppend source destination).run before = .ok ((), after)) :
    exists states : AppendReceivePrefixStates width,
      AppendReceiveExecutionResult source destination before after states := by
  rw [receiveAppend, get_bind_run] at run
  obtain ⟨⟨⟩, guarded, guardsRun, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨packetId, packetDefined, packetRun, run⟩ := (bind_run _ _ _ _ _).mp run
  have guardsShape :=
    (assert_all_success (appendReceiveGuards before.toColumns source destination)
      before guarded guardsRun).1
  obtain ⟨packetEq, packetNext, packetBootstrap, packetColumns, _⟩ :=
    define_success (queueHeadPacketTerm before.toColumns source destination)
      guarded packetDefined packetId packetRun
  have guardedNext : guarded.next = before.next := guardsShape.next
  have packetIdEq : packetId = before.next := packetEq.trans guardedNext
  subst packetId
  obtain ⟨spliced, splicedFresh, splicedRun, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨splicedEq, splicedNext, splicedBootstrap, splicedColumns, _⟩ :=
    fresh_success packetDefined splicedFresh spliced splicedRun
  have splicedIdEq : spliced = before.next + 1 := by
    rw [splicedEq, packetNext, guardedNext]
  subst spliced
  obtain ⟨growsId, growsDefined, growsRun, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨growsEq, growsNext, growsBootstrap, growsColumns, _⟩ :=
    define_success _ splicedFresh growsDefined growsId growsRun
  have growsIdEq : growsId = before.next + 2 := by
    rw [growsEq, splicedNext, packetNext, guardedNext]
  subst growsId
  obtain ⟨⟨⟩, spliceAsserted, spliceRun, run⟩ := (bind_run _ _ _ _ _).mp run
  have spliceShape := assertion_success _ growsDefined spliceAsserted spliceRun
  obtain ⟨lengthId, lengthDefined, lengthRun, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨lengthEq, lengthNext, lengthBootstrap, lengthColumns, _⟩ :=
    define_success _ spliceAsserted lengthDefined lengthId lengthRun
  have lengthIdEq : lengthId = before.next + 3 := by
    rw [lengthEq, spliceShape.1.next, growsNext, splicedNext, packetNext, guardedNext]
  subst lengthId
  obtain ⟨entriesId, entriesDefined, entriesRun, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨entriesEq, entriesNext, entriesBootstrap, entriesColumns, _⟩ :=
    define_success _ lengthDefined entriesDefined entriesId entriesRun
  have entriesIdEq : entriesId = before.next + 4 := by
    rw [entriesEq, lengthNext, spliceShape.1.next, growsNext, splicedNext,
      packetNext, guardedNext]
  subst entriesId
  obtain ⟨commitSignature, commitSignatureFresh, commitSignatureRun, run⟩ :=
    (bind_run _ _ _ _ _).mp run
  obtain ⟨commitSignatureEq, commitSignatureNext, commitSignatureBootstrap,
    commitSignatureColumns, _⟩ :=
    fresh_success entriesDefined commitSignatureFresh commitSignature commitSignatureRun
  have commitSignatureIdEq : commitSignature = before.next + 5 := by
    rw [commitSignatureEq, entriesNext, lengthNext, spliceShape.1.next, growsNext,
      splicedNext, packetNext, guardedNext]
  subst commitSignature
  obtain ⟨⟨⟩, signatureAsserted, signatureRun, run⟩ := (bind_run _ _ _ _ _).mp run
  have signatureShape :=
    assertion_success _ commitSignatureFresh signatureAsserted signatureRun
  obtain ⟨commitId, commitDefined, commitRun, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨commitEq, commitNext, commitBootstrap, commitColumns, _⟩ :=
    define_success _ signatureAsserted commitDefined commitId commitRun
  have commitIdEq : commitId = before.next + 6 := by
    rw [commitEq, signatureShape.1.next, commitSignatureNext, entriesNext, lengthNext,
      spliceShape.1.next, growsNext, splicedNext, packetNext, guardedNext]
  subst commitId
  obtain ⟨first, firstFresh, firstRun, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨firstEq, firstNext, firstBootstrap, firstColumns, _⟩ :=
    fresh_success commitDefined firstFresh first firstRun
  have firstIdEq : first = before.next + 7 := by
    rw [firstEq, commitNext, signatureShape.1.next, commitSignatureNext, entriesNext,
      lengthNext, spliceShape.1.next, growsNext, splicedNext, packetNext, guardedNext]
  subst first
  obtain ⟨retirement, retirementFresh, retirementRun, run⟩ :=
    (bind_run _ _ _ _ _).mp run
  obtain ⟨retirementEq, retirementNext, retirementBootstrap, retirementColumns, _⟩ :=
    fresh_success firstFresh retirementFresh retirement retirementRun
  have retirementIdEq : retirement = before.next + 8 := by
    rw [retirementEq, firstNext, commitNext, signatureShape.1.next, commitSignatureNext,
      entriesNext, lengthNext, spliceShape.1.next, growsNext, splicedNext, packetNext,
      guardedNext]
  subst retirement
  obtain ⟨signature, signatureFresh, signatureFreshRun, run⟩ :=
    (bind_run _ _ _ _ _).mp run
  obtain ⟨signatureEq, signatureNext, signatureBootstrap, signatureColumns, _⟩ :=
    fresh_success retirementFresh signatureFresh signature signatureFreshRun
  have signatureIdEq : signature = before.next + 9 := by
    rw [signatureEq, retirementNext, firstNext, commitNext, signatureShape.1.next,
      commitSignatureNext, entriesNext, lengthNext, spliceShape.1.next, growsNext,
      splicedNext, packetNext, guardedNext]
  subst signature
  obtain ⟨retired, retiredFresh, retiredRun, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨retiredEq, retiredNext, retiredBootstrap, retiredColumns, _⟩ :=
    fresh_success signatureFresh retiredFresh retired retiredRun
  have retiredIdEq : retired = before.next + 10 := by
    rw [retiredEq, signatureNext, retirementNext, firstNext, commitNext,
      signatureShape.1.next, commitSignatureNext, entriesNext, lengthNext,
      spliceShape.1.next, growsNext, splicedNext, packetNext, guardedNext]
  subst retired
  obtain ⟨⟨⟩, refreshAsserted, refreshRun, run⟩ := (bind_run _ _ _ _ _).mp run
  have refreshShape := assertion_success _ retiredFresh refreshAsserted refreshRun
  obtain ⟨current, currentFresh, currentRun, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨currentEq, currentNext, currentBootstrap, currentColumns, _⟩ :=
    fresh_success refreshAsserted currentFresh current currentRun
  have currentIdEq : current = before.next + 11 := by
    rw [currentEq, refreshShape.1.next, retiredNext, signatureNext, retirementNext,
      firstNext, commitNext, signatureShape.1.next, commitSignatureNext, entriesNext,
      lengthNext, spliceShape.1.next, growsNext, splicedNext, packetNext, guardedNext]
  subst current
  obtain ⟨⟨⟩, currentAsserted, currentAssertionRun, run⟩ :=
    (bind_run _ _ _ _ _).mp run
  have currentAssertionShape :=
    assertion_success _ currentFresh currentAsserted currentAssertionRun
  obtain ⟨completed, completedState, completedRun, run⟩ :=
    (bind_run _ _ _ _ _).mp run
  have completedShape :=
    retirement_completed_constraints_success before.bootstrap _ _ _ _ _
      currentAsserted completedState completed completedRun
  have completedIdEq : completed = before.next + 12 := by
    rw [completedShape.completedId, currentAssertionShape.1.next, currentNext,
      refreshShape.1.next, retiredNext, signatureNext, retirementNext, firstNext,
      commitNext, signatureShape.1.next, commitSignatureNext, entriesNext, lengthNext,
      spliceShape.1.next, growsNext, splicedNext, packetNext, guardedNext]
  subst completed
  obtain ⟨best, bestFresh, bestRun, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨bestEq, bestNext, bestBootstrap, bestColumns, _⟩ :=
    fresh_success completedState bestFresh best bestRun
  have bestIdEq : best = before.next + 13 + 3 * width := by
    rw [bestEq, completedShape.next, currentAssertionShape.1.next, currentNext,
      refreshShape.1.next, retiredNext, signatureNext, retirementNext, firstNext,
      commitNext, signatureShape.1.next, commitSignatureNext, entriesNext, lengthNext,
      spliceShape.1.next, growsNext, splicedNext, packetNext, guardedNext]
  subst best
  obtain ⟨⟨⟩, writerBefore, nackRun, writeRun⟩ := (bind_run _ _ _ _ _).mp run
  have nackShape := assertion_success _ bestFresh writerBefore nackRun
  simp_rw [guardedNext] at packetRun
  simp_rw [packetNext, guardedNext] at splicedRun
  simp_rw [splicedNext, packetNext, guardedNext] at growsRun
  simp_rw [splicedNext, packetNext, guardedNext] at spliceRun
  simp_rw [spliceShape.1.next, growsNext, splicedNext, packetNext, guardedNext] at lengthRun
  simp_rw [lengthNext, spliceShape.1.next, growsNext, splicedNext, packetNext, guardedNext]
    at entriesRun
  simp_rw [entriesNext, lengthNext, spliceShape.1.next, growsNext, splicedNext, packetNext,
    guardedNext] at commitSignatureRun
  simp_rw [entriesNext, lengthNext, spliceShape.1.next, growsNext,
    splicedNext, packetNext, guardedNext] at signatureRun
  simp_rw [signatureShape.1.next, commitSignatureNext, entriesNext, lengthNext,
    spliceShape.1.next, growsNext, splicedNext, packetNext, guardedNext] at commitRun
  simp_rw [commitNext, signatureShape.1.next, commitSignatureNext, entriesNext, lengthNext,
    spliceShape.1.next, growsNext, splicedNext, packetNext, guardedNext] at firstRun
  simp_rw [firstNext, commitNext, signatureShape.1.next, commitSignatureNext, entriesNext,
    lengthNext, spliceShape.1.next, growsNext, splicedNext, packetNext, guardedNext]
    at retirementRun
  simp_rw [retirementNext, firstNext, commitNext, signatureShape.1.next, commitSignatureNext,
    entriesNext, lengthNext, spliceShape.1.next, growsNext, splicedNext, packetNext,
    guardedNext] at signatureFreshRun
  simp_rw [signatureNext, retirementNext, firstNext, commitNext, signatureShape.1.next,
    commitSignatureNext, entriesNext, lengthNext, spliceShape.1.next, growsNext,
    splicedNext, packetNext, guardedNext] at retiredRun
  simp_rw [signatureNext, retirementNext, firstNext, commitNext,
    signatureShape.1.next, commitSignatureNext, entriesNext, lengthNext,
    spliceShape.1.next, growsNext, splicedNext, packetNext, guardedNext] at refreshRun
  simp_rw [refreshShape.1.next, retiredNext, signatureNext, retirementNext, firstNext,
    commitNext, signatureShape.1.next, commitSignatureNext, entriesNext, lengthNext,
    spliceShape.1.next, growsNext, splicedNext, packetNext, guardedNext] at currentRun
  simp_rw [refreshShape.1.next, retiredNext, signatureNext, retirementNext,
    firstNext, commitNext, signatureShape.1.next, commitSignatureNext, entriesNext,
    lengthNext, spliceShape.1.next, growsNext, splicedNext, packetNext, guardedNext]
    at currentAssertionRun
  simp_rw [refreshShape.1.next, retiredNext,
    signatureNext, retirementNext, firstNext, commitNext, signatureShape.1.next,
    commitSignatureNext, entriesNext, lengthNext, spliceShape.1.next, growsNext,
    splicedNext, packetNext, guardedNext] at completedRun
  simp_rw [completedShape.next, currentAssertionShape.1.next, currentNext,
    refreshShape.1.next, retiredNext, signatureNext, retirementNext, firstNext,
    commitNext, signatureShape.1.next, commitSignatureNext, entriesNext, lengthNext,
    spliceShape.1.next, growsNext, splicedNext, packetNext, guardedNext] at bestRun
  simp_rw [completedShape.next, currentAssertionShape.1.next, currentNext,
    refreshShape.1.next, retiredNext, signatureNext, retirementNext, firstNext,
    commitNext, signatureShape.1.next, commitSignatureNext, entriesNext, lengthNext,
    spliceShape.1.next, growsNext, splicedNext, packetNext, guardedNext] at nackRun
  simp_rw [completedShape.next, currentAssertionShape.1.next, currentNext,
    refreshShape.1.next, retiredNext, signatureNext, retirementNext, firstNext,
    commitNext, signatureShape.1.next, commitSignatureNext, entriesNext, lengthNext,
    spliceShape.1.next, growsNext, splicedNext, packetNext, guardedNext] at writeRun
  let suffix : AppendReceiveSuffixStates width :=
    { firstFresh, retirementFresh, signatureFresh, retiredFresh, refreshAsserted,
      currentFresh, currentAsserted, completedState, bestFresh, writerBefore }
  let middle : AppendReceiveMiddleStates width :=
    { lengthDefined, entriesDefined, commitSignatureFresh, signatureAsserted,
      commitDefined, suffix }
  let states : AppendReceivePrefixStates width :=
    { guarded, packetDefined, splicedFresh, growsDefined, spliceAsserted, middle }
  have runs : AppendReceivePrefixRuns source destination before after states := by
    refine ⟨guardsRun, ?_, ?_, ?_, ?_, ?_⟩
    · simpa [states] using packetRun
    · simpa [states] using splicedRun
    · simpa [states, appendReceiveExecutionTerms] using growsRun
    · simpa [states, appendReceiveExecutionTerms] using spliceRun
    · refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
      · simpa [states, middle, appendReceiveExecutionTerms] using lengthRun
      · simpa [states, middle, appendReceiveExecutionTerms] using entriesRun
      · simpa [states, middle] using commitSignatureRun
      · simpa [states, middle, appendReceiveExecutionTerms] using signatureRun
      · simpa [states, middle, appendReceiveExecutionTerms] using commitRun
      · refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
        · simpa [states, middle, suffix] using firstRun
        · simpa [states, middle, suffix] using retirementRun
        · simpa [states, middle, suffix] using signatureFreshRun
        · simpa [states, middle, suffix] using retiredRun
        · simpa [states, middle, suffix, appendReceiveExecutionTerms] using refreshRun
        · simpa [states, middle, suffix] using currentRun
        · simpa [states, middle, suffix, appendReceiveExecutionTerms] using
            currentAssertionRun
        · simpa [states, middle, suffix, appendReceiveExecutionTerms] using completedRun
        · simpa [states, middle, suffix] using bestRun
        · simpa [states, middle, suffix, appendReceiveExecutionTerms] using nackRun
        · simpa [states, middle, suffix, appendReceiveExecutionTerms] using writeRun
  have writerBootstrap : writerBefore.bootstrap = before.bootstrap := by
    exact nackShape.1.bootstrap.trans
      (bestBootstrap.trans
        (completedShape.sameBootstrap.trans
          (currentAssertionShape.1.bootstrap.trans
            (currentBootstrap.trans
              (refreshShape.1.bootstrap.trans
                (retiredBootstrap.trans
                  (signatureBootstrap.trans
                    (retirementBootstrap.trans
                      (firstBootstrap.trans
                        (commitBootstrap.trans
                          (signatureShape.1.bootstrap.trans
                            (commitSignatureBootstrap.trans
                              (entriesBootstrap.trans
                                (lengthBootstrap.trans
                                  (spliceShape.1.bootstrap.trans
                                    (growsBootstrap.trans
                                      (splicedBootstrap.trans
                                        (packetBootstrap.trans guardsShape.bootstrap))))))))))))))))))
  have writerColumns : writerBefore.toColumns = before.toColumns := by
    exact nackShape.1.columns.trans
      (bestColumns.trans
        (completedShape.sameColumns.trans
          (currentAssertionShape.1.columns.trans
            (currentColumns.trans
              (refreshShape.1.columns.trans
                (retiredColumns.trans
                  (signatureColumns.trans
                    (retirementColumns.trans
                      (firstColumns.trans
                        (commitColumns.trans
                          (signatureShape.1.columns.trans
                            (commitSignatureColumns.trans
                              (entriesColumns.trans
                                (lengthColumns.trans
                                  (spliceShape.1.columns.trans
                                    (growsColumns.trans
                                      (splicedColumns.trans
                                        (packetColumns.trans guardsShape.columns))))))))))))))))))
  have writerNext : writerBefore.next = before.next + 14 + 3 * width := by
    rw [nackShape.1.next, bestNext, completedShape.next, currentAssertionShape.1.next,
      currentNext, refreshShape.1.next, retiredNext, signatureNext, retirementNext,
      firstNext, commitNext, signatureShape.1.next, commitSignatureNext, entriesNext,
      lengthNext, spliceShape.1.next, growsNext, splicedNext, packetNext, guardedNext]
    omega
  obtain ⟨_, _, _, _, _, _, _, writesShape⟩ :=
    append_receive_writes_success source destination
      (appendReceiveExecutionTerms before source destination).branches.stepDown
      (appendReceiveExecutionTerms before source destination).values
      (appendReceiveExecutionTerms before source destination).response
      (appendReceiveExecutionTerms before source destination).completed
      writerBefore after writeRun
  have finalNext : after.next = before.next + 38 + 3 * width := by
    rw [writesShape.next, writerNext]
    omega
  exact ⟨states, runs, writerBootstrap, writerColumns, writerNext, finalNext⟩


end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
