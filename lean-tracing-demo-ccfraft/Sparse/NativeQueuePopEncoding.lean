-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeQueuePop
import Sparse.NativeFrameColumns

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def popQueueClauses {width : PNat} (before : Encoding width) (destination source : Fin width) :
    List (Expr .bool) :=
  [.equal (.free (.array .int (.array .int .int)) before.next)
      (queuePopLengths before.toColumns destination source),
    .equal (.free (.array .int (.array .int .int)) (before.next + 1))
      (queuePopHeads before.toColumns destination source)]

structure PopQueueResult {width : PNat} (before after : Encoding width)
    (destination source : Fin width) : Prop where
  bootstrap : after.bootstrap = before.bootstrap
  columns : after.toColumns =
    { before.toColumns with queueLength := before.next, queueHead := before.next + 1 }
  next : after.next = before.next + 2
  clauses : after.assertions.toList =
    before.assertions.toList ++ popQueueClauses before destination source

theorem pop_queue_success {width : PNat} (destination source : Fin width)
    (before after : Encoding width) (run : (popQueue destination source).run before = .ok ((), after)) :
    PopQueueResult before after destination source := by
  simp only [popQueue, get_bind_run] at run
  obtain ⟨nextLength, middle, lengthRun, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨nextHead, final, headRun, run⟩ := (bind_run _ _ _ _ _).mp run
  change Except.ok ((), { final with queueLength := nextLength, queueHead := nextHead }) =
    .ok ((), after) at run
  have same := congrArg Prod.snd (Except.ok.inj run)
  dsimp only at same
  rw [<- same]
  obtain ⟨lengthId, middleNext, middleBootstrap, middleColumns, middleClauses⟩ :=
    define_success _ before middle nextLength lengthRun
  obtain ⟨headId, finalNext, finalBootstrap, finalColumns, finalClauses⟩ :=
    define_success _ middle final nextHead headRun
  have headIndex : nextHead = before.next + 1 := headId.trans middleNext
  constructor
  · exact finalBootstrap.trans middleBootstrap
  · simp only [finalColumns, middleColumns, lengthId, headIndex]
  · dsimp only
    rw [finalNext, middleNext]
  · dsimp only
    rw [finalClauses, Array.toList_push, middleClauses, Array.toList_push, lengthId, headIndex]
    simp [popQueueClauses, List.append_assoc]

theorem pop_queue_holds {width : PNat} (destination source : Fin width)
    (before after : Encoding width) (run : (popQueue destination source).run before = .ok ((), after))
    (assignment : Assignment) :
    Holds after.assertions.toList assignment <->
      Holds before.assertions.toList assignment /\
        assignment (.array .int (.array .int .int)) before.next =
          (queuePopLengths before.toColumns destination source).eval assignment Locals.empty /\
        assignment (.array .int (.array .int .int)) (before.next + 1) =
          (queuePopHeads before.toColumns destination source).eval assignment Locals.empty := by
  rw [(pop_queue_success destination source before after run).clauses]
  simp [Holds, popQueueClauses, Term.eval, or_imp, forall_and]

theorem pop_queue_references {width : PNat} (destination source : Fin width)
    (before after : Encoding width) (run : (popQueue destination source).run before = .ok ((), after))
    (valid : ReferencesValid before) : ReferencesValid after := by
  have shape := pop_queue_success destination source before after run
  cases valid
  constructor <;> simp only [shape.columns, shape.next] <;> omega

theorem pop_queue_frame_success {width : PNat} (source destination : Fin width)
    (before after : Encoding width)
    (run : (popQueue destination source).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame) :
    FrameColumnsRep assignment after.toColumns
      { frame with queues := NativeArrayQueue.popSource frame.queues destination source } := by
  have shape := pop_queue_success destination source before after run
  obtain ⟨_, lengthBinding, headBinding⟩ :=
    (pop_queue_holds destination source before after run assignment).mp holds
  constructor
  · simp only [shape.columns]
    have nodes := rep.nodes
    cases nodes
    constructor <;> assumption
  · simpa only [shape.columns] using rep.hasJoined
  · intro node
    simpa only [shape.columns] using rep.preVoteStatus node
  · intro node
    simpa only [shape.columns] using rep.retirementCompleted node
  · intro txId
    simpa only [shape.columns] using rep.submittedTxIds txId
  · intro readDestination readSource
    rw [shape.columns, queue_pop_columns_rows assignment before.toColumns destination source
      readDestination readSource before.next (before.next + 1) lengthBinding headBinding,
      rep.queues readDestination readSource]
    by_cases sameDestination : readDestination = destination <;>
      by_cases sameSource : readSource = source <;>
        simp [NativeArrayQueue.popSource, sameDestination, sameSource,
          NativeArrayQueue.Queue.pop_correct]

theorem pop_queue_complete {width : PNat} (source destination : Fin width)
    (before after : Encoding width)
    (run : (popQueue destination source).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds before.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame) (valid : ReferencesValid before) :
    exists extended : Assignment, assignment.AgreesBelow before.next extended /\
      Holds after.assertions.toList extended /\
      FrameColumnsRep extended after.toColumns
        { frame with queues := NativeArrayQueue.popSource frame.queues destination source } := by
  have executed := run
  simp only [popQueue, get_bind_run] at executed
  obtain ⟨lengthId, middle, lengthRun, executed⟩ := (bind_run _ _ _ _ _).mp executed
  obtain ⟨headId, final, headRun, executed⟩ := (bind_run _ _ _ _ _).mp executed
  change Except.ok ((), { final with queueLength := lengthId, queueHead := headId }) =
    .ok ((), after) at executed
  have sameFinal := congrArg Prod.snd (Except.ok.inj executed)
  dsimp only at sameFinal
  obtain ⟨first, firstAgreement, firstHolds⟩ :=
    define_extension _ before middle lengthId lengthRun assignment holds
  obtain ⟨extended, secondAgreement, finalHolds⟩ :=
    define_extension _ middle final headId headRun first firstHolds
  have middleNext := (define_success _ before middle lengthId lengthRun).2.1
  have agreement : assignment.AgreesBelow before.next extended :=
    firstAgreement.trans (secondAgreement.restrict (by rw [middleNext]; omega))
  have afterHolds : Holds after.assertions.toList extended := by
    rw [<- sameFinal]
    exact finalHolds
  exact ⟨extended, agreement, afterHolds,
    pop_queue_frame_success source destination before after run extended afterHolds frame
      (rep.agrees_below before assignment extended frame valid agreement)⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
