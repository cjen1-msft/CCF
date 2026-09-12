-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeQueueStore
import Sparse.NativeFrameColumns

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def pushQueueClauses {width : PNat} (before : Encoding width) (destination source : Fin width)
    (packet : Expr (packetTy width)) : List (Expr .bool) :=
  [.equal (.free (.array .int (.array .int .int)) before.next)
      (queuePushLengths before.toColumns destination source),
    .equal (.free (queueCellsTy width) (before.next + 1))
      (queuePushPackets before.toColumns destination source packet)]

structure PushQueueResult {width : PNat} (before after : Encoding width)
    (destination source : Fin width) (packet : Expr (packetTy width)) : Prop where
  bootstrap : after.bootstrap = before.bootstrap
  columns : after.toColumns =
    { before.toColumns with queueLength := before.next, queueCells := before.next + 1 }
  next : after.next = before.next + 2
  clauses : after.assertions.toList = before.assertions.toList ++ pushQueueClauses before destination source packet
  packetSymbols : forall symbol, symbol ∈ packet.symbols -> symbol.2 < before.next

theorem push_queue_success {width : PNat} (destination source : Fin width) (packet : Expr (packetTy width))
    (before after : Encoding width) (run : (pushQueue destination source packet).run before = .ok ((), after)) :
    PushQueueResult before after destination source packet := by
  simp only [pushQueue, get_bind_run] at run
  split at run
  · rename_i known
    obtain ⟨nextLength, middle, lengthRun, run⟩ := (bind_run _ _ _ _ _).mp run
    obtain ⟨nextPackets, final, packetRun, run⟩ := (bind_run _ _ _ _ _).mp run
    change Except.ok ((), { final with queueLength := nextLength, queueCells := nextPackets }) =
      .ok ((), after) at run
    have same := congrArg Prod.snd (Except.ok.inj run)
    dsimp only at same
    rw [<- same]
    obtain ⟨lengthId, middleNext, middleBootstrap, middleColumns, middleClauses⟩ :=
      define_success _ before middle nextLength lengthRun
    obtain ⟨packetId, finalNext, finalBootstrap, finalColumns, finalClauses⟩ :=
      define_success _ middle final nextPackets packetRun
    have packetIndex : nextPackets = before.next + 1 := packetId.trans middleNext
    constructor
    · exact finalBootstrap.trans middleBootstrap
    · simp only [finalColumns, middleColumns, lengthId, packetIndex]
    · dsimp only
      rw [finalNext, middleNext]
    · dsimp only
      rw [finalClauses, Array.toList_push, middleClauses, Array.toList_push, lengthId, packetIndex]
      simp [pushQueueClauses, List.append_assoc]
    · intro symbol member
      have accepted : packet.symbols.all (fun symbol => symbol.2 < before.next) = true := by simpa using known
      simpa only [decide_eq_true_eq] using List.all_eq_true.mp accepted symbol member
  · cases run

theorem push_queue_holds {width : PNat} (destination source : Fin width) (packet : Expr (packetTy width))
    (before after : Encoding width) (run : (pushQueue destination source packet).run before = .ok ((), after))
    (assignment : Assignment) :
    Holds after.assertions.toList assignment <->
      Holds before.assertions.toList assignment /\
        assignment (.array .int (.array .int .int)) before.next =
          (queuePushLengths before.toColumns destination source).eval assignment Locals.empty /\
        assignment (queueCellsTy width) (before.next + 1) =
          (queuePushPackets before.toColumns destination source packet).eval assignment Locals.empty := by
  rw [(push_queue_success destination source packet before after run).clauses]
  simp [Holds, pushQueueClauses, Term.eval, or_imp, forall_and]

theorem push_queue_references {width : PNat} (destination source : Fin width) (packet : Expr (packetTy width))
    (before after : Encoding width) (run : (pushQueue destination source packet).run before = .ok ((), after))
    (valid : ReferencesValid before) : ReferencesValid after := by
  have shape := push_queue_success destination source packet before after run
  cases valid
  constructor <;> simp only [shape.columns, shape.next] <;> omega

theorem push_queue_frame_success {width : PNat} (packet : Expr (packetTy width))
    (expected : Message (Fin width) Nat) (before after : Encoding width)
    (run : (pushQueue expected.destination expected.source packet).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (samePacket : packet.eval assignment Locals.empty = packetValue expected) :
    FrameColumnsRep assignment after.toColumns
      { frame with queues := NativeArrayQueue.send frame.queues expected } := by
  have shape := push_queue_success expected.destination expected.source packet before after run
  obtain ⟨_, lengthBinding, packetBinding⟩ :=
    (push_queue_holds expected.destination expected.source packet before after run assignment).mp holds
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
  · intro destination source
    rw [shape.columns, queue_push_columns_rows assignment before.toColumns expected.destination expected.source
      destination source packet expected before.next (before.next + 1) lengthBinding packetBinding samePacket rfl,
      rep.queues destination source]
    by_cases sameDestination : destination = expected.destination <;>
      by_cases sameSource : source = expected.source <;>
        simp [NativeArrayQueue.send, sameDestination, sameSource, NativeArrayQueue.Queue.push_correct]

theorem push_queue_complete {width : PNat} (packet : Expr (packetTy width))
    (expected : Message (Fin width) Nat) (before after : Encoding width)
    (run : (pushQueue expected.destination expected.source packet).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds before.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame) (valid : ReferencesValid before)
    (samePacket : packet.eval assignment Locals.empty = packetValue expected) :
    exists extended : Assignment, assignment.AgreesBelow before.next extended /\
      Holds after.assertions.toList extended /\
      FrameColumnsRep extended after.toColumns
        { frame with queues := NativeArrayQueue.send frame.queues expected } := by
  have shape := push_queue_success expected.destination expected.source packet before after run
  have executed := run
  simp only [pushQueue, get_bind_run] at executed
  split at executed
  · obtain ⟨lengthId, middle, lengthRun, executed⟩ := (bind_run _ _ _ _ _).mp executed
    obtain ⟨packetId, final, packetRun, executed⟩ := (bind_run _ _ _ _ _).mp executed
    change Except.ok ((), { final with queueLength := lengthId, queueCells := packetId }) =
      .ok ((), after) at executed
    have sameFinal := congrArg Prod.snd (Except.ok.inj executed)
    dsimp only at sameFinal
    obtain ⟨first, firstAgreement, firstHolds⟩ := define_extension _ before middle lengthId lengthRun assignment holds
    obtain ⟨extended, secondAgreement, finalHolds⟩ := define_extension _ middle final packetId packetRun first firstHolds
    have middleNext := (define_success _ before middle lengthId lengthRun).2.1
    have agreement : assignment.AgreesBelow before.next extended :=
      firstAgreement.trans (secondAgreement.restrict (by rw [middleNext]; omega))
    have afterHolds : Holds after.assertions.toList extended := by
      rw [<- sameFinal]
      exact finalHolds
    have extendedPacket : packet.eval extended Locals.empty = packetValue expected :=
      (packet.eval_agrees_below assignment extended Locals.empty before.next shape.packetSymbols agreement).symm.trans
        samePacket
    exact ⟨extended, agreement, afterHolds,
      push_queue_frame_success packet expected before after run extended afterHolds frame
        (rep.agrees_below before assignment extended frame valid agreement) extendedPacket⟩
  · cases executed

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
