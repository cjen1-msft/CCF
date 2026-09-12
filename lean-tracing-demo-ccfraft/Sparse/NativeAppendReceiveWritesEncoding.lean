-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendReceiveWrites
import Sparse.NativeNodeRowWritesEncoding
import Sparse.NativeQueuePopEncoding
import Sparse.NativeQueueStoreEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def appendReceiveWriteFrame {width : PNat}
    (frame : NativeArrayVote.Frame (Fin width) Nat) (source destination : Fin width)
    (stepsDown : Bool) (row : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (response : AppendEntriesResponse (Fin width)) (completed : Finset (Fin width)) :
    NativeArrayVote.Frame (Fin width) Nat :=
  { frame with
    nodes := Function.update frame.nodes destination (some row)
    queues := if stepsDown then frame.queues else NativeArrayQueue.send
        (NativeArrayQueue.popSource frame.queues destination source)
        (.appendEntriesResponse response)
    globals := { frame.globals with
      retirementCompleted := if stepsDown then frame.globals.retirementCompleted else
        Function.update frame.globals.retirementCompleted destination completed } }

def appendReceiveMergeDefinitions {width : PNat} (before consumed : Encoding width)
    (destination : Fin width) (stepDown : Expr .bool) (completed : Expr (.bits width)) :
    List TypedDefinition :=
  [⟨_, .ite stepDown
      (.free (.array .int (.array .int .int)) before.queueLength)
      (.free (.array .int (.array .int .int)) consumed.queueLength)⟩,
    ⟨_, .ite stepDown
      (.free (.array .int (.array .int .int)) before.queueHead)
      (.free (.array .int (.array .int .int)) consumed.queueHead)⟩,
    ⟨_, .ite stepDown
      (.free (queueCellsTy width) before.queueCells)
      (.free (queueCellsTy width) consumed.queueCells)⟩,
    ⟨_, .ite stepDown
      (.free (.array .int (.bits width)) before.retirementCompleted)
      (.store (.free (.array .int (.bits width)) before.retirementCompleted)
        (.integer destination.val) completed)⟩]

def appendReceiveMergedColumns (consumed : Columns) (base : Nat) : Columns :=
  { consumed with
    queueLength := base
    queueHead := base + 1
    queueCells := base + 2
    retirementCompleted := base + 3 }

structure AppendReceiveWritesResult {width : PNat} (source destination : Fin width)
    (stepDown : Expr .bool) (values : NodeRowTerms width)
    (response : Expr (packetTy width)) (completed : Expr (.bits width))
    (before rowWritten popped consumed first second third fourth after : Encoding width) : Prop where
  inputsBounded :
    stepDown.symbols.all (fun symbol => symbol.2 < before.next) = true /\
    response.symbols.all (fun symbol => symbol.2 < before.next) = true /\
    completed.symbols.all (fun symbol => symbol.2 < before.next) = true
  rowRun : (writeNodeRow destination values).run before = .ok ((), rowWritten)
  popRun : (popQueue destination source).run rowWritten = .ok ((), popped)
  pushRun : (pushQueue source destination response).run popped = .ok ((), consumed)
  lengthRun : (define (Term.ite stepDown
    (.free (.array .int (.array .int .int)) before.queueLength)
    (.free (.array .int (.array .int .int)) consumed.queueLength))).run
      consumed = .ok (consumed.next, first)
  headRun : (define (Term.ite stepDown
    (.free (.array .int (.array .int .int)) before.queueHead)
    (.free (.array .int (.array .int .int)) consumed.queueHead))).run
      first = .ok (consumed.next + 1, second)
  cellsRun : (define (Term.ite stepDown
    (.free (queueCellsTy width) before.queueCells)
    (.free (queueCellsTy width) consumed.queueCells))).run
      second = .ok (consumed.next + 2, third)
  completedRun : (define (Term.ite stepDown
    (.free (.array .int (.bits width)) before.retirementCompleted)
    (.store (.free (.array .int (.bits width)) before.retirementCompleted)
      (.integer destination.val) completed))).run
      third = .ok (consumed.next + 3, fourth)
  bootstrap : after.bootstrap = before.bootstrap
  columns : after.toColumns = appendReceiveMergedColumns consumed.toColumns consumed.next
  next : after.next = before.next + 24
  clauses : after.assertions.toList = consumed.assertions.toList ++
    definitionClauses
      (appendReceiveMergeDefinitions before consumed destination stepDown completed)
      consumed.next

theorem append_receive_writes_success {width : PNat} (source destination : Fin width)
    (stepDown : Expr .bool) (values : NodeRowTerms width)
    (response : Expr (packetTy width)) (completed : Expr (.bits width))
    (before after : Encoding width)
    (run : (appendReceiveWrites source destination stepDown values response completed).run before =
      .ok ((), after)) :
    exists rowWritten popped consumed first second third fourth,
      AppendReceiveWritesResult source destination stepDown values response completed
        before rowWritten popped consumed first second third fourth after := by
  simp only [appendReceiveWrites, get_bind_run] at run
  split at run
  · rename_i bounded
    obtain ⟨_, rowWritten, rowRun, run⟩ := (bind_run _ _ _ _ _).mp run
    obtain ⟨_, popped, popRun, run⟩ := (bind_run _ _ _ _ _).mp run
    obtain ⟨_, consumed, pushRun, run⟩ := (bind_run _ _ _ _ _).mp run
    simp only [get_bind_run] at run
    obtain ⟨lengthId, first, lengthRun, run⟩ := (bind_run _ _ _ _ _).mp run
    obtain ⟨headId, second, headRun, run⟩ := (bind_run _ _ _ _ _).mp run
    obtain ⟨cellsId, third, cellsRun, run⟩ := (bind_run _ _ _ _ _).mp run
    obtain ⟨completedId, fourth, completedRun, run⟩ := (bind_run _ _ _ _ _).mp run
    let queueLength := lengthId
    let queueHead := headId
    let queueCells := cellsId
    let retirementCompleted := completedId
    have final :
        { fourth with queueLength, queueHead, queueCells, retirementCompleted } = after :=
      congrArg Prod.snd (Except.ok.inj run)
    have rowShape := write_node_row_success destination values before rowWritten rowRun
    have popShape := pop_queue_success destination source rowWritten popped popRun
    have pushShape := push_queue_success source destination response popped consumed pushRun
    obtain ⟨lengthEq, firstNext, firstBootstrap, firstColumns, firstClauses⟩ :=
      define_success _ consumed first lengthId lengthRun
    obtain ⟨headEq, secondNext, secondBootstrap, secondColumns, secondClauses⟩ :=
      define_success _ first second headId headRun
    obtain ⟨cellsEq, thirdNext, thirdBootstrap, thirdColumns, thirdClauses⟩ :=
      define_success _ second third cellsId cellsRun
    obtain ⟨completedEq, fourthNext, fourthBootstrap, fourthColumns, fourthClauses⟩ :=
      define_success _ third fourth completedId completedRun
    have headIndex : headId = consumed.next + 1 := headEq.trans firstNext
    have cellsIndex : cellsId = consumed.next + 2 := by rw [cellsEq, secondNext, firstNext]
    have completedIndex : completedId = consumed.next + 3 := by
      rw [completedEq, thirdNext, secondNext, firstNext]
    refine ⟨rowWritten, popped, consumed, first, second, third, fourth,
      ?_, rowRun, popRun, pushRun, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
    · simp only [Bool.and_eq_true] at bounded
      exact ⟨bounded.1.1, bounded.1.2, bounded.2⟩
    · simpa [lengthEq] using lengthRun
    · simpa [headIndex] using headRun
    · simpa [cellsIndex] using cellsRun
    · simpa [completedIndex] using completedRun
    · rw [<- final]
      exact fourthBootstrap.trans (thirdBootstrap.trans (secondBootstrap.trans
        (firstBootstrap.trans (pushShape.bootstrap.trans
          (popShape.bootstrap.trans rowShape.bootstrap)))))
    · rw [<- final]
      simp [appendReceiveMergedColumns, fourthColumns, thirdColumns, secondColumns,
        firstColumns, queueLength, queueHead, queueCells, retirementCompleted,
        lengthEq, headIndex, cellsIndex, completedIndex]
    · rw [<- final, fourthNext, thirdNext, secondNext, firstNext, pushShape.next,
        popShape.next, rowShape.next]
    · rw [<- final, fourthClauses, Array.toList_push, thirdClauses, Array.toList_push,
        secondClauses, Array.toList_push, firstClauses, Array.toList_push,
        lengthEq, headIndex, cellsIndex, completedIndex]
      simp [appendReceiveMergeDefinitions, definitionClauses, List.append_assoc]
  · cases run

theorem AppendReceiveWritesResult.merge_holds {width : PNat}
    {source destination : Fin width} {stepDown : Expr .bool}
    {values : NodeRowTerms width} {response : Expr (packetTy width)}
    {completed : Expr (.bits width)}
    {before rowWritten popped consumed first second third fourth after : Encoding width}
    (shape : AppendReceiveWritesResult source destination stepDown values response completed
      before rowWritten popped consumed first second third fourth after)
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment) :
    Holds consumed.assertions.toList assignment /\
    assignment (.array .int (.array .int .int)) consumed.next =
      (Term.ite stepDown (.free _ before.queueLength) (.free _ consumed.queueLength)).eval
        assignment Locals.empty /\
    assignment (.array .int (.array .int .int)) (consumed.next + 1) =
      (Term.ite stepDown (.free _ before.queueHead) (.free _ consumed.queueHead)).eval
        assignment Locals.empty /\
    assignment (queueCellsTy width) (consumed.next + 2) =
      (Term.ite stepDown (.free _ before.queueCells) (.free _ consumed.queueCells)).eval
        assignment Locals.empty /\
    assignment (.array .int (.bits width)) (consumed.next + 3) =
      (Term.ite stepDown (.free _ before.retirementCompleted)
        (.store (.free _ before.retirementCompleted) (.integer destination.val) completed)).eval
          assignment Locals.empty := by
  rw [shape.clauses] at holds
  simpa [Holds, appendReceiveMergeDefinitions, definitionClauses, Term.eval, or_imp, forall_and]
    using holds

theorem append_receive_writes_holds_before {width : PNat} (source destination : Fin width)
    (stepDown : Expr .bool) (values : NodeRowTerms width)
    (response : Expr (packetTy width)) (completed : Expr (.bits width))
    (before after : Encoding width)
    (run : (appendReceiveWrites source destination stepDown values response completed).run before =
      .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment) :
    Holds before.assertions.toList assignment := by
  obtain ⟨rowWritten, popped, consumed, _, _, _, _, shape⟩ :=
    append_receive_writes_success source destination stepDown values response completed before after run
  have consumedHolds := (shape.merge_holds assignment holds).1
  have poppedHolds :=
    ((push_queue_holds source destination response popped consumed shape.pushRun assignment).mp
      consumedHolds).1
  have rowHolds :=
    ((pop_queue_holds destination source rowWritten popped shape.popRun assignment).mp
      poppedHolds).1
  exact write_node_row_prior_holds destination values before rowWritten shape.rowRun assignment rowHolds

theorem append_receive_writes_references {width : PNat} (source destination : Fin width)
    (stepDown : Expr .bool) (values : NodeRowTerms width)
    (response : Expr (packetTy width)) (completed : Expr (.bits width))
    (before after : Encoding width)
    (run : (appendReceiveWrites source destination stepDown values response completed).run before =
      .ok ((), after))
    (valid : ReferencesValid before) : ReferencesValid after := by
  obtain ⟨rowWritten, popped, consumed, _, _, _, _, shape⟩ :=
    append_receive_writes_success source destination stepDown values response completed before after run
  have rowValid := write_node_row_references destination values before rowWritten shape.rowRun valid
  have popValid := pop_queue_references destination source rowWritten popped shape.popRun rowValid
  have consumedValid := push_queue_references source destination response popped consumed
    shape.pushRun popValid
  have rowNext := (write_node_row_success destination values before rowWritten shape.rowRun).next
  have popNext := (pop_queue_success destination source rowWritten popped shape.popRun).next
  have consumedNext := (push_queue_success source destination response popped consumed shape.pushRun).next
  cases consumedValid
  constructor <;>
    simp_all only [shape.columns, appendReceiveMergedColumns, shape.next] <;> omega

theorem append_receive_merged_frame {width : PNat}
    {source destination : Fin width} {stepDown : Expr .bool}
    {values : NodeRowTerms width} {responseTerm : Expr (packetTy width)}
    {completedTerm : Expr (.bits width)}
    {before rowWritten popped consumed first second third fourth after : Encoding width}
    (shape : AppendReceiveWritesResult source destination stepDown values responseTerm completedTerm
      before rowWritten popped consumed first second third fourth after)
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame consumedFrame : NativeArrayVote.Frame (Fin width) Nat)
    (beforeRep : FrameColumnsRep assignment before.toColumns frame)
    (consumedRep : FrameColumnsRep assignment consumed.toColumns consumedFrame)
    (sameGlobals : consumedFrame.globals = frame.globals)
    (stepsDown : Bool)
    (sameStep : stepDown.eval assignment Locals.empty = stepsDown)
    (completed : Finset (Fin width))
    (sameCompleted : completedTerm.eval assignment Locals.empty = encodeBits completed) :
    FrameColumnsRep assignment after.toColumns
      { frame with
        nodes := consumedFrame.nodes
        queues := if stepsDown then frame.queues else consumedFrame.queues
        globals := { frame.globals with
          retirementCompleted := if stepsDown then frame.globals.retirementCompleted else
            Function.update frame.globals.retirementCompleted destination completed } } := by
  obtain ⟨_, lengthBinding, headBinding, cellsBinding, completedBinding⟩ :=
    shape.merge_holds assignment holds
  constructor
  · rw [shape.columns]
    have nodes := consumedRep.nodes
    cases nodes
    constructor <;> assumption
  · have represented := consumedRep.hasJoined
    rw [sameGlobals] at represented
    simpa only [shape.columns, appendReceiveMergedColumns] using represented
  · intro node
    have represented := consumedRep.preVoteStatus node
    rw [sameGlobals] at represented
    simpa only [shape.columns, appendReceiveMergedColumns] using represented
  · intro node
    rw [shape.columns]
    simp only [appendReceiveMergedColumns]
    cases stepsDown
    · simp [Term.eval, sameStep] at completedBinding ⊢
      rw [completedBinding]
      by_cases same : node = destination
      · subst node
        simp [sameCompleted]
      · have different : (node.val : Int) ≠ (destination.val : Int) := by
          intro equal
          exact same (Fin.ext (by omega))
        simp [same, different]
        exact beforeRep.retirementCompleted node
    · simp [Term.eval, sameStep] at completedBinding ⊢
      rw [completedBinding]
      exact beforeRep.retirementCompleted node
  · intro txId
    have represented := consumedRep.submittedTxIds txId
    rw [sameGlobals] at represented
    simpa only [shape.columns, appendReceiveMergedColumns] using represented
  · intro readDestination readSource
    rw [shape.columns]
    simp only [appendReceiveMergedColumns, queueRow]
    cases stepsDown
    · simp [Term.eval, sameStep] at lengthBinding headBinding cellsBinding ⊢
      rw [lengthBinding, headBinding, cellsBinding]
      exact consumedRep.queues readDestination readSource
    · simp [Term.eval, sameStep] at lengthBinding headBinding cellsBinding ⊢
      rw [lengthBinding, headBinding, cellsBinding]
      exact beforeRep.queues readDestination readSource

theorem append_receive_writes_frame_sound {width : PNat}
    (source destination : Fin width) (stepDown : Expr .bool)
    (values : NodeRowTerms width) (row : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (responseTerm : Expr (packetTy width)) (response : AppendEntriesResponse (Fin width))
    (completedTerm : Expr (.bits width)) (completed : Finset (Fin width))
    (before after : Encoding width)
    (run : (appendReceiveWrites source destination stepDown values responseTerm completedTerm).run
      before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (valuesRep : values.Rep assignment row) (stepsDown : Bool)
    (sameStep : stepDown.eval assignment Locals.empty = stepsDown)
    (sameResponse : responseTerm.eval assignment Locals.empty =
      packetValue (.appendEntriesResponse response))
    (responseSource : response.source = destination)
    (responseDestination : response.destination = source)
    (sameCompleted : completedTerm.eval assignment Locals.empty = encodeBits completed) :
    FrameColumnsRep assignment after.toColumns
      (appendReceiveWriteFrame frame source destination stepsDown row response completed) := by
  obtain ⟨rowWritten, popped, consumed, _, _, _, _, shape⟩ :=
    append_receive_writes_success source destination stepDown values responseTerm completedTerm
      before after run
  have consumedHolds := (shape.merge_holds assignment holds).1
  have poppedHolds :=
    ((push_queue_holds source destination responseTerm popped consumed shape.pushRun assignment).mp
      consumedHolds).1
  have rowHolds :=
    ((pop_queue_holds destination source rowWritten popped shape.popRun assignment).mp
      poppedHolds).1
  let rowFrame : NativeArrayVote.Frame (Fin width) Nat :=
    { frame with nodes := Function.update frame.nodes destination (some row) }
  have rowRep := write_node_row_frame_sound destination values row before rowWritten shape.rowRun
    assignment rowHolds frame rep valuesRep
  have poppedRep := pop_queue_frame_success source destination rowWritten popped shape.popRun
    assignment poppedHolds rowFrame (by simpa [rowFrame] using rowRep)
  let packet : Message (Fin width) Nat := .appendEntriesResponse response
  have packetDestination : packet.destination = source := by
    simpa [packet] using responseDestination
  have packetSource : packet.source = destination := by
    simpa [packet] using responseSource
  have packetRun :
      (pushQueue packet.destination packet.source responseTerm).run popped =
        .ok ((), consumed) := by
    rw [packetDestination, packetSource]
    exact shape.pushRun
  have consumedRep := push_queue_frame_success responseTerm packet popped consumed packetRun
    assignment consumedHolds
    { rowFrame with queues := NativeArrayQueue.popSource rowFrame.queues destination source }
    poppedRep sameResponse
  let consumedFrame : NativeArrayVote.Frame (Fin width) Nat :=
    { rowFrame with queues :=
        NativeArrayQueue.send (NativeArrayQueue.popSource rowFrame.queues destination source) packet }
  have merged := append_receive_merged_frame shape assignment holds frame
    consumedFrame rep (by simpa [consumedFrame] using consumedRep)
    (by simp [consumedFrame, rowFrame]) stepsDown sameStep completed
    sameCompleted
  simpa [appendReceiveWriteFrame, consumedFrame, rowFrame, packet] using merged

theorem append_receive_writes_complete {width : PNat}
    (source destination : Fin width) (stepDown : Expr .bool)
    (values : NodeRowTerms width) (row : NativeArrayCheckQuorum.Local (Fin width) Nat)
    (responseTerm : Expr (packetTy width)) (response : AppendEntriesResponse (Fin width))
    (completedTerm : Expr (.bits width)) (completed : Finset (Fin width))
    (before after : Encoding width)
    (run : (appendReceiveWrites source destination stepDown values responseTerm completedTerm).run
      before = .ok ((), after))
    (assignment : Assignment) (holds : Holds before.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (valuesRep : values.Rep assignment row) (valid : ReferencesValid before)
    (stepsDown : Bool) (sameStep : stepDown.eval assignment Locals.empty = stepsDown)
    (sameResponse : responseTerm.eval assignment Locals.empty =
      packetValue (.appendEntriesResponse response))
    (responseSource : response.source = destination)
    (responseDestination : response.destination = source)
    (sameCompleted : completedTerm.eval assignment Locals.empty = encodeBits completed) :
    exists extended : Assignment, assignment.AgreesBelow before.next extended /\
      Holds after.assertions.toList extended /\
      FrameColumnsRep extended after.toColumns
        (appendReceiveWriteFrame frame source destination stepsDown row response completed) := by
  obtain ⟨rowWritten, popped, consumed, first, second, third, fourth, shape⟩ :=
    append_receive_writes_success source destination stepDown values responseTerm completedTerm
      before after run
  have stepSymbols : forall symbol, symbol ∈ stepDown.symbols ->
      symbol.2 < before.next := by
    exact fun symbol member => by
      simpa using List.all_eq_true.mp shape.inputsBounded.1 symbol member
  have responseSymbols : forall symbol, symbol ∈ responseTerm.symbols ->
      symbol.2 < before.next := by
    exact fun symbol member => by
      simpa using List.all_eq_true.mp shape.inputsBounded.2.1 symbol member
  have completedSymbols : forall symbol, symbol ∈ completedTerm.symbols ->
      symbol.2 < before.next := by
    exact fun symbol member => by
      simpa using List.all_eq_true.mp shape.inputsBounded.2.2 symbol member
  let rowFrame : NativeArrayVote.Frame (Fin width) Nat :=
    { frame with nodes := Function.update frame.nodes destination (some row) }
  obtain ⟨rowAssignment, rowAgreement, rowHolds, rowRep⟩ :=
    write_node_row_complete destination values row before rowWritten shape.rowRun assignment holds
      frame rep valuesRep valid
  have rowValid := write_node_row_references destination values before rowWritten shape.rowRun valid
  obtain ⟨popAssignment, popAgreement, popHolds, popRep⟩ :=
    pop_queue_complete source destination rowWritten popped shape.popRun rowAssignment rowHolds
      rowFrame (by simpa [rowFrame] using rowRep) rowValid
  have rowNext := (write_node_row_success destination values before rowWritten shape.rowRun).next
  have originalToPop : assignment.AgreesBelow before.next popAssignment :=
    rowAgreement.trans (popAgreement.restrict (by rw [rowNext]; omega))
  have popValid := pop_queue_references destination source rowWritten popped shape.popRun rowValid
  have popResponse :
      responseTerm.eval popAssignment Locals.empty =
        packetValue (.appendEntriesResponse response) :=
    (responseTerm.eval_agrees_below assignment popAssignment Locals.empty before.next
      responseSymbols originalToPop).symm.trans sameResponse
  let packet : Message (Fin width) Nat := .appendEntriesResponse response
  have packetDestination : packet.destination = source := by
    simpa [packet] using responseDestination
  have packetSource : packet.source = destination := by
    simpa [packet] using responseSource
  have packetRun :
      (pushQueue packet.destination packet.source responseTerm).run popped =
        .ok ((), consumed) := by
    rw [packetDestination, packetSource]
    exact shape.pushRun
  let poppedFrame : NativeArrayVote.Frame (Fin width) Nat :=
    { rowFrame with queues := NativeArrayQueue.popSource rowFrame.queues destination source }
  obtain ⟨consumedAssignment, pushAgreement, consumedHolds, consumedRep⟩ :=
    push_queue_complete responseTerm packet popped consumed packetRun popAssignment popHolds
      poppedFrame (by simpa [poppedFrame] using popRep) popValid popResponse
  have popNext := (pop_queue_success destination source rowWritten popped shape.popRun).next
  have originalToConsumed : assignment.AgreesBelow before.next consumedAssignment :=
    originalToPop.trans (pushAgreement.restrict (by rw [popNext, rowNext]; omega))
  have consumedValid := push_queue_references source destination responseTerm popped consumed
    shape.pushRun popValid
  obtain ⟨lengthAssignment, lengthAgreement, lengthHolds⟩ :=
    define_extension _ consumed first consumed.next shape.lengthRun consumedAssignment consumedHolds
  obtain ⟨headAssignment, headAgreement, headHolds⟩ :=
    define_extension _ first second (consumed.next + 1) shape.headRun lengthAssignment lengthHolds
  obtain ⟨cellsAssignment, cellsAgreement, cellsHolds⟩ :=
    define_extension _ second third (consumed.next + 2) shape.cellsRun headAssignment headHolds
  obtain ⟨extended, completedAgreement, fourthHolds⟩ :=
    define_extension _ third fourth (consumed.next + 3) shape.completedRun cellsAssignment cellsHolds
  have firstNext := (define_success _ consumed first consumed.next shape.lengthRun).2.1
  have secondNext := (define_success _ first second (consumed.next + 1) shape.headRun).2.1
  have thirdNext := (define_success _ second third (consumed.next + 2) shape.cellsRun).2.1
  have consumedToExtended : consumedAssignment.AgreesBelow consumed.next extended :=
    lengthAgreement.trans ((headAgreement.restrict (by rw [firstNext]; omega)).trans
      ((cellsAgreement.restrict (by rw [secondNext, firstNext]; omega)).trans
        (completedAgreement.restrict (by rw [thirdNext, secondNext, firstNext]; omega))))
  have originalToExtended : assignment.AgreesBelow before.next extended :=
    originalToConsumed.trans (consumedToExtended.restrict (by
      have consumedNext :=
        (push_queue_success source destination responseTerm popped consumed shape.pushRun).next
      rw [consumedNext, popNext, rowNext]
      omega))
  have afterHolds : Holds after.assertions.toList extended := by
    rw [shape.clauses]
    obtain ⟨_, _, _, _, firstClauses⟩ :=
      define_success _ consumed first consumed.next shape.lengthRun
    obtain ⟨_, _, _, _, secondClauses⟩ :=
      define_success _ first second (consumed.next + 1) shape.headRun
    obtain ⟨_, _, _, _, thirdClauses⟩ :=
      define_success _ second third (consumed.next + 2) shape.cellsRun
    obtain ⟨_, _, _, _, fourthClauses⟩ :=
      define_success _ third fourth (consumed.next + 3) shape.completedRun
    rw [fourthClauses, Array.toList_push, thirdClauses, Array.toList_push,
      secondClauses, Array.toList_push, firstClauses, Array.toList_push] at fourthHolds
    simpa [appendReceiveMergeDefinitions, definitionClauses, List.append_assoc] using fourthHolds
  have finalBeforeRep :=
    rep.agrees_below before assignment extended frame valid originalToExtended
  let consumedFrame : NativeArrayVote.Frame (Fin width) Nat :=
    { poppedFrame with queues := NativeArrayQueue.send poppedFrame.queues packet }
  have consumedNext :=
    (push_queue_success source destination responseTerm popped consumed shape.pushRun).next
  have finalConsumedRep := consumedRep.agrees_below consumed consumedAssignment extended
    consumedFrame consumedValid consumedToExtended
  have finalStep : stepDown.eval extended Locals.empty = stepsDown :=
    (stepDown.eval_agrees_below assignment extended Locals.empty before.next stepSymbols
      originalToExtended).symm.trans sameStep
  have finalCompleted : completedTerm.eval extended Locals.empty = encodeBits completed :=
    (completedTerm.eval_agrees_below assignment extended Locals.empty before.next completedSymbols
      originalToExtended).symm.trans sameCompleted
  refine ⟨extended, originalToExtended, afterHolds, ?_⟩
  have merged := append_receive_merged_frame shape extended afterHolds frame consumedFrame
    finalBeforeRep finalConsumedRep (by simp [consumedFrame, poppedFrame, rowFrame])
    stepsDown finalStep completed finalCompleted
  simpa [appendReceiveWriteFrame, consumedFrame, poppedFrame, rowFrame, packet] using merged

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
