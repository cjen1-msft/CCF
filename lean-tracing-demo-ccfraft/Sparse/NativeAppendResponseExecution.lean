-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeNodeRowWritesEncoding
import Sparse.NativeQueuePopEncoding
import Sparse.NativeAppendResponse

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

structure AppendResponseExecutionTerms (width : PNat) where
  old : NodeRowTerms width
  packet : Expr (packetTy width)
  payload : Expr (.pair .bool .int)
  witness : Expr .int
  scan : Expr .bool
  values : NodeRowTerms width

def appendResponseExecutionTerms {width : PNat} (before : Encoding width)
    (source destination : Fin width) : AppendResponseExecutionTerms width :=
  let old := nodeRowSnapshot before.toColumns destination
  let packet := queueHeadPacketTerm before.toColumns source destination
  let payload := appendResponsePayloadTerm packet
  let witness : Expr .int := .free .int before.next
  { old, packet, payload, witness
    scan := nackMatchTerm width old.logLength old.logEntries payload.snd
      (.fst (.fst packet)) witness
    values := appendResponseRowTerms before.toColumns source destination witness }

structure AppendResponseExecutionStates (width : PNat) where
  guardsAsserted : Encoding width
  witnessFresh : Encoding width
  scanAsserted : Encoding width
  rowWritten : Encoding width

structure AppendResponseExecutionRuns {width : PNat}
    (source destination : Fin width) (before after : Encoding width)
    (states : AppendResponseExecutionStates width) : Prop where
  guardsRun :
    (assertAll (appendResponseGuards before.toColumns source destination)).run
      before = .ok ((), states.guardsAsserted)
  witnessRun :
    fresh.run states.guardsAsserted =
      .ok (before.next, states.witnessFresh)
  scanRun :
    let terms := appendResponseExecutionTerms before source destination
    (assertion terms.scan).run states.witnessFresh =
      .ok ((), states.scanAsserted)
  rowRun :
    let terms := appendResponseExecutionTerms before source destination
    (writeNodeRow destination terms.values).run states.scanAsserted =
      .ok ((), states.rowWritten)
  popRun :
    (popQueue destination source).run states.rowWritten = .ok ((), after)

structure AppendResponseExecutionResult {width : PNat}
    (source destination : Fin width) (before after : Encoding width)
    (states : AppendResponseExecutionStates width) : Prop where
  runs : AppendResponseExecutionRuns source destination before after states
  guardsAssertedNext : states.guardsAsserted.next = before.next
  guardsAssertedColumns :
    states.guardsAsserted.toColumns = before.toColumns
  witnessFreshNext : states.witnessFresh.next = before.next + 1
  witnessFreshColumns :
    states.witnessFresh.toColumns = before.toColumns
  scanAssertedNext : states.scanAsserted.next = before.next + 1
  scanAssertedColumns :
    states.scanAsserted.toColumns = before.toColumns
  rowWrittenNext : states.rowWritten.next = before.next + 17
  rowWrittenColumns :
    states.rowWritten.toColumns =
      nodeRowWriteColumns before.toColumns (before.next + 1)
  afterBootstrap : after.bootstrap = before.bootstrap
  afterNext : after.next = before.next + 19
  afterColumns :
    after.toColumns =
      { nodeRowWriteColumns before.toColumns (before.next + 1) with
        queueLength := before.next + 17
        queueHead := before.next + 18 }

theorem append_response_success {width : PNat}
    (source destination : Fin width) (before after : Encoding width)
    (run :
      (receiveAppendResponse source destination).run before =
        .ok ((), after)) :
    exists states : AppendResponseExecutionStates width,
      AppendResponseExecutionResult source destination before after states := by
  rw [receiveAppendResponse, get_bind_run] at run
  obtain ⟨⟨⟩, guardsAsserted, guardsRun, run⟩ :=
    (bind_run _ _ _ _ _).mp run
  obtain ⟨witness, witnessFresh, witnessRun, run⟩ :=
    (bind_run _ _ _ _ _).mp run
  obtain ⟨⟨⟩, scanAsserted, scanRun, run⟩ :=
    (bind_run _ _ _ _ _).mp run
  obtain ⟨⟨⟩, rowWritten, rowRun, popRun⟩ :=
    (bind_run _ _ _ _ _).mp run
  have guardsShape :=
    (assert_all_success
      (appendResponseGuards before.toColumns source destination)
      before guardsAsserted guardsRun).1
  obtain ⟨witnessEq, witnessNext, witnessBootstrap, witnessColumns, _⟩ :=
    fresh_success guardsAsserted witnessFresh witness witnessRun
  have witnessId : witness = before.next :=
    witnessEq.trans guardsShape.next
  subst witness
  simp_rw [guardsShape.next] at scanRun rowRun
  have scanShape :=
    assertion_success
      (appendResponseExecutionTerms before source destination).scan
      witnessFresh scanAsserted scanRun
  have rowShape :=
    write_node_row_success destination
      (appendResponseExecutionTerms before source destination).values
      scanAsserted rowWritten rowRun
  have popShape :=
    pop_queue_success destination source rowWritten after popRun
  have witnessFreshNext : witnessFresh.next = before.next + 1 := by
    rw [witnessNext, guardsShape.next]
  have witnessFreshColumns : witnessFresh.toColumns = before.toColumns :=
    witnessColumns.trans guardsShape.columns
  have scanAssertedNext : scanAsserted.next = before.next + 1 :=
    scanShape.1.next.trans witnessFreshNext
  have scanAssertedColumns : scanAsserted.toColumns = before.toColumns :=
    scanShape.1.columns.trans witnessFreshColumns
  have rowWrittenNext : rowWritten.next = before.next + 17 := by
    rw [rowShape.next, scanAssertedNext]
  have rowWrittenColumns :
      rowWritten.toColumns =
        nodeRowWriteColumns before.toColumns (before.next + 1) := by
    rw [rowShape.columns, scanAssertedColumns, scanAssertedNext]
  have afterBootstrap : after.bootstrap = before.bootstrap :=
    popShape.bootstrap.trans
      (rowShape.bootstrap.trans
        (scanShape.1.bootstrap.trans
          (witnessBootstrap.trans guardsShape.bootstrap)))
  have afterNext : after.next = before.next + 19 := by
    rw [popShape.next, rowWrittenNext]
  have afterColumns :
      after.toColumns =
        { nodeRowWriteColumns before.toColumns (before.next + 1) with
          queueLength := before.next + 17
          queueHead := before.next + 18 } := by
    rw [popShape.columns, rowWrittenColumns, rowWrittenNext]
  simp_rw [guardsShape.next] at witnessRun
  let states : AppendResponseExecutionStates width :=
    { guardsAsserted, witnessFresh, scanAsserted, rowWritten }
  exact ⟨states,
    { runs := by
        exact ⟨guardsRun, witnessRun, scanRun, rowRun, popRun⟩
      guardsAssertedNext := guardsShape.next
      guardsAssertedColumns := guardsShape.columns
      witnessFreshNext
      witnessFreshColumns
      scanAssertedNext
      scanAssertedColumns
      rowWrittenNext
      rowWrittenColumns
      afterBootstrap
      afterNext
      afterColumns }⟩

theorem append_response_bootstrap {width : PNat}
    (source destination : Fin width) (before after : Encoding width)
    (run :
      (receiveAppendResponse source destination).run before =
        .ok ((), after)) :
    after.bootstrap = before.bootstrap := by
  obtain ⟨_, execution⟩ :=
    append_response_success source destination before after run
  exact execution.afterBootstrap

theorem append_response_prior_holds {width : PNat}
    (source destination : Fin width) (before after : Encoding width)
    (run :
      (receiveAppendResponse source destination).run before =
        .ok ((), after))
    (assignment : Assignment)
    (holds : Holds after.assertions.toList assignment) :
    Holds before.assertions.toList assignment := by
  obtain ⟨states, execution⟩ :=
    append_response_success source destination before after run
  have rowHolds :=
    (pop_queue_holds destination source states.rowWritten after
      execution.runs.popRun assignment).mp holds |>.1
  have scanHolds :=
    write_node_row_prior_holds destination
      (appendResponseExecutionTerms before source destination).values
      states.scanAsserted states.rowWritten execution.runs.rowRun assignment
      rowHolds
  have witnessHolds :=
    (assertion_holds
      (appendResponseExecutionTerms before source destination).scan
      states.witnessFresh states.scanAsserted execution.runs.scanRun
      assignment scanHolds).1
  have guardHolds :=
    fresh_prior_holds states.guardsAsserted states.witnessFresh before.next
      execution.runs.witnessRun assignment witnessHolds
  exact
    ((assert_all_holds
      (appendResponseGuards before.toColumns source destination)
      before states.guardsAsserted execution.runs.guardsRun assignment).mp
        guardHolds).1

theorem append_response_references {width : PNat}
    (source destination : Fin width) (before after : Encoding width)
    (run :
      (receiveAppendResponse source destination).run before =
        .ok ((), after))
    (valid : ReferencesValid before) :
    ReferencesValid after := by
  obtain ⟨states, execution⟩ :=
    append_response_success source destination before after run
  have guardedValid : ReferencesValid states.guardsAsserted :=
    valid.same_references
      (assert_all_success
        (appendResponseGuards before.toColumns source destination)
        before states.guardsAsserted execution.runs.guardsRun).1
  have witnessValid : ReferencesValid states.witnessFresh := by
    have shape :=
      fresh_success states.guardsAsserted states.witnessFresh before.next
        execution.runs.witnessRun
    cases guardedValid
    constructor <;> simp only [shape.2.1, shape.2.2.2.1] <;> omega
  have scanValid : ReferencesValid states.scanAsserted :=
    witnessValid.same_references
      (assertion_success
        (appendResponseExecutionTerms before source destination).scan
        states.witnessFresh states.scanAsserted execution.runs.scanRun).1
  have rowValid : ReferencesValid states.rowWritten :=
    write_node_row_references destination
      (appendResponseExecutionTerms before source destination).values
      states.scanAsserted states.rowWritten execution.runs.rowRun scanValid
  exact
    pop_queue_references destination source states.rowWritten after
      execution.runs.popRun rowValid

theorem append_response_next {width : PNat}
    (source destination : Fin width) (before after : Encoding width)
    (run :
      (receiveAppendResponse source destination).run before =
        .ok ((), after)) :
    after.next = before.next + 19 := by
  obtain ⟨_, execution⟩ :=
    append_response_success source destination before after run
  exact execution.afterNext

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
