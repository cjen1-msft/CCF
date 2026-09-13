-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeNodeRowWritesEncoding
import Sparse.NativeQueuePopEncoding
import Sparse.NativeVoteResponse

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

structure VoteResponseExecutionStates (width : PNat) where
  guardsAsserted : Encoding width
  rowWritten : Encoding width

structure VoteResponseExecutionRuns {width : PNat} (preVote : Bool)
    (source destination : Fin width) (before after : Encoding width)
    (states : VoteResponseExecutionStates width) : Prop where
  guardsRun :
    (assertAll (voteResponseGuards before.toColumns preVote source destination)).run
      before = .ok ((), states.guardsAsserted)
  rowRun :
    (writeNodeRow destination
      (voteResponseRowTerms before.toColumns preVote source destination)).run
        states.guardsAsserted = .ok ((), states.rowWritten)
  popRun :
    (popQueue destination source).run states.rowWritten = .ok ((), after)

structure VoteResponseExecutionResult {width : PNat} (preVote : Bool)
    (source destination : Fin width) (before after : Encoding width)
    (states : VoteResponseExecutionStates width) : Prop where
  runs : VoteResponseExecutionRuns preVote source destination before after states
  guardsAssertedNext : states.guardsAsserted.next = before.next
  guardsAssertedColumns :
    states.guardsAsserted.toColumns = before.toColumns
  rowWrittenNext : states.rowWritten.next = before.next + 16
  rowWrittenColumns :
    states.rowWritten.toColumns =
      nodeRowWriteColumns before.toColumns before.next
  afterBootstrap : after.bootstrap = before.bootstrap
  afterNext : after.next = before.next + 18
  afterColumns :
    after.toColumns =
      { nodeRowWriteColumns before.toColumns before.next with
        queueLength := before.next + 16
        queueHead := before.next + 17 }

theorem vote_response_success {width : PNat} (preVote : Bool)
    (source destination : Fin width) (before after : Encoding width)
    (run :
      (receiveVoteResponse preVote source destination).run before =
        .ok ((), after)) :
    exists states : VoteResponseExecutionStates width,
      VoteResponseExecutionResult preVote source destination before after states := by
  rw [receiveVoteResponse, get_bind_run] at run
  obtain ⟨⟨⟩, guardsAsserted, guardsRun, run⟩ :=
    (bind_run _ _ _ _ _).mp run
  obtain ⟨⟨⟩, rowWritten, rowRun, popRun⟩ :=
    (bind_run _ _ _ _ _).mp run
  have guardsShape :=
    (assert_all_success
      (voteResponseGuards before.toColumns preVote source destination)
      before guardsAsserted guardsRun).1
  have rowShape :=
    write_node_row_success destination
      (voteResponseRowTerms before.toColumns preVote source destination)
      guardsAsserted rowWritten rowRun
  have popShape := pop_queue_success destination source rowWritten after popRun
  have guardsAssertedNext : guardsAsserted.next = before.next :=
    guardsShape.next
  have guardsAssertedColumns : guardsAsserted.toColumns = before.toColumns :=
    guardsShape.columns
  have rowWrittenNext : rowWritten.next = before.next + 16 := by
    rw [rowShape.next, guardsAssertedNext]
  have rowWrittenColumns :
      rowWritten.toColumns =
        nodeRowWriteColumns before.toColumns before.next := by
    rw [rowShape.columns, guardsAssertedColumns, guardsAssertedNext]
  have afterBootstrap : after.bootstrap = before.bootstrap :=
    popShape.bootstrap.trans (rowShape.bootstrap.trans guardsShape.bootstrap)
  have afterNext : after.next = before.next + 18 := by
    rw [popShape.next, rowWrittenNext]
  have afterColumns :
      after.toColumns =
        { nodeRowWriteColumns before.toColumns before.next with
          queueLength := before.next + 16
          queueHead := before.next + 17 } := by
    rw [popShape.columns, rowWrittenColumns, rowWrittenNext]
  let states : VoteResponseExecutionStates width := { guardsAsserted, rowWritten }
  exact ⟨states,
    { runs := by
        exact ⟨guardsRun, rowRun, popRun⟩
      guardsAssertedNext
      guardsAssertedColumns
      rowWrittenNext
      rowWrittenColumns
      afterBootstrap
      afterNext
      afterColumns }⟩

theorem vote_response_bootstrap {width : PNat} (preVote : Bool)
    (source destination : Fin width) (before after : Encoding width)
    (run :
      (receiveVoteResponse preVote source destination).run before =
        .ok ((), after)) :
    after.bootstrap = before.bootstrap := by
  obtain ⟨_, execution⟩ :=
    vote_response_success preVote source destination before after run
  exact execution.afterBootstrap

theorem vote_response_prior_holds {width : PNat} (preVote : Bool)
    (source destination : Fin width) (before after : Encoding width)
    (run :
      (receiveVoteResponse preVote source destination).run before =
        .ok ((), after))
    (assignment : Assignment)
    (holds : Holds after.assertions.toList assignment) :
    Holds before.assertions.toList assignment := by
  obtain ⟨states, execution⟩ :=
    vote_response_success preVote source destination before after run
  have rowHolds :=
    (pop_queue_holds destination source states.rowWritten after
      execution.runs.popRun assignment).mp holds |>.1
  have guardHolds :=
    write_node_row_prior_holds destination
      (voteResponseRowTerms before.toColumns preVote source destination)
      states.guardsAsserted states.rowWritten execution.runs.rowRun assignment
      rowHolds
  exact
    ((assert_all_holds
      (voteResponseGuards before.toColumns preVote source destination)
      before states.guardsAsserted execution.runs.guardsRun assignment).mp
        guardHolds).1

theorem vote_response_references {width : PNat} (preVote : Bool)
    (source destination : Fin width) (before after : Encoding width)
    (run :
      (receiveVoteResponse preVote source destination).run before =
        .ok ((), after))
    (valid : ReferencesValid before) :
    ReferencesValid after := by
  obtain ⟨states, execution⟩ :=
    vote_response_success preVote source destination before after run
  have guardedValid : ReferencesValid states.guardsAsserted :=
    valid.same_references
      (assert_all_success
        (voteResponseGuards before.toColumns preVote source destination)
        before states.guardsAsserted execution.runs.guardsRun).1
  have rowValid : ReferencesValid states.rowWritten :=
    write_node_row_references destination
      (voteResponseRowTerms before.toColumns preVote source destination)
      states.guardsAsserted states.rowWritten execution.runs.rowRun guardedValid
  exact
    pop_queue_references destination source states.rowWritten after
      execution.runs.popRun rowValid

theorem vote_response_next {width : PNat} (preVote : Bool)
    (source destination : Fin width) (before after : Encoding width)
    (run :
      (receiveVoteResponse preVote source destination).run before =
        .ok ((), after)) :
    after.next = before.next + 18 := by
  obtain ⟨_, execution⟩ :=
    vote_response_success preVote source destination before after run
  exact execution.afterNext

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
