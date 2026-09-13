-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeFrameColumns
import Sparse.NativeFrameEncode
import Sparse.NativeVoteSendEncoding
import Sparse.NativeTermUpdateEncoding
import Sparse.NativeCampaignEncoding
import Sparse.NativeAppendSendEncoding
import Sparse.NativeVoteReceiveEncoding
import Sparse.NativeAppendReceiveEncoding
import Sparse.NativeVoteResponseSound
import Sparse.NativeVoteResponseComplete
import Sparse.NativeAppendResponseSound
import Sparse.NativeAppendResponseComplete
import Sparse.NativeMembershipChangeEncoding
import Sparse.NativeAdvanceCommitEncoding
import Sparse.NativeSignCommittableEncoding
import Sparse.NativeBecomeLeaderExecution
import Sparse.NativeBecomeLeaderSound
import Sparse.NativeBecomeLeaderComplete
import Sparse.NativeClientRequestSound
import Sparse.NativeClientRequestStructure
import Sparse.NativeClientRequestComplete
import Sparse.NativeQueuePatternEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem frame_observation_run {width : PNat} (item : FrameInstruction width)
    (before : Encoding width) (clauses : List (Expr .bool))
    (emitted : frameObservationClauses before.toColumns item = .ok clauses) :
    (frameInstruction item).run before = (assertAll clauses).run before := by
  have observationRun
      (same : frameInstruction item = do
        let state <- get
        assertAll (<- frameObservationClauses state.toColumns item)) :
      (frameInstruction item).run before = (assertAll clauses).run before := by
    rw [same]
    simp only [get_bind_run]
    rw [emitted]
    rfl
  cases item
  case node item =>
    simp only [frameObservationClauses] at emitted
    exact observation_instruction_run item before clauses emitted
  case joined node expected =>
    exact observationRun rfl
  case hasJoined expected =>
    exact observationRun rfl
  case preVoteStatus node expected =>
    exact observationRun rfl
  case retirementCompleted node expected =>
    exact observationRun rfl
  case submittedTxId txId expected =>
    exact observationRun rfl
  case queueLength source destination expected =>
    exact observationRun rfl
  case queuePoint source destination index expected =>
    exact observationRun rfl
  case queuePattern source destination index expected =>
    exact observationRun rfl
  all_goals (simp only [frameObservationClauses] at emitted; cases emitted)

theorem frame_observation_correct {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (columns : Columns) (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment columns frame)
    (item : FrameInstruction width) (clauses : List (Expr .bool))
    (emitted : frameObservationClauses columns item = .ok clauses) :
    Holds clauses assignment <-> NativeArrayVote.follows frame [item] := by
  cases item
  case node item =>
    simp only [frameObservationClauses] at emitted
    simpa only [NativeArrayVote.follows, and_true] using
      observation_correct assignment columns frame.nodes rep.nodes item clauses emitted
  case joined node expected =>
    cases Except.ok.inj emitted
    simp only [Holds, List.mem_singleton, forall_eq, Term.eval, rep.hasJoined,
      NativeArrayVote.follows, and_true]
    change decide ((encodeBits frame.globals.hasJoined).getLsbD node.val = expected) = true <->
      decide (node ∈ frame.globals.hasJoined) = expected
    rw [encode_bits_bit]
    simp
  case hasJoined expected =>
    cases Except.ok.inj emitted
    simp [Holds, Term.eval, rep.hasJoined, encode_bits_eq, NativeArrayVote.follows]
  case preVoteStatus node expected =>
    cases Except.ok.inj emitted
    simp [Holds, Term.eval, rep.preVoteStatus, pre_vote_bit_eq, NativeArrayVote.follows]
  case retirementCompleted node expected =>
    cases Except.ok.inj emitted
    simp [Holds, Term.eval, rep.retirementCompleted, encode_bits_eq, NativeArrayVote.follows]
  case submittedTxId txId expected =>
    cases Except.ok.inj emitted
    cases expected <;> simp [Holds, natSetMember, all, lt, Term.eval, NativeArrayVote.follows]
    · simpa only [not_and_or, not_lt] using not_congr (rep.submittedTxIds txId)
    · exact rep.submittedTxIds txId
  case queueLength source destination expected =>
    cases Except.ok.inj emitted
    simp [Holds, Term.eval, queue_scalar_correct, rep.queue_length, NativeArrayVote.follows]
  case queuePoint source destination index expected =>
    cases Except.ok.inj emitted
    have headNatural : 0 <= (queueScalarTerm columns.queueHead
        (.integer destination.val) (.integer source.val)).eval assignment Locals.empty := by
      rw [queue_scalar_correct]
      exact Int.natCast_nonneg _
    have lengthNatural : 0 <= (queueScalarTerm columns.queueLength
        (.integer destination.val) (.integer source.val)).eval assignment Locals.empty := by
      rw [queue_scalar_correct]
      exact Int.natCast_nonneg _
    simp only [Holds, List.mem_singleton, forall_eq]
    rw [queue_point_correct source
      (queueScalarTerm columns.queueHead (.integer destination.val) (.integer source.val))
      (queueScalarTerm columns.queueLength (.integer destination.val) (.integer source.val))
      (queueCellsTerm columns.queueCells (.integer destination.val) (.integer source.val))
      index expected assignment Locals.empty headNatural lengthNatural]
    simp only [queue_scalar_correct, queueCellsTerm, Term.eval]
    change (queueRow assignment columns destination source).decode[index]? = some expected <->
      NativeArrayVote.follows frame [.queuePoint source destination index expected]
    rw [rep.queues destination source]
    simp only [NativeArrayVote.follows, and_true, NativeArrayQueue.Queue.point_correct]
  case queuePattern source destination index expected =>
    change Except.ok [queuePattern source
      (queueScalarTerm columns.queueHead
        (.integer destination.val) (.integer source.val))
      (queueScalarTerm columns.queueLength
        (.integer destination.val) (.integer source.val))
      (queueCellsTerm columns.queueCells
        (.integer destination.val) (.integer source.val)) index expected] =
      .ok clauses at emitted
    cases Except.ok.inj emitted
    have headNatural : 0 <= (queueScalarTerm columns.queueHead
        (.integer destination.val) (.integer source.val)).eval assignment Locals.empty := by
      rw [queue_scalar_correct]
      exact Int.natCast_nonneg _
    have lengthNatural : 0 <= (queueScalarTerm columns.queueLength
        (.integer destination.val) (.integer source.val)).eval assignment Locals.empty := by
      rw [queue_scalar_correct]
      exact Int.natCast_nonneg _
    simp only [Holds, List.mem_singleton, forall_eq]
    rw [queue_pattern_correct source
      (queueScalarTerm columns.queueHead (.integer destination.val) (.integer source.val))
      (queueScalarTerm columns.queueLength (.integer destination.val) (.integer source.val))
      (queueCellsTerm columns.queueCells (.integer destination.val) (.integer source.val))
      index expected assignment Locals.empty headNatural lengthNatural]
    simp only [queue_scalar_correct, queueCellsTerm, Term.eval]
    change (exists message,
      (queueRow assignment columns destination source).decode[index]? = some message /\
        expected.matches message = true) <->
      NativeArrayVote.follows frame [.queuePattern source destination index expected]
    rw [rep.queues destination source]
    simp only [NativeArrayVote.follows, and_true]
  all_goals (simp only [frameObservationClauses] at emitted; cases emitted)

theorem frame_observation_cons {width : PNat} [Bootstrap (Fin width)]
    (frame : NativeArrayVote.Frame (Fin width) Nat) (columns : Columns)
    (item : FrameInstruction width) (rest : List (FrameInstruction width))
    (clauses : List (Expr .bool)) (emitted : frameObservationClauses columns item = .ok clauses) :
    NativeArrayVote.follows frame (item :: rest) <->
      NativeArrayVote.follows frame [item] /\ NativeArrayVote.follows frame rest := by
  cases item
  case node item =>
    simp only [frameObservationClauses] at emitted
    simp only [NativeArrayVote.follows, observation_node_step frame columns item clauses emitted, and_true]
  case joined =>
    simp [NativeArrayVote.follows]
  case hasJoined =>
    simp [NativeArrayVote.follows]
  case preVoteStatus =>
    simp [NativeArrayVote.follows]
  case retirementCompleted =>
    simp [NativeArrayVote.follows]
  case submittedTxId =>
    simp [NativeArrayVote.follows]
  case queueLength =>
    simp [NativeArrayVote.follows]
  case queuePoint =>
    simp [NativeArrayVote.follows]
  case queuePattern =>
    simp [NativeArrayVote.follows]
  all_goals (simp only [frameObservationClauses] at emitted; cases emitted)

inductive FrameInstructionRun {width : PNat} (before after : Encoding width) :
    FrameInstruction width -> Prop where
  | quorum (node : Fin width)
      (run : (checkQuorum node.val).run before = .ok ((), after)) :
      FrameInstructionRun before after (.node (.checkQuorum node))
  | vote (preVote : Bool) (source destination : Fin width)
      (run : (sendVote preVote source destination).run before = .ok ((), after)) :
      FrameInstructionRun before after (.vote preVote source destination)
  | updateTerm (source destination : Fin width)
      (run : (NativeEncode.updateTerm source destination).run before = .ok ((), after)) :
      FrameInstructionRun before after (.updateTerm source destination)
  | campaign (preVote : Bool) (node : Fin width)
      (run : (NativeEncode.campaign preVote node).run before = .ok ((), after)) :
      FrameInstructionRun before after (.campaign preVote node)
  | receiveVote (source destination : Fin width)
      (run : (NativeEncode.receiveVote source destination).run before = .ok ((), after)) :
      FrameInstructionRun before after (.receiveVote source destination)
  | receiveAppend (source destination : Fin width)
      (run : (NativeEncode.receiveAppend source destination).run before = .ok ((), after)) :
      FrameInstructionRun before after (.receiveAppend source destination)
  | receiveVoteResponse (preVote : Bool) (source destination : Fin width)
      (run : (NativeEncode.receiveVoteResponse preVote source destination).run
        before = .ok ((), after)) :
      FrameInstructionRun before after
        (.receiveVoteResponse preVote source destination)
  | receiveAppendResponse (source destination : Fin width)
      (run : (NativeEncode.receiveAppendResponse source destination).run
        before = .ok ((), after)) :
      FrameInstructionRun before after (.receiveAppendResponse source destination)
  | changeConfiguration (source : Fin width) (configuration : Finset (Fin width))
      (run : (membershipChange source configuration).run before = .ok ((), after)) :
      FrameInstructionRun before after (.changeConfiguration source configuration)
  | advanceCommit (source : Fin width)
      (run : (advanceCommitIndex source).run before = .ok ((), after)) :
      FrameInstructionRun before after (.advanceCommit source)
  | signCommittable (source : Fin width)
      (run : (signCommittableMessages source).run before = .ok ((), after)) :
      FrameInstructionRun before after (.signCommittable source)
  | becomeLeader (source : Fin width)
      (run : (NativeEncode.becomeLeader source).run before = .ok ((), after)) :
      FrameInstructionRun before after (.becomeLeader source)
  | clientRequest (source : Fin width) (transaction : Nat)
      (run : (clientRequest source (.integer transaction)).run before = .ok ((), after)) :
      FrameInstructionRun before after (.clientRequest source transaction)
  | appendEntries (source destination : Fin width) (batchEnd : Nat)
      (run : (sendAppend source destination batchEnd).run before = .ok ((), after)) :
      FrameInstructionRun before after (.appendEntries source destination batchEnd)
  | observation {item : FrameInstruction width} (clauses : List (Expr .bool))
      (emitted : frameObservationClauses before.toColumns item = .ok clauses)
      (run : (assertAll clauses).run before = .ok ((), after)) :
      FrameInstructionRun before after item

theorem frame_instruction_cases {width : PNat} (item : FrameInstruction width)
    (before after : Encoding width) (run : (frameInstruction item).run before = .ok ((), after)) :
    FrameInstructionRun before after item := by
  cases item
  case node item =>
    rcases instruction_cases item before after run with ⟨node, rfl, action⟩ | ⟨clauses, emitted, asserted⟩
    · exact .quorum node action
    · exact .observation clauses emitted asserted
  case vote preVote source destination => exact .vote preVote source destination run
  case updateTerm source destination => exact .updateTerm source destination run
  case campaign preVote node => exact .campaign preVote node run
  case receiveVote source destination => exact .receiveVote source destination run
  case receiveAppend source destination => exact .receiveAppend source destination run
  case receiveVoteResponse preVote source destination =>
    exact .receiveVoteResponse preVote source destination run
  case receiveAppendResponse source destination =>
    exact .receiveAppendResponse source destination run
  case changeConfiguration source configuration =>
    exact .changeConfiguration source configuration run
  case advanceCommit source => exact .advanceCommit source run
  case signCommittable source => exact .signCommittable source run
  case becomeLeader source => exact .becomeLeader source run
  case clientRequest source transaction => exact .clientRequest source transaction run
  case appendEntries source destination batchEnd =>
    exact .appendEntries source destination batchEnd run
  case joined node expected => exact .observation _ rfl run
  case hasJoined expected => exact .observation _ rfl run
  case preVoteStatus node expected => exact .observation _ rfl run
  case retirementCompleted node expected =>
    exact .observation _ rfl run
  case submittedTxId txId expected =>
    exact .observation _ rfl run
  case queueLength source destination expected =>
    exact .observation _ rfl run
  case queuePoint source destination index expected =>
    exact FrameInstructionRun.observation _
      rfl
      ((frame_observation_run
        (.queuePoint source destination index expected) before _ rfl).symm.trans run)
  case queuePattern source destination index expected =>
    exact FrameInstructionRun.observation _
      rfl
      ((frame_observation_run
        (.queuePattern source destination index expected) before _ rfl).symm.trans run)

theorem frame_instruction_bootstrap {width : PNat}
    (item : FrameInstruction width) (before after : Encoding width)
    (run : (frameInstruction item).run before = .ok ((), after)) :
    after.bootstrap = before.bootstrap := by
  cases frame_instruction_cases item before after run with
  | quorum node action => exact (quorum_success node.val before after action).bootstrap
  | vote preVote source destination action =>
    exact send_vote_bootstrap preVote source destination before after action
  | updateTerm source destination action =>
    exact (term_update_success source destination before after action).bootstrap
  | campaign preVote node action =>
    exact campaign_bootstrap preVote node before after action
  | receiveVote source destination action =>
    exact receive_vote_bootstrap source destination before after action
  | receiveAppend source destination action =>
    exact receive_append_bootstrap source destination before after action
  | receiveVoteResponse preVote source destination action =>
    exact vote_response_bootstrap preVote source destination before after action
  | receiveAppendResponse source destination action =>
    exact append_response_bootstrap source destination before after action
  | changeConfiguration source configuration action =>
    exact membership_change_bootstrap source configuration before after action
  | advanceCommit source action =>
    exact advance_commit_bootstrap source before after action
  | signCommittable source action =>
    exact signature_bootstrap source before after action
  | becomeLeader source action =>
    exact become_leader_bootstrap source before after action
  | clientRequest source transaction action =>
    exact client_request_bootstrap source (.integer transaction) before after action
  | appendEntries source destination batchEnd action =>
    exact send_append_bootstrap source destination batchEnd before after action
  | observation clauses emitted asserted =>
    exact (assert_all_success clauses before after asserted).1.bootstrap

theorem frame_instruction_next_mono {width : PNat} (item : FrameInstruction width)
    (before after : Encoding width) (run : (frameInstruction item).run before = .ok ((), after)) :
    before.next <= after.next := by
  cases frame_instruction_cases item before after run with
  | quorum node action =>
    rw [(quorum_success node.val before after action).next]
    omega
  | vote preVote source destination action =>
    obtain ⟨guarded, shape, pushed⟩ :=
      send_vote_prefix preVote source destination before after action
    rw [(push_queue_success destination source _ guarded after pushed).next, shape.next]
    omega
  | updateTerm source destination action =>
    rw [(term_update_success source destination before after action).next]
    omega
  | campaign preVote node action =>
    obtain ⟨guarded, shape, written⟩ :=
      campaign_prefix preVote node before after action
    rw [(campaign_writes_success preVote node guarded after written).next, shape.next]
    omega
  | receiveVote source destination action =>
    obtain ⟨signature, guarded, prefixRun, writesRun⟩ :=
      receive_vote_runs source destination before after action
    obtain ⟨signatureEq, prefixShape⟩ :=
      receive_vote_prefix_success source destination before guarded signature prefixRun
    subst signature
    rw [receiveVoteTail] at writesRun
    obtain ⟨voted, popped, writes, popRun, pushRun⟩ :=
      vote_receive_writes_steps source destination _ _ guarded after writesRun
    rw [(push_queue_success source destination _ popped after pushRun).next,
      (pop_queue_success destination source voted popped popRun).next, writes.next,
      prefixShape.next]
    omega
  | receiveAppend source destination action =>
    obtain ⟨states, execution⟩ :=
      receive_append_success source destination before after action
    rw [execution.finalNext]
    omega
  | receiveVoteResponse preVote source destination action =>
    rw [vote_response_next preVote source destination before after action]
    omega
  | receiveAppendResponse source destination action =>
    rw [append_response_next source destination before after action]
    omega
  | changeConfiguration source configuration action =>
    obtain ⟨initial, suffix, execution⟩ :=
      membership_change_success source configuration before after action
    rw [execution.finalNext]
    omega
  | advanceCommit source action =>
    rw [advance_commit_next source before after action]
    omega
  | signCommittable source action =>
    obtain ⟨states, execution⟩ :=
      sign_committable_messages_prefix source before after action
    let terms := signaturePrefixTerms before source
    rw [retirement_tail_next before.bootstrap source terms.appended terms.old.commit
      (signatureGuards before.toColumns source) states.tailBefore after execution.runs.tailRun,
      execution.tailBeforeNext]
    omega
  | becomeLeader source action =>
    rw [become_leader_next source before after action]
    omega
  | clientRequest source transaction action =>
    rw [client_request_next source (.integer transaction) before after action]
    omega
  | appendEntries source destination batchEnd action =>
    obtain ⟨guarded, defined, prefixShape, definition, pushed⟩ :=
      append_send_steps source destination batchEnd before after action
    rw [(push_queue_success destination source _ _ after pushed).next,
      (define_success _ guarded defined _ definition).2.1, prefixShape.next]
    omega
  | observation clauses emitted action =>
    rw [(assert_all_success clauses before after action).1.next]

theorem frame_instruction_references {width : PNat} (item : FrameInstruction width)
    (before after : Encoding width) (run : (frameInstruction item).run before = .ok ((), after))
    (valid : ReferencesValid before) : ReferencesValid after := by
  cases frame_instruction_cases item before after run with
  | quorum node action => exact instruction_references (.checkQuorum node) before after action valid
  | vote preVote source destination action =>
    exact send_vote_references preVote source destination before after action valid
  | updateTerm source destination action =>
    exact term_update_references source destination before after action valid
  | campaign preVote node action =>
    exact campaign_references preVote node before after action valid
  | receiveVote source destination action =>
    exact receive_vote_references source destination before after action valid
  | receiveAppend source destination action =>
    exact receive_append_references source destination before after action valid
  | receiveVoteResponse preVote source destination action =>
    exact vote_response_references preVote source destination before after action valid
  | receiveAppendResponse source destination action =>
    exact append_response_references source destination before after action valid
  | changeConfiguration source configuration action =>
    exact membership_change_references source configuration before after action valid
  | advanceCommit source action =>
    exact advance_commit_references source before after action valid
  | signCommittable source action =>
    exact signature_references source before after action valid
  | becomeLeader source action =>
    exact become_leader_references source before after action valid
  | clientRequest source transaction action =>
    exact client_request_references source (.integer transaction) before after action valid
  | appendEntries source destination batchEnd action =>
    exact send_append_references source destination batchEnd before after action valid
  | observation clauses emitted asserted =>
    exact valid.same_references (assert_all_success clauses before after asserted).1

theorem frame_instruction_holds_before {width : PNat} (item : FrameInstruction width)
    (before after : Encoding width) (run : (frameInstruction item).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment) :
    Holds before.assertions.toList assignment := by
  cases frame_instruction_cases item before after run with
  | quorum node action => exact ((quorum_holds node.val before after action assignment).mp holds).1
  | vote preVote source destination action =>
    exact send_vote_holds_before preVote source destination before after action assignment holds
  | updateTerm source destination action =>
    exact ((term_update_holds source destination before after action assignment).mp holds).1
  | campaign preVote node action =>
    exact campaign_holds_before preVote node before after action assignment holds
  | receiveVote source destination action =>
    exact receive_vote_holds_before source destination before after action assignment holds
  | receiveAppend source destination action =>
    exact receive_append_prior_holds source destination before after action assignment holds
  | receiveVoteResponse preVote source destination action =>
    exact vote_response_prior_holds preVote source destination before after action
      assignment holds
  | receiveAppendResponse source destination action =>
    exact append_response_prior_holds source destination before after action
      assignment holds
  | changeConfiguration source configuration action =>
    exact membership_change_prior_holds source configuration before after action assignment holds
  | advanceCommit source action =>
    exact advance_commit_prior_holds source before after action assignment holds
  | signCommittable source action =>
    exact signature_prior_holds source before after action assignment holds
  | becomeLeader source action =>
    exact become_leader_prior_holds source before after action assignment holds
  | clientRequest source transaction action =>
    exact client_request_prior_holds source (.integer transaction) before after action
      assignment holds
  | appendEntries source destination batchEnd action =>
    exact send_append_holds_before source destination batchEnd before after action assignment holds
  | observation clauses emitted asserted =>
    exact ((assert_all_holds clauses before after asserted assignment).mp holds).1

theorem frame_quorum_success {width : PNat} [Bootstrap (Fin width)]
    (node : Fin width) (before after : Encoding width)
    (run : (checkQuorum node.val).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION) :
    Holds before.assertions.toList assignment /\ NativeArrayCheckQuorum.enabled frame.nodes node /\
      FrameColumnsRep assignment after.toColumns (frame.nodeStep (.checkQuorum node)) := by
  obtain ⟨previous, enabled, nodes⟩ :=
    quorum_native_success node before after run assignment holds frame.nodes rep.nodes sameBootstrap
  have columns := (quorum_success node.val before after run).columns
  have joined := congrArg Columns.hasJoined columns
  have status := congrArg Columns.preVoteStatus columns
  have completed := congrArg Columns.retirementCompleted columns
  have submitted := And.intro (congrArg Columns.submittedTxIds columns) (congrArg Columns.submittedTxLimit columns)
  have queue := And.intro (congrArg Columns.queueLength columns)
    (And.intro (congrArg Columns.queueHead columns) (congrArg Columns.queueCells columns))
  exact ⟨previous, enabled, rep.node_step assignment before.toColumns after.toColumns frame
    (.checkQuorum node) nodes joined status completed submitted queue⟩

theorem frame_quorum_complete {width : PNat} [Bootstrap (Fin width)]
    (node : Fin width) (before after : Encoding width)
    (run : (checkQuorum node.val).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds before.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame) (valid : ReferencesValid before)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION)
    (enabled : NativeArrayCheckQuorum.enabled frame.nodes node) :
    exists extended : Assignment, assignment.AgreesBelow before.next extended /\
      Holds after.assertions.toList extended /\
      FrameColumnsRep extended after.toColumns (frame.nodeStep (.checkQuorum node)) := by
  obtain ⟨extended, agreement, held, nodes⟩ :=
    quorum_complete node before after run assignment holds frame.nodes rep.nodes valid sameBootstrap enabled
  have extendedRep := rep.agrees_below before assignment extended frame valid agreement
  have columns := (quorum_success node.val before after run).columns
  have joined := congrArg Columns.hasJoined columns
  have status := congrArg Columns.preVoteStatus columns
  have completed := congrArg Columns.retirementCompleted columns
  have submitted := And.intro (congrArg Columns.submittedTxIds columns) (congrArg Columns.submittedTxLimit columns)
  have queue := And.intro (congrArg Columns.queueLength columns)
    (And.intro (congrArg Columns.queueHead columns) (congrArg Columns.queueCells columns))
  exact ⟨extended, agreement, held,
    extendedRep.node_step extended before.toColumns after.toColumns frame (.checkQuorum node) nodes
      joined status completed submitted queue⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
