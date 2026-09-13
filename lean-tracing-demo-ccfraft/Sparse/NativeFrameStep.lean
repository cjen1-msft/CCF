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
import Sparse.NativeMembershipChangeEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem frame_observation_run {width : PNat} (item : FrameInstruction width)
    (before : Encoding width) (clauses : List (Expr .bool))
    (emitted : frameObservationClauses before.toColumns item = .ok clauses) :
    (frameInstruction item).run before = (assertAll clauses).run before := by
  cases item <;> simp only [frameObservationClauses] at emitted
  case node item => exact observation_instruction_run item before clauses emitted
  case hasJoined expected =>
    cases Except.ok.inj emitted
    rfl
  case preVoteStatus node expected =>
    cases Except.ok.inj emitted
    rfl
  case retirementCompleted node expected =>
    cases Except.ok.inj emitted
    rfl
  case submittedTxId txId expected =>
    cases Except.ok.inj emitted
    rfl
  case queueLength source destination expected =>
    cases Except.ok.inj emitted
    rfl
  case queuePoint source destination index expected =>
    cases Except.ok.inj emitted
    rfl
  all_goals cases emitted

theorem frame_observation_correct {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (columns : Columns) (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment columns frame)
    (item : FrameInstruction width) (clauses : List (Expr .bool))
    (emitted : frameObservationClauses columns item = .ok clauses) :
    Holds clauses assignment <-> NativeArrayVote.follows frame [item] := by
  cases item <;> simp only [frameObservationClauses] at emitted
  case node item =>
    simpa only [NativeArrayVote.follows, and_true] using
      observation_correct assignment columns frame.nodes rep.nodes item clauses emitted
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
  all_goals cases emitted

theorem frame_observation_cons {width : PNat} [Bootstrap (Fin width)]
    (frame : NativeArrayVote.Frame (Fin width) Nat) (columns : Columns)
    (item : FrameInstruction width) (rest : List (FrameInstruction width))
    (clauses : List (Expr .bool)) (emitted : frameObservationClauses columns item = .ok clauses) :
    NativeArrayVote.follows frame (item :: rest) <->
      NativeArrayVote.follows frame [item] /\ NativeArrayVote.follows frame rest := by
  cases item <;> simp only [frameObservationClauses] at emitted
  case node item =>
    simp only [NativeArrayVote.follows, observation_node_step frame columns item clauses emitted, and_true]
  case hasJoined => simp [NativeArrayVote.follows]
  case preVoteStatus => simp [NativeArrayVote.follows]
  case retirementCompleted => simp [NativeArrayVote.follows]
  case submittedTxId => simp [NativeArrayVote.follows]
  case queueLength => simp [NativeArrayVote.follows]
  case queuePoint => simp [NativeArrayVote.follows]
  all_goals cases emitted

theorem frame_instruction_cases {width : PNat} (item : FrameInstruction width)
    (before after : Encoding width) (run : (frameInstruction item).run before = .ok ((), after)) :
    (exists node, item = .node (.checkQuorum node) /\ (checkQuorum node.val).run before = .ok ((), after)) \/
      (exists preVote source destination, item = .vote preVote source destination /\
        (sendVote preVote source destination).run before = .ok ((), after)) \/
      (exists source destination, item = .updateTerm source destination /\
        (updateTerm source destination).run before = .ok ((), after)) \/
      (exists preVote node, item = .campaign preVote node /\
        (campaign preVote node).run before = .ok ((), after)) \/
      (exists source destination, item = .receiveVote source destination /\
        (receiveVote source destination).run before = .ok ((), after)) \/
      (exists source destination, item = .receiveAppend source destination /\
        (receiveAppend source destination).run before = .ok ((), after)) \/
      (exists source configuration, item = .changeConfiguration source configuration /\
        (membershipChange source configuration).run before = .ok ((), after)) \/
      (exists source destination batchEnd, item = .appendEntries source destination batchEnd /\
        (sendAppend source destination batchEnd).run before = .ok ((), after)) \/
      (exists clauses, frameObservationClauses before.toColumns item = .ok clauses /\
        (assertAll clauses).run before = .ok ((), after)) := by
  cases item
  case node item =>
    rcases instruction_cases item before after run with ⟨node, rfl, action⟩ | ⟨clauses, emitted, asserted⟩
    · exact Or.inl ⟨node, rfl, action⟩
    · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr
        (Or.inr (Or.inr ⟨clauses, emitted, asserted⟩)))))))
  case vote preVote source destination => exact Or.inr (Or.inl ⟨preVote, source, destination, rfl, run⟩)
  case updateTerm source destination => exact Or.inr (Or.inr (Or.inl ⟨source, destination, rfl, run⟩))
  case campaign preVote node => exact Or.inr (Or.inr (Or.inr (Or.inl ⟨preVote, node, rfl, run⟩)))
  case receiveVote source destination =>
    refine Or.inr (Or.inr (Or.inr (Or.inr (Or.inl ⟨source, destination, rfl, ?_⟩))))
    simpa only [frameInstruction] using run
  case receiveAppend source destination =>
    refine Or.inr (Or.inr (Or.inr (Or.inr
      (Or.inr (Or.inl ⟨source, destination, rfl, ?_⟩)))))
    simpa only [frameInstruction] using run
  case changeConfiguration source configuration =>
    refine Or.inr (Or.inr (Or.inr (Or.inr (Or.inr
      (Or.inr (Or.inl ⟨source, configuration, rfl, ?_⟩))))))
    simpa only [frameInstruction] using run
  case appendEntries source destination batchEnd =>
    exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inr
      (Or.inr (Or.inr (Or.inl ⟨source, destination, batchEnd, rfl, run⟩)))))))
  case hasJoined expected => exact Or.inr (Or.inr (Or.inr (Or.inr
    (Or.inr (Or.inr (Or.inr (Or.inr ⟨_, rfl, run⟩)))))))
  case preVoteStatus node expected =>
    exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr
      (Or.inr (Or.inr ⟨_, rfl, run⟩)))))))
  case retirementCompleted node expected =>
    exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr
      (Or.inr (Or.inr ⟨_, rfl, run⟩)))))))
  case submittedTxId txId expected =>
    exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr
      (Or.inr (Or.inr ⟨_, rfl, run⟩)))))))
  case queueLength source destination expected =>
    exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr
      (Or.inr (Or.inr ⟨_, rfl, run⟩)))))))
  case queuePoint source destination index expected =>
    refine Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr
      (Or.inr (Or.inr ⟨_, rfl, ?_⟩)))))))
    exact (frame_observation_run (.queuePoint source destination index expected) before _ rfl).symm.trans run
theorem frame_instruction_references {width : PNat} (item : FrameInstruction width)
    (before after : Encoding width) (run : (frameInstruction item).run before = .ok ((), after))
    (valid : ReferencesValid before) : ReferencesValid after := by
  rcases frame_instruction_cases item before after run with ⟨node, _, action⟩ |
    ⟨preVote, source, destination, _, action⟩ | ⟨source, destination, _, action⟩ |
    ⟨preVote, node, _, action⟩ | ⟨source, destination, _, action⟩ |
    ⟨source, destination, _, action⟩ |
    ⟨source, configuration, _, action⟩ |
    ⟨source, destination, batchEnd, _, action⟩ |
    ⟨clauses, _, asserted⟩
  · exact instruction_references (.checkQuorum node) before after action valid
  · exact send_vote_references preVote source destination before after action valid
  · exact term_update_references source destination before after action valid
  · exact campaign_references preVote node before after action valid
  · exact receive_vote_references source destination before after action valid
  · exact receive_append_references source destination before after action valid
  · exact membership_change_references source configuration before after action valid
  · exact send_append_references source destination batchEnd before after action valid
  · exact valid.same_references (assert_all_success clauses before after asserted).1

theorem frame_instruction_holds_before {width : PNat} (item : FrameInstruction width)
    (before after : Encoding width) (run : (frameInstruction item).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment) :
    Holds before.assertions.toList assignment := by
  rcases frame_instruction_cases item before after run with ⟨node, _, action⟩ |
    ⟨preVote, source, destination, _, action⟩ | ⟨source, destination, _, action⟩ |
    ⟨preVote, node, _, action⟩ | ⟨source, destination, _, action⟩ |
    ⟨source, destination, _, action⟩ |
    ⟨source, configuration, _, action⟩ |
    ⟨source, destination, batchEnd, _, action⟩ |
    ⟨clauses, _, asserted⟩
  · exact ((quorum_holds node.val before after action assignment).mp holds).1
  · exact send_vote_holds_before preVote source destination before after action assignment holds
  · exact ((term_update_holds source destination before after action assignment).mp holds).1
  · exact campaign_holds_before preVote node before after action assignment holds
  · exact receive_vote_holds_before source destination before after action assignment holds
  · exact receive_append_prior_holds source destination before after action assignment holds
  · exact membership_change_prior_holds source configuration before after action assignment holds
  · exact send_append_holds_before source destination batchEnd before after action assignment holds
  · exact ((assert_all_holds clauses before after asserted assignment).mp holds).1

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
