-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeFrameColumns

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
  all_goals cases emitted

theorem frame_observation_correct {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (columns : Columns) (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment columns frame)
    (domains : forall node : Fin width, NodeDomain width assignment node.val)
    (item : FrameInstruction width) (clauses : List (Expr .bool))
    (emitted : frameObservationClauses columns item = .ok clauses) :
    Holds clauses assignment <-> NativeArrayVote.follows frame [item] := by
  cases item <;> simp only [frameObservationClauses] at emitted
  case node item =>
    simpa only [NativeArrayVote.follows, and_true] using
      observation_correct assignment columns frame.nodes rep.nodes domains item clauses emitted
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
    cases expected <;> simp [Holds, natSetMember, Term.eval, NativeArrayVote.follows]
    · exact not_congr (rep.submittedTxIds txId)
    · exact rep.submittedTxIds txId
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
  all_goals cases emitted

theorem frame_instruction_cases {width : PNat} (item : FrameInstruction width)
    (before after : Encoding width) (run : (frameInstruction item).run before = .ok ((), after)) :
    (exists node, item = .node (.checkQuorum node) /\ (checkQuorum node.val).run before = .ok ((), after)) \/
      (exists clauses, frameObservationClauses before.toColumns item = .ok clauses /\
        (assertAll clauses).run before = .ok ((), after)) := by
  cases item
  case node item =>
    rcases instruction_cases item before after run with ⟨node, rfl, action⟩ | ⟨clauses, emitted, asserted⟩
    · exact Or.inl ⟨node, rfl, action⟩
    · exact Or.inr ⟨clauses, emitted, asserted⟩
  case hasJoined expected => exact Or.inr ⟨_, rfl, run⟩
  case preVoteStatus node expected => exact Or.inr ⟨_, rfl, run⟩
  case retirementCompleted node expected => exact Or.inr ⟨_, rfl, run⟩
  case submittedTxId txId expected => exact Or.inr ⟨_, rfl, run⟩
  all_goals cases run

theorem frame_instruction_references {width : PNat} (item : FrameInstruction width)
    (before after : Encoding width) (run : (frameInstruction item).run before = .ok ((), after))
    (valid : ReferencesValid before) : ReferencesValid after := by
  rcases frame_instruction_cases item before after run with ⟨node, _, action⟩ | ⟨clauses, _, asserted⟩
  · exact instruction_references (.checkQuorum node) before after action valid
  · exact valid.same_references (assert_all_success clauses before after asserted).1

theorem frame_instruction_holds_before {width : PNat} (item : FrameInstruction width)
    (before after : Encoding width) (run : (frameInstruction item).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment) :
    Holds before.assertions.toList assignment := by
  rcases frame_instruction_cases item before after run with ⟨node, _, action⟩ | ⟨clauses, _, asserted⟩
  · exact ((quorum_holds node.val before after action assignment).mp holds).1
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
  have joined := congrArg Columns.hasJoined (quorum_success node.val before after run).columns
  have status := congrArg Columns.preVoteStatus (quorum_success node.val before after run).columns
  have completed := congrArg Columns.retirementCompleted (quorum_success node.val before after run).columns
  have submitted := congrArg Columns.submittedTxIds (quorum_success node.val before after run).columns
  exact ⟨previous, enabled, rep.node_step assignment before.toColumns after.toColumns frame
    (.checkQuorum node) nodes joined status completed submitted⟩

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
  have joined := congrArg Columns.hasJoined (quorum_success node.val before after run).columns
  have status := congrArg Columns.preVoteStatus (quorum_success node.val before after run).columns
  have completed := congrArg Columns.retirementCompleted (quorum_success node.val before after run).columns
  have submitted := congrArg Columns.submittedTxIds (quorum_success node.val before after run).columns
  exact ⟨extended, agreement, held,
    extendedRep.node_step extended before.toColumns after.toColumns frame (.checkQuorum node) nodes
      joined status completed submitted⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
