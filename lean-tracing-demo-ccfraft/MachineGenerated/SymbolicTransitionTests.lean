-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionTerm
import MachineGenerated.SymbolicTransitionScans
import MachineGenerated.SymbolicTransitionConfiguration
import MachineGenerated.SymbolicTransitionLogTests
import MachineGenerated.SymbolicTransitionSignatureTests
import MachineGenerated.SymbolicTransitionRetiredWriteTests
import MachineGenerated.SymbolicTransitionClientTests
import MachineGenerated.SymbolicTransitionReconfigurationTests
import MachineGenerated.SymbolicTransitionElectionTests
import MachineGenerated.SymbolicTransitionLeadershipTests
import MachineGenerated.SymbolicTransitionAppendTests
import MachineGenerated.SymbolicTransitionProposalTests
import MachineGenerated.SymbolicTransitionCommitTests
import Shared.SymbolicSmt

set_option autoImplicit false

namespace CCFRaft.SymbolicTransitionTests

open Symbolic SymbolicModel SymbolicTransition

def bounds : BoundedState.Bounds := ⟨3, 8, 8, 6, 1⟩
def assignment : Assignment := fun i => if i = 0 then 3 else 0

local instance : NeZero NODE_COUNT := ⟨by decide⟩
local instance : NeZero bounds.transactionCount := ⟨by decide⟩

def sampleLocal (role : Role) : BoundedState.LocalStateData :=
  { BoundedState.encodeLocal (freshNodeState : NodeState Node Nat) with
    role := role
    currentTerm := 2
    log := [⟨1, .signature⟩]
    commitIndex := 1
    sentIndex := Vector.ofFn (fun n => n.val % 3)
    matchIndex := Vector.ofFn (fun n => n.val % 2)
    isNewFollower := false
    votedFor := some 4
    votesGranted := {1, 4}
    preVotesGranted := {2, 3}
    membershipState := .retirementSigned
    retirementIndex := some 1
    retirementCommittableIndex := some 2
    retiredCommittedIndex := some 3 }

def packetExamples (term : Nat) : List (Message Node Nat) :=
  [ .appendEntriesRequest ⟨term, 0, 0, [⟨1, .signature⟩], 1, 0, 1⟩,
    .appendEntriesResponse ⟨term, true, 1, 0, 1⟩,
    .requestVoteRequest ⟨term, 1, 1, 0, 1⟩,
    .requestVoteResponse ⟨term, true, 0, 1⟩,
    .requestPreVote ⟨term, 1, 1, 0, 1⟩,
    .requestPreVoteResponse ⟨term, true, 0, 1⟩,
    .proposeVoteRequest ⟨term, 0, 1⟩ ]

def fixture (sourceAllocated destinationAllocated : Bool) (role : Role)
    (queue : List (Message Node Nat)) : EntryData bounds.transactionCount :=
  (Vector.ofFn (fun n =>
      if (n = 0 ∧ sourceAllocated) ∨ (n = 1 ∧ destinationAllocated) then some (sampleLocal role)
      else none),
    Vector.ofFn (fun n => if n = 1 then queue else []),
    {0, 2}, {0, 1, 4}, Vector.ofFn (fun n => if n = 4 then .enabled else .capable),
    Vector.ofFn (fun n => if n = 3 then {1, 4} else ∅))

def helperAssertions : List (Expr .bool) :=
  let a := nodeSetCodec.literal {0, 2, 4}
  let b := nodeSetCodec.literal {0, 1, 4}
  let log : Expr logCodec.ty := .ofList
    [ .pair (.unknown 0) (contentCodec.literal (.reconfiguration {0, 1})),
      .pair (.unknown 0) (contentCodec.literal .signature),
      .pair (.unknown 0) (contentCodec.literal (.retiredCommitted {0})),
      .pair (.unknown 0) (contentCodec.literal (.transaction 2)),
      .pair (.unknown 0) (contentCodec.literal (.reconfiguration {1, 2})),
      .pair (.unknown 0) (contentCodec.literal .signature) ]
  [ .eq (setUnion a b) (nodeSetCodec.literal {0, 1, 2, 4}),
    .eq (setIntersection a b) (nodeSetCodec.literal {0, 4}),
    .eq (setDifference a b) (nodeSetCodec.literal {2}),
    .eq (setCard a) (.nat 3),
    .eq (setCard (Codec.finset 0 |>.literal ∅)) (.nat 0),
    majority a b,
    .not (majority (nodeSetCodec.literal {0}) (nodeSetCodec.literal {0, 1})),
    .not (majority (nodeSetCodec.literal ∅) (nodeSetCodec.literal ∅)),
    .eq (configurationsFrom 6 (.nat 1) log)
      (configurationCodec.list.literal [⟨1, {0, 1}⟩, ⟨5, {1, 2}⟩]),
    .eq (signatureAfter 6 (.nat 1) (.nat 1) log) (Codec.nat.option.literal (some 2)),
    .eq (signatureAfter 6 (.nat 2) (.nat 1) log) (Codec.nat.option.literal (some 6)),
    .eq (signatureAfter 6 (.nat 6) (.nat 1) log) (Codec.nat.option.literal none),
    .eq (retiredIndex 6 (nodeCodec.literal 0) (.nat 1) log) (Codec.nat.option.literal (some 3)),
    .eq (retiredIndex 6 (nodeCodec.literal 1) (.nat 1) log) (Codec.nat.option.literal none),
    .eq (configurationsFrom 0 (.nat 1) .nil) .nil,
    .eq (signatureAfter 0 (.nat 0) (.nat 1) .nil) (Codec.nat.option.literal none) ]

def configurationAssertions : List (Expr .bool) :=
  let first : Configuration Node := ⟨1, {1, 2, 7}⟩
  let last : Configuration Node := ⟨3, {2, 8}⟩
  let log := logCodec.literal
    [⟨2, .reconfiguration first.nodes⟩, ⟨2, .signature⟩, ⟨3, .reconfiguration last.nodes⟩]
  let optional := Codec.nat.option
  [ .eq (.unknown 0) (.nat 3),
    .eq (currentConfigurationExpr 3 log (.nat 0)) (configurationCodec.literal implicitConfiguration),
    .eq (currentConfigurationExpr 3 log (.nat 1)) (configurationCodec.literal first),
    .eq (currentConfigurationExpr 3 log (.nat 2)) (configurationCodec.literal first),
    .eq (currentConfigurationExpr 3 log (.unknown 0)) (configurationCodec.literal last),
    .eq (latestConfigurationExpr 3 log) (configurationCodec.literal last),
    .eq (activeConfigurationExpr 3 log (.nat 0))
      (configurationCodec.list.literal [implicitConfiguration, first, last]),
    .eq (activeConfigurationExpr 3 log (.nat 2)) (configurationCodec.list.literal [first, last]),
    .eq (activeConfigurationExpr 3 log (.unknown 0)) (configurationCodec.list.literal [last]),
    .eq (activeNodeUnionExpr 3 log (.nat 2)) (nodeSetCodec.literal {1, 2, 7, 8}),
    .eq (activeNodeUnionExpr 3 log (.unknown 0)) (nodeSetCodec.literal {2, 8}),
    .eq (retirementIndexExpr 3 (nodeCodec.literal 0) log) (optional.literal (some 1)),
    .eq (retirementIndexExpr 3 (nodeCodec.literal 1) log) (optional.literal (some 3)),
    .eq (retirementIndexExpr 3 (nodeCodec.literal 7) log) (optional.literal (some 3)),
    .eq (retirementIndexExpr 3 (nodeCodec.literal 8) log) (optional.literal none),
    .eq (retirementIndexExpr 3 (nodeCodec.literal 14) log) (optional.literal none),
    .eq (retirementFrom (nodeCodec.literal 0) 1 (.bool true)
      (configurationCodec.list.literal [⟨0, ∅⟩])) (optional.literal (some 0)),
    .eq (retirementFrom (nodeCodec.literal 0) 0 (.bool true) .nil) (optional.literal none),
    .eq (currentConfigurationExpr 0 .nil (.nat 0)) (configurationCodec.literal implicitConfiguration),
    .eq (activeNodeUnionExpr 0 .nil (.nat 0)) (nodeSetCodec.literal INITIAL_CONFIGURATION),
    .eq (retirementIndexExpr 0 (nodeCodec.literal 0) .nil) (optional.literal none) ]

def runConfigurations : IO Unit := do
  for (formula, i) in configurationAssertions.zipIdx do
    unless formula.evalMemo assignment do
      throw (IO.userError s!"configuration regression {i} failed")
  IO.println s!"{configurationAssertions.length} configuration and retirement-order regressions passed"

def configurationSolverAssertions : List (Expr .bool) :=
  let configuration : Configuration Node := ⟨1, {7}⟩
  let log := logCodec.literal [⟨2, .reconfiguration configuration.nodes⟩]
  [ .eq (.unknown 0) (.nat 3),
    .eq (currentConfigurationExpr 1 log (.unknown 0)) (configurationCodec.literal configuration),
    .eq (latestConfigurationExpr 1 log) (configurationCodec.literal configuration),
    .eq (activeConfigurationExpr 1 log (.unknown 0)) (configurationCodec.list.literal [configuration]),
    .eq (activeNodeUnionExpr 1 log (.unknown 0)) (nodeSetCodec.literal configuration.nodes),
    .eq (retirementIndexExpr 1 (nodeCodec.literal 0) log) (Codec.nat.option.literal (some 1)) ]

def symbolicSource : Expr nodeCodec.ty :=
  nodeCodec.literal 0

def symbolicDestination : Expr nodeCodec.ty :=
  nodeCodec.literal 1

def symbolicState : Expr (stateCodec bounds.transactionCount).ty :=
  let base := (stateCodec bounds.transactionCount).literal (fixture false true .leader [])
  let packet : Expr messageCodec.ty :=
    .inr (.inr (.inr (.inr (.inr (.inr
      (.pair (.unknown 0) (.pair symbolicSource symbolicDestination)))))))
  let queues := tableStore base.snd.fst (finValue symbolicDestination) (.cons packet .nil)
  .pair base.fst (.pair queues base.snd.snd)

def termAssertions : List (Expr .bool) :=
  let nextState := updateTermNext bounds symbolicState symbolicSource symbolicDestination
  let updated := readLocal bounds.transactionCount nextState symbolicDestination
  [ .eq (.unknown 0) (.nat 3),
    updateTermGuard bounds symbolicState symbolicSource symbolicDestination,
    .eq updated.fst (roleCodec.literal .follower),
    .eq updated.snd.fst (.unknown 0),
    .eq nextState.snd symbolicState.snd ]

def enabledDecision (state : CCFRaft.State Node Nat) (source destination : Node) : Bool :=
  @decide (Enabled state (.updateTerm source destination)) (by unfold Enabled; infer_instance)

def checkTransition (data : EntryData bounds.transactionCount) : Bool :=
  let limits := { bounds with queueCapacity := (data.2.1.get 1).length }
  let e := (stateCodec bounds.transactionCount).literal data
  let s := evalEntryMemo limits assignment e
  let enabled := (updateTermEnabled limits e (nodeCodec.literal 0) (nodeCodec.literal 1)).evalMemo assignment
  let actual := evalEntryMemo limits assignment
    (updateTermNext limits e (nodeCodec.literal 0) (nodeCodec.literal 1))
  enabled == enabledDecision s 0 1 &&
    decide (BoundedState.encode actual = BoundedState.encode (next s (.updateTerm 0 1)))

def solverAssertions (name : String) : Except String (List (Expr .bool)) :=
  match name with
  | "named-sat" =>
      let initial : Expr .nat := .named 0 0 (.unknown 0)
      .ok [.eq initial (.nat 1), .eq (.named 0 1 (.add initial (.nat 1))) (.nat 2)]
  | "named-conflict-error" =>
      .ok [.eq (.named 0 0 (.nat 1)) (.nat 1), .eq (.named 0 0 (.nat 2)) (.nat 2)]
  | "named-absent-group-error" => .ok [.eq (.named 1 0 (.nat 1)) (.nat 1)]
  | "commit-sat" => .ok SymbolicTransitionCommitTests.solverAssertions
  | "commit-terminal-sat" => .ok SymbolicTransitionCommitTests.terminalAssertions
  | "commit-unsat" =>
      .ok [.eq (.unknown 0) (.nat 1), .eq (.unknown 1) (.nat 1),
        .not (SymbolicTransitionCommitTests.solverAssertions.foldr Expr.and (.bool true))]
  | "commit-no-majority-unsat" =>
      .ok [.eq (.unknown 0) (.nat 1), .eq (.unknown 1) (.nat 0),
        advanceAccepted SymbolicTransitionCommitTests.solverBounds SymbolicTransitionCommitTests.symbolicState
          (nodeCodec.literal 0)]
  | "commit-overflow-unsat" =>
      .ok [advanceAccepted SymbolicTransitionCommitTests.overflowBounds SymbolicTransitionCommitTests.overflowState
        (nodeCodec.literal 0)]
  | "proposal-sat" => .ok SymbolicTransitionProposalTests.solverAssertions
  | "proposal-unsat" =>
      .ok [.eq (.unknown 0) (.nat 1), .eq (.unknown 1) (.nat 1),
        .not (SymbolicTransitionProposalTests.solverAssertions.foldr Expr.and (.bool true))]
  | "proposal-rank-unsat" =>
      .ok [.eq (.unknown 0) (.nat 1), .eq (.unknown 1) (.nat 2),
        proposalAccepted SymbolicTransitionLeadershipTests.solverBounds SymbolicTransitionProposalTests.symbolicState
          (nodeCodec.literal 0) (nodeCodec.literal 1)]
  | "append-send-sat" => .ok SymbolicTransitionAppendTests.solverAssertions
  | "append-send-unsat" =>
      .ok [.eq (.unknown 0) (.nat 1),
        .not (SymbolicTransitionAppendTests.solverAssertions.foldr Expr.and (.bool true))]
  | "append-send-overflow-unsat" =>
      .ok [appendSendAccepted SymbolicTransitionAppendTests.overflowBounds SymbolicTransitionAppendTests.overflowState
        (nodeCodec.literal 0) (nodeCodec.literal 1) (.nat 1)]
  | "leadership-sat" => .ok SymbolicTransitionLeadershipTests.solverAssertions
  | "vote-send-sat" => .ok SymbolicTransitionLeadershipTests.sendAssertions
  | "leadership-unsat" | "vote-send-unsat" =>
      let assertions := if name = "leadership-unsat" then SymbolicTransitionLeadershipTests.solverAssertions
        else SymbolicTransitionLeadershipTests.sendAssertions
      .ok [.eq (.unknown 0) (.nat 1), .eq (.unknown 1) (.nat 1),
        .not (assertions.foldr Expr.and (.bool true))]
  | "leadership-no-majority-unsat" =>
      .ok [.eq (.unknown 0) (.nat 1), .eq (.unknown 1) (.nat 0),
        leaderAccepted SymbolicTransitionLeadershipTests.solverBounds SymbolicTransitionLeadershipTests.symbolicState
          (nodeCodec.literal 0)]
  | "election-sat" => .ok SymbolicTransitionElectionTests.solverAssertions
  | "election-unsat" =>
      .ok [.eq (.unknown 0) (.nat 1), .eq (.unknown 1) (.nat 1),
        .not (SymbolicTransitionElectionTests.solverAssertions.foldr Expr.and (.bool true))]
  | "election-no-majority-unsat" | "election-overflow-unsat" =>
      .ok [.eq (.unknown 0) (.nat (if name = "election-overflow-unsat" then 3 else 1)),
        .eq (.unknown 1) (.nat (if name = "election-no-majority-unsat" then 0 else 1)),
        candidateAccepted SymbolicTransitionElectionTests.solverBounds SymbolicTransitionElectionTests.symbolicState
          (nodeCodec.literal 0)]
  | "reconfiguration-sat" => .ok SymbolicTransitionReconfigurationTests.solverAssertions
  | "reconfiguration-unsat" =>
      .ok [.eq (.unknown 0) (.nat 1),
        .not (SymbolicTransitionReconfigurationTests.solverAssertions.foldr Expr.and (.bool true))]
  | "reconfiguration-rejoin-unsat" =>
      .ok [.eq (.unknown 0) (.nat 1),
        configurationAccepted SymbolicTransitionReconfigurationTests.bounds
          (SymbolicTransitionReconfigurationTests.fixture { joined := {0, 1, 2, 3, 4, 7} })
          (nodeCodec.literal 0) SymbolicTransitionReconfigurationTests.symbolicConfiguration]
  | "client-sat" => .ok SymbolicTransitionClientTests.solverAssertions
  | "client-unsat" =>
      .ok [.eq (.unknown 0) (.nat 1), .eq (.unknown 1) (.nat 1), .eq (.unknown 2) (.nat 3),
        .not (SymbolicTransitionClientTests.solverAssertions.foldr Expr.and (.bool true))]
  | "client-outside-unsat" | "client-duplicate-unsat" =>
      .ok [.eq (.unknown 0) (.nat (if name = "client-outside-unsat" then 2 else 0)),
        .eq (.unknown 1) (.nat 1), .eq (.unknown 2) (.nat 3),
        clientAccepted SymbolicTransitionClientTests.bounds SymbolicTransitionClientTests.symbolicState
          (nodeCodec.literal 0) (.unknown 0)]
  | "retired-write-sat" => .ok SymbolicTransitionRetiredWriteTests.solverAssertions
  | "retired-write-unsat" =>
      .ok [.eq (.unknown 0) (.nat 3), .eq (.unknown 1) (.nat 1),
        .not (SymbolicTransitionRetiredWriteTests.solverAssertions.foldr Expr.and (.bool true))]
  | "signature-sat" => .ok SymbolicTransitionSignatureTests.solverAssertions
  | "signature-unsat" =>
      .ok [.eq (.unknown 0) (.nat 3),
        .not (SymbolicTransitionSignatureTests.solverAssertions.foldr Expr.and (.bool true))]
  | "retirement-sat" => .ok SymbolicTransitionLogTests.solverAssertions
  | "retirement-unsat" =>
      .ok [.eq (.unknown 0) (.nat 1), .eq (.unknown 1) (.nat 3),
        .not (SymbolicTransitionLogTests.solverAssertions.foldr Expr.and (.bool true))]
  | "configurations-sat" => .ok configurationSolverAssertions
  | "configurations-unsat" =>
      .ok [.eq (.unknown 0) (.nat 3), .not (configurationSolverAssertions.foldr Expr.and (.bool true))]
  | "helpers-sat" => .ok helperAssertions
  | "helpers-unsat" => .ok [.not (helperAssertions.foldr Expr.and (.bool true))]
  | "term-sat" => .ok termAssertions
  | "term-unsat" =>
      let updated := readLocal bounds.transactionCount
        (updateTermNext bounds symbolicState symbolicSource symbolicDestination) symbolicDestination
      .ok (termAssertions ++ [.not (.eq updated.snd.fst (.unknown 0))])
  | _ => .error s!"unknown symbolic transition case: {name}"

def run : IO Unit := do
  SymbolicTransitionCommitTests.run
  SymbolicTransitionProposalTests.run
  SymbolicTransitionAppendTests.run
  SymbolicTransitionLeadershipTests.run
  SymbolicTransitionElectionTests.run
  SymbolicTransitionReconfigurationTests.run
  SymbolicTransitionClientTests.run
  SymbolicTransitionRetiredWriteTests.run
  SymbolicTransitionSignatureTests.run
  SymbolicTransitionLogTests.run
  runConfigurations
  for (formula, i) in helperAssertions.zipIdx do
    unless formula.evalMemo assignment do throw (IO.userError s!"helper regression {i} failed")
  IO.println s!"{helperAssertions.length} helper regressions passed"
  (← IO.getStdout).flush
  for (formula, i) in termAssertions.zipIdx do
    unless formula.evalMemo assignment do throw (IO.userError s!"symbolic term regression {i} failed")
  IO.println s!"{termAssertions.length} symbolic-field assertions passed"
  (← IO.getStdout).flush
  let mut checked := 0
  let scenarios : List (Bool × Bool × Role × Nat) :=
    [(false, false, .none, 1), (false, true, .leader, 3),
      (true, true, .candidate, 2), (true, false, .follower, 3),
      (true, true, .preVoteCandidate, 1), (true, true, .leader, 3)]
  for (sourceAllocated, destinationAllocated, role, term) in scenarios do
    for packet in packetExamples term do
      let data := fixture sourceAllocated destinationAllocated role [packet]
      unless checkTransition data do
        throw (IO.userError s!"updateTerm case {checked} failed")
      checked := checked + 1
    IO.println s!"{checked} Model transition comparisons passed"
    (← IO.getStdout).flush
  let old := Message.proposeVoteRequest (TxId := Nat) ⟨2, 0, 1⟩
  let newer := Message.proposeVoteRequest (TxId := Nat) ⟨3, 0, 1⟩
  let other := Message.proposeVoteRequest (TxId := Nat) ⟨3, 2, 1⟩
  for queue in [[], [old, newer], [other, newer], [newer, newer]] do
    unless checkTransition (fixture false true .leader queue) do
      throw (IO.userError "first-source packet ordering or duplicate retention failed")
  let zeroBounds : BoundedState.Bounds := ⟨0, 0, 0, 0, 0⟩
  let zero := freshEntry zeroBounds
  unless (stateWithin zeroBounds zero).evalMemo (fun _ => 0) do
    throw (IO.userError "zero-bounds absent entry rejected")
  if (updateTermGuard zeroBounds zero (nodeCodec.literal 0) (nodeCodec.literal 1)).evalMemo (fun _ => 0) then
    throw (IO.userError "absent destination enabled under zero bounds")
  IO.println s!"{helperAssertions.length} helper regressions, {termAssertions.length} symbolic-field assertions, {checked} Model transition comparisons, 4 ordering cases, zero-bound cases passed"

end CCFRaft.SymbolicTransitionTests

def main (args : List String) : IO Unit :=
  match args with
  | [] => CCFRaft.SymbolicTransitionTests.run
  | ["--configurations"] => CCFRaft.SymbolicTransitionTests.runConfigurations
  | ["--retirement"] => CCFRaft.SymbolicTransitionLogTests.run
  | ["--signature"] => CCFRaft.SymbolicTransitionSignatureTests.run
  | ["--signature-tail"] => CCFRaft.SymbolicTransitionSignatureTests.runTail
  | ["--signature-symbolic-actor"] => CCFRaft.SymbolicTransitionSignatureTests.runSymbolicActor
  | ["--retired-write"] => CCFRaft.SymbolicTransitionRetiredWriteTests.run
  | ["--retired-write-tail"] => CCFRaft.SymbolicTransitionRetiredWriteTests.runTail
  | ["--client"] => CCFRaft.SymbolicTransitionClientTests.run
  | ["--client-tail"] => CCFRaft.SymbolicTransitionClientTests.runTail
  | ["--reconfiguration"] => CCFRaft.SymbolicTransitionReconfigurationTests.run
  | ["--reconfiguration-tail"] => CCFRaft.SymbolicTransitionReconfigurationTests.runTail
  | ["--elections"] => CCFRaft.SymbolicTransitionElectionTests.run
  | ["--leadership"] => CCFRaft.SymbolicTransitionLeadershipTests.run
  | ["--append-send"] => CCFRaft.SymbolicTransitionAppendTests.run
  | ["--proposal"] => CCFRaft.SymbolicTransitionProposalTests.run
  | ["--commit"] => CCFRaft.SymbolicTransitionCommitTests.run
  | ["--commit-tail"] => CCFRaft.SymbolicTransitionCommitTests.runTail
  | ["--commit-case", index] =>
      match index.toNat? with
      | some index => CCFRaft.SymbolicTransitionCommitTests.runCase index
      | none => throw (IO.userError "commit case must be a natural number")
  | ["--commit-probe", index] =>
      match index.toNat? with
      | some index => CCFRaft.SymbolicTransitionCommitTests.runCase index true
      | none => throw (IO.userError "commit probe case must be a natural number")
  | ["--commit-named-case", index] =>
      match index.toNat? with
      | some index => CCFRaft.SymbolicTransitionCommitTests.runCase index false true
      | none => throw (IO.userError "named commit case must be a natural number")
  | ["--proposal-tail"] => CCFRaft.SymbolicTransitionProposalTests.runTail
  | ["--proposal-case", index] =>
      match index.toNat? with
      | some index => CCFRaft.SymbolicTransitionProposalTests.runCase index
      | none => throw (IO.userError "proposal case must be a natural number")
  | ["--append-send-tail"] => CCFRaft.SymbolicTransitionAppendTests.runTail
  | ["--append-send-case", index] =>
      match index.toNat? with
      | some index => CCFRaft.SymbolicTransitionAppendTests.runCase index
      | none => throw (IO.userError "append-send case must be a natural number")
  | ["--leadership-tail"] => CCFRaft.SymbolicTransitionLeadershipTests.runTail
  | ["--leadership-case", index] =>
      match index.toNat? with
      | some index => CCFRaft.SymbolicTransitionLeadershipTests.runCase index
      | none => throw (IO.userError "leadership case must be a natural number")
  | ["--election-tail"] => CCFRaft.SymbolicTransitionElectionTests.runTail
  | ["--election-case", index] =>
      match index.toNat? with
      | some index => CCFRaft.SymbolicTransitionElectionTests.runCase index
      | none => throw (IO.userError "election case must be a natural number")
  | ["--reconfiguration-case", index] =>
      match index.toNat? with
      | some index => CCFRaft.SymbolicTransitionReconfigurationTests.runCase index
      | none => throw (IO.userError "reconfiguration case must be a natural number")
  | ["--client-case", index] =>
      match index.toNat? with
      | some index => CCFRaft.SymbolicTransitionClientTests.runCase index
      | none => throw (IO.userError "client case must be a natural number")
  | ["--retired-write-case", index] =>
      match index.toNat? with
      | some index => CCFRaft.SymbolicTransitionRetiredWriteTests.runCase index
      | none => throw (IO.userError "retired-write case must be a natural number")
  | ["--signature-case", index] =>
      match index.toNat? with
      | some index => CCFRaft.SymbolicTransitionSignatureTests.runTransitionCase index
      | none => throw (IO.userError "signature case must be a natural number")
  | ["--smt", name] =>
      match CCFRaft.SymbolicTransitionTests.solverAssertions name with
      | .ok formulas =>
          match Symbolic.script formulas with
          | .ok script => IO.print script
          | .error message => throw (IO.userError message)
      | .error message => throw (IO.userError message)
  | _ => throw (IO.userError "usage: SymbolicTransitionTests.lean [--configurations | --retirement | --signature | --signature-tail | --signature-symbolic-actor | --signature-case INDEX | --retired-write | --retired-write-tail | --retired-write-case INDEX | --client | --client-tail | --client-case INDEX | --reconfiguration | --reconfiguration-tail | --reconfiguration-case INDEX | --elections | --election-tail | --election-case INDEX | --leadership | --leadership-tail | --leadership-case INDEX | --append-send | --append-send-tail | --append-send-case INDEX | --proposal | --proposal-tail | --proposal-case INDEX | --commit | --commit-tail | --commit-case INDEX | --commit-probe INDEX | --commit-named-case INDEX | --smt CASE]")
