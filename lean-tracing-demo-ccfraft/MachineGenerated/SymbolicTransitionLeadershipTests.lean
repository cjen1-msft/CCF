-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionLeader
import MachineGenerated.SymbolicTransitionVoteSend
import MachineGenerated.SymbolicTransitionAppend
import MachineGenerated.SymbolicTransitionProposal
import MachineGenerated.SymbolicTransitionCommit
import MachineGenerated.SymbolicTransitionEvaluation
import BoundedSymbolicTrace

set_option autoImplicit false

namespace CCFRaft.SymbolicTransitionLeadershipTests

open Symbolic SymbolicModel SymbolicTransition

local instance : NeZero NODE_COUNT := ⟨by decide⟩

def bounds : BoundedState.Bounds := ⟨0, 4, 8, 4, 2⟩
def assignment : Assignment := fun _ => 1

structure Case where
  action : BoundedSymbolicTrace.SymbolicAction := .becomeLeader 0
  role : Role := .candidate
  phase : MembershipState := .active
  log : List (Entry Node Nat) := []
  commit : Nat := 0
  votes : Finset Node := {0, 1, 2}
  present : Bool := true
  destinationPresent : Bool := true
  completed : Finset Node := {0, 1}
  queueMode : Nat := 0
  enabled : Bool := true
  accepted : Bool := true

def fixture (scenario : Case) : Expr (stateCodec 0).ty :=
  let value : BoundedState.LocalStateData :=
    { BoundedState.encodeLocal (freshNodeState : NodeState Node Nat) with
      role := scenario.role, currentTerm := 1, log := scenario.log, commitIndex := scenario.commit,
      membershipState := scenario.phase, votesGranted := scenario.votes,
      sentIndex := Vector.ofFn (fun n => n.val % 3), matchIndex := Vector.ofFn (fun n => n.val % 2),
      votedFor := some 14, preVotesGranted := {7, 14}, isNewFollower := false,
      retirementIndex := some 3, retirementCommittableIndex := some 4, retiredCommittedIndex := some 5 }
  let base : EntryData 0 :=
    (Vector.ofFn (fun node =>
        if node = 0 ∧ scenario.present then some value
        else if node = 1 ∧ scenario.destinationPresent then
          some (BoundedState.encodeLocal (freshNodeState : NodeState Node Nat)) else none),
      Vector.ofFn (fun _ => []), ∅, {0, 7},
      Vector.ofFn (fun node => if node = 0 then .enabled else .capable),
      Vector.ofFn (fun node => if node = 7 then {14} else scenario.completed))
  let before := BoundedState.decode base.toData
  let packet : Message Node Nat :=
    match scenario.action with
    | .appendEntries source destination batchEnd =>
        .appendEntriesRequest (makeAppendEntriesRequest before source destination batchEnd)
    | .proposeVote source destination => .proposeVoteRequest (makeProposeVoteRequest before source destination)
    | .advanceCommitIndexAndProposeVote source destination =>
        .proposeVoteRequest (makeProposeVoteRequest before source destination)
    | .requestPreVote source destination => .requestPreVote (makeRequestPreVote before source destination)
    | _ => .requestVoteRequest (makeRequestVoteRequest before 0 1)
  let queue := match scenario.queueMode with
    | 0 => []
    | 1 => [packet, packet]
    | _ => [.proposeVoteRequest ⟨1, 7, 1⟩, .proposeVoteRequest ⟨1, 14, 1⟩]
  (stateCodec 0).literal (base.1, Vector.ofFn (fun node =>
    if node = 1 then queue else if node = 14 then [.proposeVoteRequest ⟨1, 7, 14⟩] else []), base.2.2)

def expressions (limits : BoundedState.Bounds) (state : Expr (stateCodec limits.transactionCount).ty) :
    BoundedSymbolicTrace.SymbolicAction →
      Except String (Expr .bool × Expr .bool × Expr (stateCodec limits.transactionCount).ty)
  | .becomeLeader node =>
      .ok (leaderEnabled limits state (nodeCodec.literal node), leaderAccepted limits state (nodeCodec.literal node),
        leaderNext limits state (nodeCodec.literal node))
  | .requestVote source destination =>
      .ok (voteSendEnabled false limits state (nodeCodec.literal source) (nodeCodec.literal destination),
        voteSendAccepted false limits state (nodeCodec.literal source) (nodeCodec.literal destination),
        voteSendNext false limits state (nodeCodec.literal source) (nodeCodec.literal destination))
  | .requestPreVote source destination =>
      .ok (voteSendEnabled true limits state (nodeCodec.literal source) (nodeCodec.literal destination),
        voteSendAccepted true limits state (nodeCodec.literal source) (nodeCodec.literal destination),
        voteSendNext true limits state (nodeCodec.literal source) (nodeCodec.literal destination))
  | .appendEntries source destination batchEnd =>
      .ok (appendSendEnabled limits state (nodeCodec.literal source) (nodeCodec.literal destination) (.nat batchEnd),
        appendSendAccepted limits state (nodeCodec.literal source) (nodeCodec.literal destination) (.nat batchEnd),
        appendSendNext limits state (nodeCodec.literal source) (nodeCodec.literal destination) (.nat batchEnd))
  | .proposeVote source destination =>
      .ok (proposalEnabled limits state (nodeCodec.literal source) (nodeCodec.literal destination),
        proposalAccepted limits state (nodeCodec.literal source) (nodeCodec.literal destination),
        proposalNext limits state (nodeCodec.literal source) (nodeCodec.literal destination))
  | .advanceCommitIndex node =>
      .ok (advanceEnabled limits state (nodeCodec.literal node), advanceAccepted limits state (nodeCodec.literal node),
        advanceNext limits state (nodeCodec.literal node))
  | .advanceCommitIndexAndProposeVote source destination =>
      .ok (advanceProposalEnabled limits state (nodeCodec.literal source) (nodeCodec.literal destination),
        advanceProposalAccepted limits state (nodeCodec.literal source) (nodeCodec.literal destination),
        advanceProposalNext limits state (nodeCodec.literal source) (nodeCodec.literal destination))
  | _ => .error "not a leadership or send test action"

def check (limits : BoundedState.Bounds) (state : Expr (stateCodec limits.transactionCount).ty)
    (action : BoundedSymbolicTrace.SymbolicAction) (ρ : Assignment) (diagnostic : Bool := false) : IO Unit := do
  let reportPhase (message : String) : IO Unit := do
    if diagnostic then
      IO.println message
      (← IO.getStdout).flush
  reportPhase "shared-cache check: entry evaluation starting"
  let (before, cache) := (evalEntryMemoM limits ρ state).run {}
  unless decide (BoundedState.WithinBounds limits before) do
    throw (IO.userError "leadership fixture violates input bounds")
  let actual := evaluateActionMemo ρ action
  let expected := next before actual
  reportPhase "shared-cache check: expression construction starting"
  let (enabled, accepted, successor) ← match expressions limits state action with
    | .ok values => pure values
    | .error message => throw (IO.userError message)
  reportPhase "shared-cache check: Enabled evaluation starting"
  let (actualEnabled, cache) := (enabled.evalMemoM ρ).run cache
  unless actualEnabled == decide (Enabled before actual) do
    throw (IO.userError "leadership Enabled differs from Model")
  reportPhase "shared-cache check: acceptance evaluation starting"
  let (actualAccepted, cache) := (accepted.evalMemoM ρ).run cache
  unless actualAccepted == (decide (Enabled before actual) && decide (BoundedState.WithinBounds limits expected)) do
    throw (IO.userError "leadership acceptance differs from Model")
  reportPhase "shared-cache check: successor evaluation starting"
  let (after, _) := (evalEntryMemoM limits ρ successor).run cache
  unless decide (BoundedState.encode after = BoundedState.encode expected) do
    throw (IO.userError "leadership successor differs from complete Model state")
  reportPhase "shared-cache check: complete Model comparison passed"

def cases : List Case :=
  let vote : Case := { action := .requestVote 0 1 }
  let pre : Case := { action := .requestPreVote 0 1, role := .preVoteCandidate }
  let joint : Entry Node Nat := ⟨1, .reconfiguration {7, 8}⟩
  [ {}, { log := [⟨1, .signature⟩, joint], votes := {0, 1, 2, 7, 8} },
    { log := [joint], enabled := false, accepted := false },
    { log := [joint], votes := {0, 1, 2, 7, 8} },
    { votes := {0, 1}, enabled := false, accepted := false },
    { role := .leader, enabled := false, accepted := false },
    { phase := .retiredCommitted, enabled := false, accepted := false },
    { log := [⟨1, .reconfiguration {1}⟩, ⟨1, .retiredCommitted {0}⟩, ⟨1, .signature⟩],
      commit := 3, enabled := false, accepted := false },
    { present := false, enabled := false, accepted := false },
    vote, pre,
    { vote with role := .preVoteCandidate, enabled := false, accepted := false },
    { pre with role := .candidate, enabled := false, accepted := false },
    { vote with action := .requestVote 0 0, enabled := false, accepted := false },
    { pre with action := .requestPreVote 0 0, enabled := false, accepted := false },
    { vote with destinationPresent := false, enabled := false, accepted := false },
    { pre with present := false, enabled := false, accepted := false },
    { vote with log := [joint], commit := 1, enabled := false, accepted := false },
    { vote with phase := .retiredCommitted },
    { vote with queueMode := 1 }, { pre with queueMode := 1 },
    { vote with queueMode := 2, accepted := false }, { pre with queueMode := 2, accepted := false },
    { vote with log := [⟨2, .signature⟩, ⟨3, .signature⟩], commit := 1 },
    { pre with log := [⟨2, .signature⟩], commit := 4 } ]

def runCase (index : Nat) : IO Unit := do
  let some scenario := cases[index]? | throw (IO.userError s!"unknown leadership case {index}")
  let limits := { bounds with logCapacity := scenario.log.length }
  let state := fixture scenario
  let before := evalEntryMemo limits assignment state
  let action := evaluateActionMemo assignment scenario.action
  unless decide (Enabled before action) == scenario.enabled do
    throw (IO.userError s!"leadership Enabled expectation {index} failed")
  unless (decide (Enabled before action) && decide (BoundedState.WithinBounds limits (next before action))) == scenario.accepted do
    throw (IO.userError s!"leadership acceptance expectation {index} failed")
  check limits state scenario.action assignment
  IO.println s!"leadership case {index} passed"
  (← IO.getStdout).flush

def symbolicState : Expr (stateCodec 0).ty :=
  let base := fixture {}
  let fields := SymbolicReceive.Local.unpack (readLocal 0 base (nodeCodec.literal 0)).normalizeMemo
  let value := { fields with
    currentTerm := Expr.unknown 0
    votesGranted := tableExpr (fun n : Node =>
      if n = 0 ∨ n = 1 then .bool true else if n = 2 then .lt (.nat 0) (.unknown 1) else .bool false) }
  (writeLocal 0 base (nodeCodec.literal 0) value.pack).normalizeMemo

def solverBounds : BoundedState.Bounds := { bounds with logCapacity := 0 }

def solverAssertions : List (Expr .bool) :=
  let after := leaderNext solverBounds symbolicState (nodeCodec.literal 0)
  let fields := SymbolicReceive.Local.unpack (readLocal 0 after (nodeCodec.literal 0)).normalizeMemo
  [ .eq (.unknown 0) (.nat 1), .eq (.unknown 1) (.nat 1),
    stateWithin solverBounds symbolicState,
    leaderAccepted solverBounds symbolicState (nodeCodec.literal 0),
    .eq fields.role (roleCodec.literal .leader), .eq fields.currentTerm (.unknown 0),
    .eq fields.log .nil,
    .eq fields.sentIndex ((nodeTableCodec Codec.nat).literal (Vector.ofFn fun _ => 0)),
    .eq fields.matchIndex ((nodeTableCodec Codec.nat).literal (Vector.ofFn fun _ => 0)),
    .eq fields.votedFor (nodeCodec.option.literal (some 14)),
    .eq fields.preVotesGranted (nodeSetCodec.literal {7, 14}),
    .eq fields.isNewFollower (.bool false) ]

def sendAssertions : List (Expr .bool) :=
  let after := voteSendNext false solverBounds symbolicState (nodeCodec.literal 0) (nodeCodec.literal 1)
  let expected : Expr messageCodec.ty := .inr (.inr (.inl
    (.pair (.unknown 0) (.pair (.nat 0) (.pair (.nat 0) (.pair (nodeCodec.literal 0) (nodeCodec.literal 1)))))))
  [ .eq (.unknown 0) (.nat 1), .eq (.unknown 1) (.nat 1),
    stateWithin solverBounds symbolicState,
    voteSendAccepted false solverBounds symbolicState (nodeCodec.literal 0) (nodeCodec.literal 1),
    .eq (entryQueue 0 after (nodeCodec.literal 1)) (.cons expected .nil),
    .eq after.fst symbolicState.fst, .eq after.snd.snd symbolicState.snd.snd ]

def runTail : IO Unit := do
  for (term, vote) in [(1, 0), (1, 1), (3, 1)] do
    check solverBounds symbolicState (.becomeLeader 0) (fun n => if n = 0 then term else vote)
    check solverBounds symbolicState (.requestVote 0 1) (fun n => if n = 0 then term else vote)
  for (formula, index) in solverAssertions.zipIdx do
    unless formula.evalMemo assignment do
      throw (IO.userError s!"symbolic leadership assertion {index} failed")
  for (formula, index) in sendAssertions.zipIdx do
    unless formula.evalMemo assignment do
      throw (IO.userError s!"symbolic vote-send assertion {index} failed")
  let zero : BoundedState.Bounds := ⟨0, 0, 0, 0, 0⟩
  for action in [(.becomeLeader 0 : BoundedSymbolicTrace.SymbolicAction), .requestVote 0 1, .requestPreVote 0 1] do
    check zero (freshEntry zero) action (fun _ => 0)
  IO.println s!"6 shared-assignment cases, 3 zero-bound actions, {solverAssertions.length + sendAssertions.length} leadership assertions passed"

def run : IO Unit := do
  for index in List.range cases.length do runCase index
  runTail

end CCFRaft.SymbolicTransitionLeadershipTests
