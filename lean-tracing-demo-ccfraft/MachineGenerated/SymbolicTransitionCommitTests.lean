-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionProposalTests

set_option autoImplicit false

namespace CCFRaft.SymbolicTransitionCommitTests

open Symbolic SymbolicModel SymbolicTransition SymbolicTransitionLeadershipTests

local instance : NeZero NODE_COUNT := ⟨by decide⟩

def terminalCase : Case :=
  { action := .advanceCommitIndexAndProposeVote 0 1, role := .leader,
    log := [⟨1, .reconfiguration {1}⟩, ⟨1, .retiredCommitted {0}⟩, ⟨1, .signature⟩] }

def terminalMatches : List (Node × Nat) := [(1, 3), (3, 3)]

def cases : List (Case × List (Node × Nat) × Nat) :=
  let base : Case := { action := .advanceCommitIndex 0, role := .leader, log := [⟨1, .signature⟩] }
  let joint : Case := { base with log := [⟨1, .reconfiguration {7, 8}⟩, ⟨1, .signature⟩] }
  [ (base, [], 1),
    ({ base with log := [], enabled := false, accepted := false }, [], 0),
    ({ base with log := [⟨2, .signature⟩], enabled := false, accepted := false }, [], 0),
    ({ base with log := [⟨1, .reconfiguration {0, 1}⟩], enabled := false, accepted := false }, [], 0),
    ({ base with role := .candidate, enabled := false, accepted := false }, [], 1),
    ({ base with present := false, enabled := false, accepted := false }, [], 0),
    ({ base with commit := 1, enabled := false, accepted := false }, [], 0),
    ({ base with phase := .retiredCommitted }, [], 1),
    ({ base with enabled := false, accepted := false }, [(3, 0)], 0),
    ({ base with log := [⟨1, .signature⟩, ⟨1, .signature⟩] }, [], 1),
    ({ base with log := [⟨1, .signature⟩, ⟨1, .signature⟩], commit := 1 }, [(1, 2), (3, 2)], 2),
    ({ base with log := [⟨1, .signature⟩, ⟨1, .reconfiguration {7, 8}⟩] }, [], 1),
    ({ joint with enabled := false, accepted := false }, [(1, 2), (3, 2)], 0),
    (joint, [(1, 2), (3, 2), (7, 2), (8, 2)], 2),
    (terminalCase, terminalMatches, 3),
    ({ terminalCase with action := .advanceCommitIndex 0, enabled := false, accepted := false }, terminalMatches, 3),
    ({ terminalCase with destinationPresent := false, enabled := false, accepted := false }, terminalMatches, 3),
    ({ terminalCase with action := .advanceCommitIndexAndProposeVote 0 0, enabled := false, accepted := false }, terminalMatches, 3),
    ({ terminalCase with role := .follower, enabled := false, accepted := false }, terminalMatches, 3),
    ({ terminalCase with enabled := false, accepted := false }, [(1, 2), (3, 3)], 0),
    ({ terminalCase with queueMode := 1 }, terminalMatches, 3),
    ({ terminalCase with queueMode := 2, accepted := false }, terminalMatches, 3),
    ({ base with action := .advanceCommitIndexAndProposeVote 0 1, enabled := false, accepted := false }, [], 1) ]

def runCase (index : Nat) (probe : Bool := false) (named : Bool := false) : IO Unit := do
  let some (scenario, overrides, frontier) := cases[index]? | throw (IO.userError s!"unknown commit case {index}")
  let limits := { bounds with logCapacity := scenario.log.length }
  let input := SymbolicTransitionProposalTests.fixtureWithMatches scenario overrides
  let state := if named then Expr.named 0 0 input else input
  let before := evalEntryMemo limits assignment state
  let action := evaluateActionMemo assignment scenario.action
  unless highestCommittableIndex before 0 == frontier do
    throw (IO.userError s!"commit frontier expectation {index} failed")
  if probe then
    IO.println s!"commit case {index} native frontier computed"
    (← IO.getStdout).flush
  let frontierExpr := highestCommitExpr limits state (nodeCodec.literal 0)
  unless frontierExpr.evalMemo assignment == frontier do
    throw (IO.userError s!"symbolic commit frontier {index} failed")
  if probe then
    IO.println s!"commit case {index} symbolic frontier computed"
    (← IO.getStdout).flush
    let compactFrontier := SymbolicReceive.compact frontierExpr
    IO.println s!"compacted frontier {compactFrontier.evalMemo assignment}"
    (← IO.getStdout).flush
    let input := SymbolicReceive.compact (setCommitExpr (readLocal 0 state (nodeCodec.literal 0)) compactFrontier)
    IO.println s!"compacted input {(decodeMemo localCodec assignment input).commitIndex}"
    (← IO.getStdout).flush
    let retirement := SymbolicReceive.compact (retirementIndexExpr limits.logCapacity (nodeCodec.literal 0) input.snd.snd.fst.normalizeMemo)
    IO.println s!"retirement {(decodeMemo Codec.nat.option assignment retirement)}"
    (← IO.getStdout).flush
    let value := advancedLocal limits state (nodeCodec.literal 0)
    IO.println s!"refreshed commit index {(decodeMemo localCodec assignment value).commitIndex}"
    (← IO.getStdout).flush
    let log := SymbolicReceive.compact value.snd.snd.fst
    let commit := SymbolicReceive.compact value.snd.snd.snd.fst
    let current := SymbolicReceive.compact (currentConfigurationExpr limits.logCapacity log commit)
    IO.println s!"current configuration {(decodeMemo configurationCodec assignment current).index}"
    (← IO.getStdout).flush
    let previous := SymbolicReceive.compact (previouslyConfiguredExpr limits.logCapacity log current.fst)
    IO.println s!"previously configured {(decodeMemo nodeSetCodec assignment previous).card}"
    (← IO.getStdout).flush
    let retired := SymbolicReceive.compact (committedRetiredNodesExpr limits.logCapacity commit (.nat 1) log)
    IO.println s!"retired nodes {(decodeMemo nodeSetCodec assignment retired).card}"
    (← IO.getStdout).flush
    let completed := retirementCompletedNodesExpr limits.logCapacity log commit
    IO.println s!"completed nodes {(decodeMemo nodeSetCodec assignment completed).card}"
    (← IO.getStdout).flush
    let written := SymbolicReceive.compact (writeLocal 0 state (nodeCodec.literal 0) value)
    IO.println s!"written commit index {((evalEntryMemo limits assignment written).nodes 0).commitIndex}"
    (← IO.getStdout).flush
    let refreshed := refreshCompletedExpr limits limits.logCapacity written (nodeCodec.literal 0) value
    IO.println s!"refreshed completion {((evalEntryMemo limits assignment refreshed).retirementCompleted 0).card}"
    (← IO.getStdout).flush
    let advanced := SymbolicReceive.compact refreshed
    IO.println s!"advanced commit index {((evalEntryMemo limits assignment advanced).nodes 0).commitIndex}"
    (← IO.getStdout).flush
    let demoted := demoteExpr limits advanced (nodeCodec.literal 0)
    IO.println s!"demoted commit index {((evalEntryMemo limits assignment demoted).nodes 0).commitIndex}"
    (← IO.getStdout).flush
    IO.println "constructing and comparing complete transition"
    (← IO.getStdout).flush
  unless decide (Enabled before action) == scenario.enabled do
    throw (IO.userError s!"commit Enabled expectation {index} failed")
  unless (decide (Enabled before action) && decide (BoundedState.WithinBounds limits (next before action))) == scenario.accepted do
    throw (IO.userError s!"commit acceptance expectation {index} failed")
  check limits state scenario.action assignment
  IO.println s!"{if named then "named " else ""}commit case {index} passed"
  (← IO.getStdout).flush

def symbolicState : Expr (stateCodec 0).ty :=
  let base := fixture { role := .leader, log := [⟨1, .signature⟩], action := .advanceCommitIndex 0 }
  let value := SymbolicReceive.Local.unpack (readLocal 0 base (nodeCodec.literal 0)).normalizeMemo
  (writeLocal 0 base (nodeCodec.literal 0)
    { value with
      currentTerm := .unknown 0
      matchIndex := tableStore value.matchIndex (.nat 3) (.unknown 1) }.pack).normalizeMemo

def solverBounds : BoundedState.Bounds := { bounds with logCapacity := 1 }

-- Keep scenario construction behind selector dispatch, not module initialization.
@[noinline, never_extract]
def solverAssertions (state : Expr (stateCodec 0).ty := symbolicState) : List (Expr .bool) :=
  let after := advanceNext solverBounds state (nodeCodec.literal 0)
  let value := SymbolicReceive.Local.unpack (readLocal 0 after (nodeCodec.literal 0)).normalizeMemo
  [ .eq (.unknown 0) (.nat 1), .eq (.unknown 1) (.nat 1), stateWithin solverBounds state,
    advanceAccepted solverBounds state (nodeCodec.literal 0),
    .eq (highestCommitExpr solverBounds state (nodeCodec.literal 0)) (.nat 1),
    .eq value.commitIndex (.nat 1), .eq value.currentTerm (.unknown 0),
    .eq value.role (roleCodec.literal .leader), .eq value.isNewFollower (.bool false),
    .eq value.votedFor (nodeCodec.option.literal (some 14)),
    .eq after.snd.fst state.snd.fst ]

def terminalState : Expr (stateCodec 0).ty :=
  SymbolicTransitionProposalTests.fixtureWithMatches terminalCase terminalMatches

def terminalBounds : BoundedState.Bounds := { bounds with logCapacity := 3 }

@[noinline, never_extract]
def terminalAssertions (state : Expr (stateCodec 0).ty := terminalState) : List (Expr .bool) :=
  let after := advanceProposalNext terminalBounds state (nodeCodec.literal 0) (nodeCodec.literal 1)
  let value := SymbolicReceive.Local.unpack (readLocal 0 after (nodeCodec.literal 0)).normalizeMemo
  [ stateWithin terminalBounds state,
    advanceProposalAccepted terminalBounds state (nodeCodec.literal 0) (nodeCodec.literal 1),
    .eq value.role (roleCodec.literal .follower), .eq value.isNewFollower (.bool true),
    .eq value.membershipState (membershipCodec.literal .retiredCommitted),
    .eq value.commitIndex (.nat 3), .eq value.currentTerm (.nat 1),
    .eq value.votedFor (nodeCodec.option.literal (some 14)),
    .eq (entryQueue 0 after (nodeCodec.literal 1)) (queueCodec.literal [.proposeVoteRequest ⟨1, 0, 1⟩]) ]

def overflowBounds : BoundedState.Bounds := { bounds with logCapacity := 2, indexCount := 2 }

def overflowState : Expr (stateCodec 0).ty :=
  let base := fixture {
    role := .leader, commit := 1,
    log := [⟨1, .reconfiguration {0}⟩, ⟨1, .signature⟩] }
  let value := SymbolicReceive.Local.unpack (readLocal 0 base (nodeCodec.literal 0)).normalizeMemo
  let indices := (nodeTableCodec Codec.nat).literal (Vector.ofFn fun _ => 0)
  (writeLocal 0 base (nodeCodec.literal 0)
    { value with
      sentIndex := indices, matchIndex := indices,
      retirementIndex := .inl .unit, retirementCommittableIndex := .inl .unit,
      retiredCommittedIndex := .inl .unit }.pack).normalizeMemo

def runTail : IO Unit := do
  let solver := solverAssertions
  let terminal := terminalAssertions
  for (term, matched) in [(1, 0), (1, 1), (2, 1)] do
    check solverBounds symbolicState (.advanceCommitIndex 0) (fun n => if n = 0 then term else matched)
  for (formula, index) in solver.zipIdx do
    unless formula.evalMemo assignment do throw (IO.userError s!"symbolic commit assertion {index} failed")
  for (formula, index) in terminal.zipIdx do
    unless formula.evalMemo assignment do throw (IO.userError s!"terminal commit assertion {index} failed")
  check overflowBounds overflowState (.advanceCommitIndex 0) assignment
  unless (advanceEnabled overflowBounds overflowState (nodeCodec.literal 0)).evalMemo assignment do
    throw (IO.userError "commit overflow should be Model enabled")
  if (advanceAccepted overflowBounds overflowState (nodeCodec.literal 0)).evalMemo assignment then
    throw (IO.userError "commit-index overflow accepted")
  let zero : BoundedState.Bounds := ⟨0, 0, 0, 0, 0⟩
  for action in [(.advanceCommitIndex 0 : BoundedSymbolicTrace.SymbolicAction), .advanceCommitIndexAndProposeVote 0 1] do
    check zero (freshEntry zero) action (fun _ => 0)
  IO.println s!"3 shared-assignment cases, zero-bound actions, commit overflow, {solver.length + terminal.length} commit assertions passed"

def run : IO Unit := do
  for index in List.range cases.length do runCase index
  runTail

end CCFRaft.SymbolicTransitionCommitTests
