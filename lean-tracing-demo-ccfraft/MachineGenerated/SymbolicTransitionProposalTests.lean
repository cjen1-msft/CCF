-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionLeadershipTests

set_option autoImplicit false

namespace CCFRaft.SymbolicTransitionProposalTests

open Symbolic SymbolicModel SymbolicTransition SymbolicTransitionLeadershipTests

local instance : NeZero NODE_COUNT := ⟨by decide⟩

def cases : List (Case × List (Node × Nat)) :=
  let base : Case := { action := .proposeVote 0 1, role := .leader }
  [ (base, []), ({ base with phase := .retiredCommitted }, []),
    ({ base with role := .candidate, enabled := false, accepted := false }, []),
    ({ base with action := .proposeVote 0 0, enabled := false, accepted := false }, []),
    ({ base with present := false, enabled := false, accepted := false }, []),
    ({ base with destinationPresent := false, enabled := false, accepted := false }, []),
    ({ base with enabled := false, accepted := false }, [(3, 2)]),
    (base, [(0, 7), (14, 7)]),
    ({ base with log := [⟨1, .reconfiguration {7, 8}⟩], enabled := false, accepted := false }, []),
    ({ base with log := [⟨1, .reconfiguration {7, 8}⟩] }, [(1, 2)]),
    ({ base with log := [⟨1, .reconfiguration {1, 7}⟩] }, []),
    ({ base with log := [⟨1, .reconfiguration {0}⟩], commit := 1, enabled := false, accepted := false }, []),
    ({ base with queueMode := 1 }, []),
    ({ base with queueMode := 2, accepted := false }, []) ]

def fixtureWithMatches (scenario : Case) (overrides : List (Node × Nat)) : Expr (stateCodec 0).ty :=
  let base := fixture scenario
  if overrides.isEmpty then base else
    let value := SymbolicReceive.Local.unpack (readLocal 0 base (nodeCodec.literal 0)).normalizeMemo
    let matched := overrides.foldl (fun indices pair =>
      tableStore indices (Expr.nat pair.1.val) (.nat pair.2)) value.matchIndex
    (writeLocal 0 base (nodeCodec.literal 0) { value with matchIndex := matched }.pack).normalizeMemo

def runCase (index : Nat) : IO Unit := do
  let some (scenario, overrides) := cases[index]? | throw (IO.userError s!"unknown proposal case {index}")
  let limits := { bounds with logCapacity := scenario.log.length }
  let state := fixtureWithMatches scenario overrides
  let before := evalEntryMemo limits assignment state
  let action := evaluateActionMemo assignment scenario.action
  unless decide (Enabled before action) == scenario.enabled do
    throw (IO.userError s!"proposal Enabled expectation {index} failed")
  unless (decide (Enabled before action) && decide (BoundedState.WithinBounds limits (next before action))) == scenario.accepted do
    throw (IO.userError s!"proposal acceptance expectation {index} failed")
  check limits state scenario.action assignment
  IO.println s!"proposal case {index} passed"
  (← IO.getStdout).flush

def symbolicState : Expr (stateCodec 0).ty :=
  let base := fixture { role := .leader, action := .proposeVote 0 1 }
  let value := SymbolicReceive.Local.unpack (readLocal 0 base (nodeCodec.literal 0)).normalizeMemo
  let matched := tableStore value.matchIndex (.nat 3) (.unknown 1)
  (writeLocal 0 base (nodeCodec.literal 0)
    { value with currentTerm := .unknown 0, matchIndex := matched }.pack).normalizeMemo

def solverAssertions : List (Expr .bool) :=
  let after := proposalNext solverBounds symbolicState (nodeCodec.literal 0) (nodeCodec.literal 1)
  let packet : Expr messageCodec.ty := .inr (.inr (.inr (.inr (.inr (.inr
    (.pair (.unknown 0) (.pair (nodeCodec.literal 0) (nodeCodec.literal 1))))))))
  [ .eq (.unknown 0) (.nat 1), .eq (.unknown 1) (.nat 1), stateWithin solverBounds symbolicState,
    proposalAccepted solverBounds symbolicState (nodeCodec.literal 0) (nodeCodec.literal 1),
    .eq (entryQueue 0 after (nodeCodec.literal 1)) (.cons packet .nil),
    .eq after.fst symbolicState.fst, .eq after.snd.snd symbolicState.snd.snd ]

def runTail : IO Unit := do
  for (term, matched) in [(1, 0), (1, 1), (3, 2)] do
    check solverBounds symbolicState (.proposeVote 0 1) (fun n => if n = 0 then term else matched)
  for (formula, index) in solverAssertions.zipIdx do
    unless formula.evalMemo assignment do
      throw (IO.userError s!"symbolic proposal assertion {index} failed")
  let zero : BoundedState.Bounds := ⟨0, 0, 0, 0, 0⟩
  check zero (freshEntry zero) (.proposeVote 0 1) (fun _ => 0)
  IO.println s!"3 shared-assignment cases, zero bounds, {solverAssertions.length} proposal assertions passed"

def run : IO Unit := do
  for index in List.range cases.length do runCase index
  runTail

end CCFRaft.SymbolicTransitionProposalTests
