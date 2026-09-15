-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionLeadershipTests

set_option autoImplicit false

namespace CCFRaft.SymbolicTransitionAppendTests

open Symbolic SymbolicModel SymbolicTransition SymbolicTransitionLeadershipTests

local instance : NeZero NODE_COUNT := ⟨by decide⟩

def cases : List Case :=
  let heartbeat : Case := { action := .appendEntries 0 1 0, role := .leader }
  let send : Case := { heartbeat with
    action := .appendEntries 0 1 2
    log := [⟨1, .signature⟩, ⟨2, .reconfiguration {0, 1, 7}⟩] }
  [ heartbeat, send,
    { heartbeat with action := .appendEntries 0 1 1, enabled := false, accepted := false },
    { send with action := .appendEntries 0 1 1, enabled := false, accepted := false },
    { heartbeat with action := .appendEntries 0 0 0, enabled := false, accepted := false },
    { heartbeat with role := .candidate, enabled := false, accepted := false },
    { heartbeat with present := false, enabled := false, accepted := false },
    { heartbeat with destinationPresent := false, enabled := false, accepted := false },
    { heartbeat with phase := .retiredCommitted, enabled := false, accepted := false },
    { send with phase := .retiredCommitted },
    { heartbeat with
      action := .appendEntries 0 1 1
      log := [⟨1, .reconfiguration {0, 7}⟩], commit := 1 },
    { heartbeat with
      action := .appendEntries 0 1 1
      log := [⟨1, .reconfiguration {0, 7}⟩], commit := 1, completed := ∅,
      enabled := false, accepted := false },
    { heartbeat with queueMode := 1 }, { send with queueMode := 1 },
    { heartbeat with queueMode := 2, accepted := false }, { send with queueMode := 2, accepted := false },
    { heartbeat with action := .appendEntries 0 1 1, log := [⟨1, .signature⟩], commit := 4 } ]

def runCase (index : Nat) : IO Unit := do
  let some scenario := cases[index]? | throw (IO.userError s!"unknown append-send case {index}")
  let limits := { bounds with logCapacity := scenario.log.length }
  let state := fixture scenario
  let before := evalEntryMemo limits assignment state
  let action := evaluateActionMemo assignment scenario.action
  unless decide (Enabled before action) == scenario.enabled do
    throw (IO.userError s!"append-send Enabled expectation {index} failed")
  unless (decide (Enabled before action) && decide (BoundedState.WithinBounds limits (next before action))) == scenario.accepted do
    throw (IO.userError s!"append-send acceptance expectation {index} failed")
  check limits state scenario.action assignment
  IO.println s!"append-send case {index} passed"
  (← IO.getStdout).flush

def symbolicState : Expr (stateCodec 0).ty :=
  let base := fixture { role := .leader }
  let fields := SymbolicReceive.Local.unpack (readLocal 0 base (nodeCodec.literal 0)).normalizeMemo
  (writeLocal 0 base (nodeCodec.literal 0) { fields with currentTerm := .unknown 0 }.pack).normalizeMemo

def solverAssertions : List (Expr .bool) :=
  let after := appendSendNext solverBounds symbolicState (nodeCodec.literal 0) (nodeCodec.literal 1) (.nat 0)
  let fields := SymbolicReceive.Local.unpack (readLocal 0 after (nodeCodec.literal 0)).normalizeMemo
  let packet : Expr messageCodec.ty :=
    .inl (.pair (.unknown 0) (.pair (.nat 1) (.pair (.nat 0)
      (.pair .nil (.pair (.nat 0) (.pair (nodeCodec.literal 0) (nodeCodec.literal 1)))))))
  [ .eq (.unknown 0) (.nat 1), stateWithin solverBounds symbolicState,
    appendSendAccepted solverBounds symbolicState (nodeCodec.literal 0) (nodeCodec.literal 1) (.nat 0),
    .eq (entryQueue 0 after (nodeCodec.literal 1)) (.cons packet .nil),
    .eq (tableSelect fields.sentIndex (nodeCodec.literal 1)) (.nat 0),
    .eq (tableSelect fields.sentIndex (nodeCodec.literal 2)) (.nat 2),
    .eq fields.currentTerm (.unknown 0), .eq fields.role (roleCodec.literal .leader),
    .eq fields.retirementIndex (Codec.nat.option.literal (some 3)),
    .eq after.snd.snd symbolicState.snd.snd ]

def overflowState : Expr (stateCodec 0).ty :=
  let base := fixture { role := .leader, log := [⟨1, .signature⟩] }
  let fields := SymbolicReceive.Local.unpack (readLocal 0 base (nodeCodec.literal 0)).normalizeMemo
  let zeroIndices := (nodeTableCodec Codec.nat).literal (Vector.ofFn fun _ => 0)
  let value := { fields with
    sentIndex := zeroIndices, matchIndex := zeroIndices,
    retirementIndex := .inl .unit, retirementCommittableIndex := .inl .unit,
    retiredCommittedIndex := .inl .unit }
  (writeLocal 0 base (nodeCodec.literal 0) value.pack).normalizeMemo

def overflowBounds : BoundedState.Bounds := { bounds with indexCount := 1, logCapacity := 1 }

def runTail : IO Unit := do
  for term in [1, 3] do
    check solverBounds symbolicState (.appendEntries 0 1 0) (fun _ => term)
  for (formula, index) in solverAssertions.zipIdx do
    unless formula.evalMemo assignment do
      throw (IO.userError s!"symbolic append-send assertion {index} failed")
  let zero : BoundedState.Bounds := ⟨0, 0, 0, 0, 0⟩
  check zero (freshEntry zero) (.appendEntries 0 1 0) (fun _ => 0)
  check overflowBounds overflowState (.appendEntries 0 1 1) assignment
  unless (appendSendEnabled overflowBounds overflowState (nodeCodec.literal 0) (nodeCodec.literal 1) (.nat 1)).evalMemo assignment do
    throw (IO.userError "index-overflow action should be Model enabled")
  if (appendSendAccepted overflowBounds overflowState (nodeCodec.literal 0) (nodeCodec.literal 1) (.nat 1)).evalMemo assignment then
    throw (IO.userError "out-of-bounds sent index was accepted")
  IO.println s!"2 shared-assignment cases, zero bounds, sent-index overflow, {solverAssertions.length} append-send assertions passed"

def run : IO Unit := do
  for index in List.range cases.length do runCase index
  runTail

end CCFRaft.SymbolicTransitionAppendTests
