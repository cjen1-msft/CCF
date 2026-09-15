-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionRetiredWrite
import MachineGenerated.SymbolicTransitionEvaluation
import MachineGenerated.SymbolicTransitionTransactionDomain

set_option autoImplicit false

namespace CCFRaft.SymbolicTransitionRetiredWriteTests

open Symbolic SymbolicModel SymbolicTransition

local instance : NeZero NODE_COUNT := ⟨by decide⟩

def bounds : BoundedState.Bounds := ⟨0, 8, 8, 2, 0⟩
def assignment : Assignment := fun i => if i = 0 then 3 else 1

def fixture (present : Bool) (role : Role) (phase : MembershipState)
    (entries : List (Entry Node Nat)) (commit : Nat) (pending : Finset Node) : EntryData 0 :=
  let value : BoundedState.LocalStateData :=
    { BoundedState.encodeLocal (freshNodeState : NodeState Node Nat) with
      role := role, currentTerm := 3, log := entries, commitIndex := commit,
      membershipState := phase }
  (Vector.ofFn (fun node => if node = 0 ∧ present then some value else none),
    Vector.ofFn (fun _ => []), ∅, {0, 7}, Vector.ofFn (fun _ => .enabled),
    Vector.ofFn (fun node => if node = 0 then pending else {14}))

def enabledDecision (state : CCFRaft.State Node Nat) : Bool :=
  @decide (Enabled state (.appendRetiredCommitted 0)) (by unfold Enabled; infer_instance)

def cases : List (Bool × Role × MembershipState × List (Entry Node Nat) × Nat × Finset Node × Bool) :=
  let retired : Entry Node Nat := ⟨2, .retiredCommitted {7}⟩
  let configuration : Entry Node Nat := ⟨2, .reconfiguration {7}⟩
  [ (false, .leader, .active, [], 0, {7}, false),
    (true, .follower, .active, [], 0, {7}, false),
    (true, .leader, .retiredCommitted, [], 0, {7}, false),
    (true, .leader, .active, [], 0, ∅, false),
    (true, .leader, .active, [], 0, {7}, true),
    (true, .leader, .active, [retired], 0, {7}, false),
    (true, .leader, .active, [retired], 0, {7, 14}, true),
    (true, .leader, .active, [configuration], 1, {0, 1}, true),
    (true, .leader, .active, [configuration], 2, {0, 1}, false),
    (true, .leader, .active, [configuration, ⟨3, .signature⟩], 2, {1}, true) ]

def runCase (index : Nat) : IO Unit := do
  let some (present, role, phase, entries, commit, pending, enabled) := cases[index]? |
    throw (IO.userError s!"unknown retired-write case {index}")
  let limits := { bounds with logCapacity := min bounds.logCapacity (entries.length + 1) }
  let state := (stateCodec 0).literal (fixture present role phase entries commit pending)
  let before := evalEntryMemo limits assignment state
  unless decide (BoundedState.WithinBounds limits before) do
    throw (IO.userError s!"retired-write fixture {index} is outside bounds")
  unless enabledDecision before == enabled &&
      (retiredWriteEnabled limits state (nodeCodec.literal 0)).evalMemo assignment == enabled do
    throw (IO.userError s!"retired-write guard {index} differs from Model or expected result")
  let actualPending := decodeMemo nodeSetCodec assignment (pendingRetiredExpr limits state (nodeCodec.literal 0))
  unless decide (actualPending = pendingRetiredCommittedNodes before 0) do
    throw (IO.userError s!"retired-write pending set {index} differs from Model")
  let expected := next before (.appendRetiredCommitted 0)
  let actual := evalEntryMemo limits assignment (retiredWriteNext limits state (nodeCodec.literal 0))
  unless decide (BoundedState.encode actual = BoundedState.encode expected) do
    throw (IO.userError s!"retired-write complete successor {index} differs from Model")
  unless (retiredWriteGuard limits state (nodeCodec.literal 0)).evalMemo assignment ==
      (enabled && decide (BoundedState.WithinBounds limits expected)) do
    throw (IO.userError s!"retired-write bounded guard {index} differs from Model")
  IO.println s!"retired-write case {index} passed"
  (← IO.getStdout).flush

def symbolicState : Expr (stateCodec 0).ty :=
  let base := (stateCodec 0).literal (fixture true .leader .active [] 0 ∅)
  let value := (readLocal 0 base (nodeCodec.literal 0)).normalizeMemo
  let value := Expr.pair value.fst (.pair (.unknown 0) value.snd.snd)
  let pending := tableExpr fun node : Fin NODE_COUNT =>
    if node = 7 then Expr.lt (.nat 0) (.unknown 1) else .bool false
  (setCompletedExpr 0 (writeLocal 0 base (nodeCodec.literal 0) value).normalizeMemo
    (nodeCodec.literal 0) pending).normalizeMemo

def solverAssertions : List (Expr .bool) :=
  let successor := retiredWriteNext bounds symbolicState (nodeCodec.literal 0)
  let value := (readLocal 0 successor (nodeCodec.literal 0)).normalizeMemo
  [ .eq (.unknown 0) (.nat 3), .eq (.unknown 1) (.nat 1),
    retiredWriteGuard bounds symbolicState (nodeCodec.literal 0),
    .eq value.snd.fst (.unknown 0),
    .eq value.snd.snd.fst (logCodec.literal [⟨3, .retiredCommitted {7}⟩]),
    .eq (tableSelect successor.snd.snd.snd.snd.snd (nodeCodec.literal 0)) (nodeSetCodec.literal ∅),
    .eq (tableSelect successor.snd.snd.snd.snd.snd (nodeCodec.literal 14)) (nodeSetCodec.literal {14}) ]

def runTail : IO Unit := do
  let emptyState := (stateCodec 0).literal (fixture false .leader .active [] 0 {7})
  let zeroBounds : BoundedState.Bounds := ⟨0, 0, 0, 0, 0⟩
  unless (stateWithin zeroBounds emptyState).evalMemo assignment do
    throw (IO.userError "zero-domain absent retired-write fixture rejected")
  if (retiredWriteGuard zeroBounds emptyState (nodeCodec.literal 0)).evalMemo assignment then
    throw (IO.userError "zero-domain absent retired-write action enabled")
  let before := evalEntryMemo bounds assignment
    ((stateCodec 0).literal (fixture true .leader .active [] 0 ∅))
  unless decide (BoundedState.WithinBounds bounds before) &&
      @decide (Enabled before (.clientRequest 0 0)) (by unfold Enabled; infer_instance) &&
      !decide (BoundedState.WithinBounds bounds (next before (.clientRequest 0 0))) do
    throw (IO.userError "client transaction-domain boundary reproduction failed")
  for (formula, index) in solverAssertions.zipIdx do
    unless formula.evalMemo assignment do
      throw (IO.userError s!"symbolic retired-write assertion {index} failed")
  IO.println s!"zero bounds, client domain boundary, {solverAssertions.length} symbolic retired-write assertions passed"

def run : IO Unit := do
  for index in List.range cases.length do runCase index
  runTail
  IO.println s!"{cases.length} complete Model retired-write comparisons passed"

end CCFRaft.SymbolicTransitionRetiredWriteTests
