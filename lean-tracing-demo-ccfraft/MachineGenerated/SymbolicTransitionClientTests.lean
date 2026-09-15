-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionClient
import MachineGenerated.SymbolicTransitionEvaluation
import BoundedSymbolicTrace

set_option autoImplicit false

namespace CCFRaft.SymbolicTransitionClientTests

open Symbolic SymbolicModel SymbolicTransition

local instance : NeZero NODE_COUNT := ⟨by decide⟩

def bounds : BoundedState.Bounds := ⟨2, 4, 4, 1, 0⟩
local instance : NeZero bounds.transactionCount := ⟨by decide⟩
def assignment : Assignment := fun i => if i = 2 then 3 else 1

structure Case where
  role : Role := .leader
  phase : MembershipState := .active
  log : List (Entry Node Nat) := []
  commit : Nat := 0
  present : Bool := true
  submitted : Finset (Fin bounds.transactionCount) := ∅
  transaction : Nat := 1
  enabled : Bool := true
  capacity : Nat := 1

def fixture (transactions : Nat) (value : Option BoundedState.LocalStateData)
    (submitted : Finset (Fin transactions)) : EntryData transactions :=
  (Vector.ofFn (fun node => if node = 0 then value else none),
    Vector.ofFn (fun _ => []), submitted, {0, 7}, Vector.ofFn (fun _ => .enabled),
    Vector.ofFn (fun node => if node = 0 then {7} else {14}))

def caseEntry (scenario : Case) : Expr (stateCodec bounds.transactionCount).ty :=
  let value : BoundedState.LocalStateData :=
    { BoundedState.encodeLocal (freshNodeState : NodeState Node Nat) with
      role := scenario.role, currentTerm := 3, log := scenario.log,
      commitIndex := scenario.commit, membershipState := scenario.phase }
  (stateCodec bounds.transactionCount).literal (fixture bounds.transactionCount
    (if scenario.present then some value else none) scenario.submitted)

def cases : List Case :=
  [ {}, { submitted := {0} }, { submitted := {0}, transaction := 0, enabled := false },
    { submitted := {0, 1}, enabled := false }, { role := .follower, enabled := false },
    { role := .candidate, enabled := false }, { phase := .retiredCommitted, enabled := false },
    { log := [⟨2, .reconfiguration {7}⟩, ⟨2, .retiredCommitted {0}⟩],
      commit := 2, capacity := 3, enabled := false },
    { present := false, enabled := false }, { transaction := 2 }, { transaction := 999 },
    { log := [⟨2, .signature⟩] }, { transaction := 0 } ]

def enabledDecision (state : CCFRaft.State Node Nat) (transaction : Nat) : Bool :=
  @decide (Enabled state (.clientRequest 0 transaction)) (by unfold Enabled; infer_instance)

def checkTransition (limits : BoundedState.Bounds)
    (state : Expr (stateCodec limits.transactionCount).ty) (transaction : Expr .nat)
    (ρ : Assignment) : IO Unit := do
  let before := evalEntryMemo limits ρ state
  unless decide (BoundedState.WithinBounds limits before) do
    throw (IO.userError "client fixture is outside input bounds")
  let action : BoundedSymbolicTrace.SymbolicAction := .clientRequest 0 transaction
  let expected := next before (evaluateActionMemo ρ action)
  let enabled := enabledDecision before (transaction.evalMemo ρ)
  let accepted := enabled && decide (BoundedState.WithinBounds limits expected)
  unless (clientEnabled limits state (nodeCodec.literal 0) transaction).evalMemo ρ == enabled do
    throw (IO.userError "client Enabled differs from Model")
  unless (clientAccepted limits state (nodeCodec.literal 0) transaction).evalMemo ρ == accepted &&
      (clientGuard limits state (nodeCodec.literal 0) transaction).evalMemo ρ == accepted do
    throw (IO.userError "bounded client acceptance differs from Model")
  if transaction.evalMemo ρ < limits.transactionCount then
    let actual := evalEntryMemo limits ρ (clientNext limits state (nodeCodec.literal 0) transaction)
    unless decide (BoundedState.encode actual = BoundedState.encode expected) do
      throw (IO.userError "in-domain client successor differs from complete Model state")
  else if accepted then
    throw (IO.userError "out-of-domain client transaction accepted")

def runCase (index : Nat) : IO Unit := do
  let some scenario := cases[index]? | throw (IO.userError s!"unknown client case {index}")
  let limits := { bounds with logCapacity := scenario.capacity }
  let state := caseEntry scenario
  unless enabledDecision (evalEntryMemo limits assignment state) scenario.transaction == scenario.enabled do
    throw (IO.userError s!"client Enabled expectation {index} failed")
  checkTransition limits state (.nat scenario.transaction) assignment
  IO.println s!"client case {index} passed"
  (← IO.getStdout).flush

def symbolicState : Expr (stateCodec bounds.transactionCount).ty :=
  let base := caseEntry {}
  let value := (readLocal bounds.transactionCount base (nodeCodec.literal 0)).normalizeMemo
  let value := Expr.pair value.fst (.pair (.unknown 2) value.snd.snd)
  let submitted := tableExpr fun index : Fin bounds.transactionCount =>
    if index = 0 then Expr.lt (.nat 0) (.unknown 1) else .bool false
  (setSubmittedExpr bounds.transactionCount
    (writeLocal bounds.transactionCount base (nodeCodec.literal 0) value).normalizeMemo submitted).normalizeMemo

def solverAssertions : List (Expr .bool) :=
  let successor := clientNext bounds symbolicState (nodeCodec.literal 0) (.unknown 0)
  let value := (readLocal bounds.transactionCount successor (nodeCodec.literal 0)).normalizeMemo
  [ .eq (.unknown 0) (.nat 1), .eq (.unknown 1) (.nat 1), .eq (.unknown 2) (.nat 3),
    clientGuard bounds symbolicState (nodeCodec.literal 0) (.unknown 0),
    .eq value.snd.fst (.unknown 2),
    .eq value.snd.snd.fst (logCodec.literal [⟨3, .transaction 1⟩]),
    .eq successor.snd.snd.fst ((Codec.finset bounds.transactionCount).literal {0, 1}),
    .eq (tableSelect successor.snd.snd.snd.snd.snd (nodeCodec.literal 0)) (nodeSetCodec.literal ∅),
    .eq (tableSelect successor.snd.snd.snd.snd.snd (nodeCodec.literal 14)) (nodeSetCodec.literal {14}) ]

def runTail : IO Unit := do
  for (transaction, present) in [(0, 0), (0, 1), (1, 1), (2, 1)] do
    checkTransition bounds symbolicState (.unknown 0)
      (fun i => if i = 0 then transaction else if i = 1 then present else 3)
  let zeroTransactions := { bounds with transactionCount := 0 }
  let leader : BoundedState.LocalStateData :=
    { BoundedState.encodeLocal (freshNodeState : NodeState Node Nat) with role := .leader }
  checkTransition zeroTransactions ((stateCodec 0).literal (fixture 0 (some leader) ∅)) (.nat 0) assignment
  let zeroBounds : BoundedState.Bounds := ⟨0, 0, 0, 0, 0⟩
  checkTransition zeroBounds ((stateCodec 0).literal (fixture 0 none ∅)) (.nat 0) assignment
  for (formula, index) in solverAssertions.zipIdx do
    unless formula.evalMemo assignment do
      throw (IO.userError s!"symbolic client assertion {index} failed")
  IO.println s!"4 shared-assignment client cases, zero transaction/scalar bounds, {solverAssertions.length} symbolic assertions passed"

def run : IO Unit := do
  for index in List.range cases.length do runCase index
  runTail
  IO.println s!"{cases.length} client cases passed"

end CCFRaft.SymbolicTransitionClientTests
