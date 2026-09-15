-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionReconfiguration
import MachineGenerated.SymbolicTransitionEvaluation

set_option autoImplicit false

namespace CCFRaft.SymbolicTransitionReconfigurationTests

open Symbolic SymbolicModel SymbolicTransition

local instance : NeZero NODE_COUNT := ⟨by decide⟩

def bounds : BoundedState.Bounds := ⟨0, 4, 4, 1, 0⟩
def assignment : Assignment := fun _ => 1

structure Case where
  role : Role := .leader
  phase : MembershipState := .active
  log : List (Entry Node Nat) := []
  commit : Nat := 0
  present : Bool := true
  peerPresent : Bool := false
  joined : Finset Node := {0, 1, 2, 3, 4}
  configuration : Finset Node := {0, 7}
  zeroSent : Bool := false
  indexCount : Nat := 4
  capacity : Nat := 1
  enabled : Bool := true
  postWithin : Bool := true

def fixture (scenario : Case) : Expr (stateCodec 0).ty :=
  let source : BoundedState.LocalStateData :=
    { BoundedState.encodeLocal (freshNodeState : NodeState Node Nat) with
      role := scenario.role, currentTerm := 2, log := scenario.log,
      commitIndex := scenario.commit, membershipState := scenario.phase,
      sentIndex := Vector.ofFn (fun _ => if scenario.zeroSent then 0 else 1) }
  let peer : BoundedState.LocalStateData :=
    { BoundedState.encodeLocal (freshNodeState : NodeState Node Nat) with
      role := .candidate, currentTerm := 1, log := [⟨1, .signature⟩],
      votedFor := some 14, votesGranted := {7, 14}, isNewFollower := false }
  (stateCodec 0).literal
    (Vector.ofFn (fun node =>
      if node = 0 ∧ scenario.present then some source
      else if node = 7 ∧ scenario.peerPresent then some peer else none),
      Vector.ofFn (fun _ => []), ∅, scenario.joined,
      Vector.ofFn (fun node => if node = 7 then .enabled else .capable),
      Vector.ofFn (fun node => if node = 0 then {14} else {0}))

def cases : List Case :=
  [ {}, { peerPresent := true }, { joined := {0, 1, 2, 3, 4, 7}, enabled := false },
    { configuration := ∅, enabled := false }, { configuration := {0, 1, 2, 3, 4}, enabled := false },
    { role := .follower, enabled := false }, { phase := .retiredCommitted, enabled := false },
    { present := false, enabled := false },
    { log := [⟨2, .reconfiguration {0, 7}⟩], configuration := {0, 7, 8},
      joined := {0, 1, 2, 3, 4, 7}, capacity := 2 },
    { log := [⟨2, .reconfiguration {7}⟩], joined := ∅, capacity := 2 },
    { log := [⟨2, .signature⟩], zeroSent := true, indexCount := 1, capacity := 2, postWithin := false },
    { log := [⟨2, .signature⟩], postWithin := false },
    { log := [⟨2, .reconfiguration {7}⟩, ⟨2, .retiredCommitted {0}⟩],
      commit := 2, joined := ∅, capacity := 3, enabled := false } ]

def enabledDecision (state : CCFRaft.State Node Nat) (configuration : Finset Node) : Bool :=
  @decide (Enabled state (.changeConfiguration 0 configuration)) (by unfold Enabled; infer_instance)

def checkTransition (limits : BoundedState.Bounds)
    (state : Expr (stateCodec limits.transactionCount).ty) (configuration : Expr nodeSetCodec.ty)
    (ρ : Assignment) : IO Unit := do
  let before := evalEntryMemo limits ρ state
  unless decide (BoundedState.WithinBounds limits before) do
    throw (IO.userError "reconfiguration fixture is outside input bounds")
  let nodes := decodeMemo nodeSetCodec ρ configuration
  let enabled := enabledDecision before nodes
  let expected := next before (.changeConfiguration 0 nodes)
  unless (configurationEnabled limits state (nodeCodec.literal 0) configuration).evalMemo ρ == enabled do
    throw (IO.userError "reconfiguration Enabled differs from Model")
  let actual := evalEntryMemo limits ρ (configurationNext limits state (nodeCodec.literal 0) configuration)
  unless decide (BoundedState.encode actual = BoundedState.encode expected) do
    throw (IO.userError "reconfiguration successor differs from complete Model state")
  unless (configurationAccepted limits state (nodeCodec.literal 0) configuration).evalMemo ρ ==
      (enabled && decide (BoundedState.WithinBounds limits expected)) do
    throw (IO.userError "reconfiguration bounded acceptance differs from Model")

def runCase (index : Nat) : IO Unit := do
  let some scenario := cases[index]? | throw (IO.userError s!"unknown reconfiguration case {index}")
  let limits := { bounds with logCapacity := scenario.capacity, indexCount := scenario.indexCount }
  let state := fixture scenario
  let before := evalEntryMemo limits assignment state
  unless enabledDecision before scenario.configuration == scenario.enabled do
    throw (IO.userError s!"reconfiguration Enabled expectation {index} failed")
  unless decide (BoundedState.WithinBounds limits (next before (.changeConfiguration 0 scenario.configuration))) ==
      scenario.postWithin do
    throw (IO.userError s!"reconfiguration post-bounds expectation {index} failed")
  checkTransition limits state (nodeSetCodec.literal scenario.configuration) assignment
  IO.println s!"reconfiguration case {index} passed"
  (← IO.getStdout).flush

def symbolicConfiguration : Expr nodeSetCodec.ty :=
  tableExpr fun node : Node => if node = 0 then .bool true
    else if node = 7 then .lt (.nat 0) (.unknown 0) else .bool false

def solverAssertions : List (Expr .bool) :=
  let state := fixture {}
  let successor := configurationNext bounds state (nodeCodec.literal 0) symbolicConfiguration
  let source := (readLocal 0 successor (nodeCodec.literal 0)).normalizeMemo
  [ .eq (.unknown 0) (.nat 1),
    configurationAccepted bounds state (nodeCodec.literal 0) symbolicConfiguration,
    .eq source.snd.snd.fst (logCodec.literal [⟨2, .reconfiguration {0, 7}⟩]),
    .eq (entryNode 0 successor (nodeCodec.literal 7))
      (localCodec.option.literal (some (BoundedState.encodeLocal freshNodeState))),
    .eq (tableSelect source.snd.snd.snd.snd.fst (nodeCodec.literal 7)) (.nat 0),
    .eq (tableSelect source.snd.snd.snd.snd.fst (nodeCodec.literal 14)) (.nat 1),
    .eq successor.snd.snd.snd.fst (nodeSetCodec.literal {0, 1, 2, 3, 4, 7}),
    .eq (tableSelect successor.snd.snd.snd.snd.fst (nodeCodec.literal 7)) (preVoteCodec.literal .enabled),
    .eq (tableSelect successor.snd.snd.snd.snd.snd (nodeCodec.literal 14)) (nodeSetCodec.literal {0}) ]

def runTail : IO Unit := do
  for choice in [0, 1] do
    checkTransition bounds (fixture {}) symbolicConfiguration (fun _ => choice)
  let zeroBounds : BoundedState.Bounds := ⟨0, 0, 0, 0, 0⟩
  checkTransition zeroBounds (fixture { present := false }) (nodeSetCodec.literal {0, 7}) assignment
  for (formula, index) in solverAssertions.zipIdx do
    unless formula.evalMemo assignment do
      throw (IO.userError s!"symbolic reconfiguration assertion {index} failed")
  IO.println s!"2 symbolic configuration cases, zero bounds, {solverAssertions.length} symbolic assertions passed"

def run : IO Unit := do
  for index in List.range cases.length do runCase index
  runTail
  IO.println s!"{cases.length} complete Model reconfiguration comparisons passed"

end CCFRaft.SymbolicTransitionReconfigurationTests
