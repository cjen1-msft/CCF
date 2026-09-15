-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionSignature
import MachineGenerated.SymbolicTransitionEvaluation

set_option autoImplicit false

namespace CCFRaft.SymbolicTransitionSignatureTests

open Symbolic SymbolicModel SymbolicTransition

local instance : NeZero NODE_COUNT := ⟨by decide⟩

def bounds : BoundedState.Bounds := ⟨0, 8, 32, 4, 1⟩
def assignment : Assignment := fun i => if i = 0 then 3 else 0

def completedCases : List (List (Entry Node Nat) × Nat × Finset Node) :=
  let configuration : Entry Node Nat := ⟨2, .reconfiguration {1, 2, 7}⟩
  let retired : Entry Node Nat := ⟨2, .retiredCommitted {0, 4}⟩
  [ ([], 0, ∅), ([], 9, ∅),
    ([configuration], 0, ∅),
    ([configuration], 1, {0, 3, 4}),
    ([configuration], 9, {0, 3, 4}),
    ([configuration, retired], 1, {0, 3, 4}),
    ([configuration, retired], 2, {3}),
    ([configuration, ⟨3, .reconfiguration {0, 1, 2, 3, 4, 7}⟩], 2, ∅),
    ([configuration, ⟨3, .reconfiguration {7, 8}⟩], 2, {0, 1, 2, 3, 4}),
    ([configuration, retired, ⟨3, .reconfiguration {7, 8}⟩], 3, {1, 2, 3}) ]

def localFixture (role : Role) (phase : MembershipState)
    (log : List (Entry Node Nat)) (commit : Nat) : BoundedState.LocalStateData :=
  { BoundedState.encodeLocal (freshNodeState : NodeState Node Nat) with
    role := role
    currentTerm := 3
    log := log
    commitIndex := commit
    sentIndex := Vector.ofFn (fun node => node.val)
    matchIndex := Vector.ofFn (fun node => node.val + 1)
    votedFor := some 7
    votesGranted := {0, 7}
    preVotesGranted := {1, 14}
    membershipState := phase
    retirementIndex := some 4
    retirementCommittableIndex := some 5
    retiredCommittedIndex := some 6 }

def fixture (present : Bool) (value : BoundedState.LocalStateData) : EntryData 0 :=
  (Vector.ofFn (fun node =>
      if node = 0 then if present then some value else none
      else if node = 14 then some (localFixture .follower .active [] 0) else none),
    Vector.ofFn (fun node =>
      if node = 7 then [.proposeVoteRequest ⟨2, 14, 7⟩] else []),
    ∅, {0, 7, 14}, Vector.ofFn (fun node => if node = 7 then .capable else .enabled),
    Vector.ofFn (fun node => if node = 0 then {8} else {0, 7}))

def enabledDecision (state : CCFRaft.State Node Nat) (node : Node) : Bool :=
  @decide (Enabled state (.signCommittableMessages node)) (by unfold Enabled; infer_instance)

def transitionCases : List (Bool × Role × MembershipState × List (Entry Node Nat) × Nat × Bool) :=
  let signature : Entry Node Nat := ⟨2, .signature⟩
  let configuration : Entry Node Nat := ⟨2, .reconfiguration {1}⟩
  let retired : Entry Node Nat := ⟨2, .retiredCommitted {0}⟩
  [ (false, .leader, .active, [signature], 0, false),
    (true, .none, .active, [signature], 0, false),
    (true, .follower, .active, [signature], 0, false),
    (true, .preVoteCandidate, .active, [signature], 0, false),
    (true, .candidate, .active, [signature], 0, false),
    (true, .leader, .active, [], 0, false),
    (true, .leader, .retiredCommitted, [signature], 0, false),
    (true, .leader, .active, [signature], 0, true),
    (true, .leader, .active, [configuration], 0, true),
    (true, .leader, .retirementOrdered, [configuration], 0, true),
    (true, .leader, .retirementSigned, [configuration], 0, true),
    (true, .leader, .retirementCompleted, [configuration], 1, true),
    (true, .leader, .active, [configuration, retired], 1, true),
    (true, .leader, .active, [configuration, retired], 2, false),
    (true, .leader, .active, [retired], 1, true),
    (true, .leader, .active, [signature, signature, signature, configuration], 0, true) ]

def checkTransition (limits : BoundedState.Bounds) (state : Expr (stateCodec limits.transactionCount).ty)
    (node : Expr nodeCodec.ty) (ρ : Assignment) : IO Unit := do
  let before := evalEntryMemo limits ρ state
  let action := Action.signCommittableMessages (decodeMemo nodeCodec ρ node)
  unless decide (BoundedState.WithinBounds limits before) do
    throw (IO.userError "signature fixture is outside declared input bounds")
  let expected := next before action
  let actual := evalEntryMemo limits ρ (signatureNext limits state node)
  unless decide (BoundedState.encode actual = BoundedState.encode expected) do
    throw (IO.userError "signature successor differs from complete Model state")
  let enabled := enabledDecision before (decodeMemo nodeCodec ρ node)
  unless (signatureEnabled limits state node).evalMemo ρ == enabled do
    throw (IO.userError "signature Enabled differs from Model")
  unless (signatureGuard limits state node).evalMemo ρ ==
      (enabled && decide (BoundedState.WithinBounds limits expected)) do
    throw (IO.userError "signature bounded guard differs from Model")

def runTransitionCase (index : Nat) : IO Unit := do
  let some (present, role, phase, entries, commit, enabled) := transitionCases[index]? |
    throw (IO.userError s!"unknown signature case {index}")
  let limits := { bounds with logCapacity := min bounds.logCapacity (entries.length + 1) }
  let state := (stateCodec 0).literal (fixture present (localFixture role phase entries commit))
  unless enabledDecision (evalEntryMemo limits assignment state) 0 == enabled do
    throw (IO.userError s!"signature guard expectation {index} failed")
  checkTransition limits state (nodeCodec.literal 0) assignment
  if entries.length = limits.logCapacity then
    if (signatureGuard limits state (nodeCodec.literal 0)).evalMemo assignment then
      throw (IO.userError "signature capacity overflow was not rejected")
  IO.println s!"signature case {index} passed"
  (← IO.getStdout).flush

def emptyData : EntryData 0 :=
  (Vector.ofFn (fun _ => none), Vector.ofFn (fun _ => []), ∅, ∅,
    Vector.ofFn (fun _ => .capable), Vector.ofFn (fun _ => ∅))

def solverBounds : BoundedState.Bounds := ⟨0, 8, 4, 2, 0⟩

def symbolicState : Expr (stateCodec 0).ty :=
  let base := (stateCodec 0).literal emptyData
  let value := localCodec.literal
    { BoundedState.encodeLocal (freshNodeState : NodeState Node Nat) with role := .leader }
  let log := Expr.cons (.pair (.unknown 0) (contentCodec.literal .signature)) .nil
  let value := Expr.pair value.fst (.pair (.unknown 0) (.pair log value.snd.snd.snd))
  (writeLocal 0 base (nodeCodec.literal 0) value).normalizeMemo

def solverAssertions : List (Expr .bool) :=
  let successor := (signatureNext solverBounds symbolicState (nodeCodec.literal 0)).normalizeMemo
  let value := (readLocal 0 successor (nodeCodec.literal 0)).normalizeMemo
  [ .eq (.unknown 0) (.nat 3),
    signatureGuard solverBounds symbolicState (nodeCodec.literal 0),
    .eq value.fst (roleCodec.literal .leader),
    .eq value.snd.fst (.unknown 0),
    .eq (termAtExpr value.snd.snd.fst (.nat 1)) (.unknown 0),
    .eq (termAtExpr value.snd.snd.fst (.nat 2)) (.unknown 0),
    .eq (.length value.snd.snd.fst) (.nat 2),
    .eq successor.snd symbolicState.snd ]

def runTail : IO Unit := do
  let state := (stateCodec 0).literal (fixture true (localFixture .leader .active [] 0))
  let selector := Expr.ite (.eq (.unknown 1) (.nat 0)) (nodeCodec.literal 0) (nodeCodec.literal 14)
  for choice in [0, 1] do
    let ρ : Assignment := fun i => if i = 0 then 3 else choice
    let before := evalEntryMemo bounds ρ state
    let actual := evalEntryMemo bounds ρ (setCompletedExpr 0 state selector (nodeSetCodec.literal {1, 7}))
    let expected := { before with
      retirementCompleted := Function.update before.retirementCompleted (decodeMemo nodeCodec ρ selector) {1, 7} }
    unless decide (BoundedState.encode actual = BoundedState.encode expected) do
      throw (IO.userError s!"symbolic observer selection {choice} failed")
  let zeroBounds : BoundedState.Bounds := ⟨0, 0, 0, 0, 0⟩
  checkTransition zeroBounds ((stateCodec 0).literal emptyData) (nodeCodec.literal 0) (fun _ => 0)
  for (formula, index) in solverAssertions.zipIdx do
    unless formula.evalMemo assignment do
      throw (IO.userError s!"symbolic signature assertion {index} failed")
  IO.println s!"2 symbolic observer selectors, zero bounds, {solverAssertions.length} symbolic assertions passed"

-- Separate from the default batch because full symbolic actor composition is slow.
def runSymbolicActor : IO Unit := do
  let selector := Expr.ite (.eq (.unknown 1) (.nat 0)) (nodeCodec.literal 0) (nodeCodec.literal 14)
  for choice in [0, 1] do
    IO.println s!"checking full symbolic actor choice {choice}"
    (← IO.getStdout).flush
    checkTransition solverBounds symbolicState selector (fun i => if i = 0 then 3 else choice)
  IO.println "2 complete Model symbolic actor comparisons passed"

def run : IO Unit := do
  for ((entries, commit, nodes), index) in completedCases.zipIdx do
    let actual := decodeMemo nodeSetCodec assignment
      (retirementCompletedNodesExpr entries.length (logCodec.literal entries) (.nat commit))
    unless decide (actual = retirementCompletedNodes entries commit ∧ actual = nodes) do
      throw (IO.userError s!"retirement completion case {index} failed")
    let value := localFixture .leader .active entries commit
    let data := fixture true value
    let state := (stateCodec 0).literal data
    for observer in ([0, 7, 14] : List Node) do
      let refreshed := evalEntryMemo bounds assignment
        (refreshCompletedExpr bounds entries.length state (nodeCodec.literal observer) (localCodec.literal value))
      let before := evalEntryMemo bounds assignment state
      let expected := { before with
        retirementCompleted := refreshRetirementCompleted before.retirementCompleted observer
          (BoundedState.decodeLocal value) }
      unless decide (BoundedState.encode refreshed = BoundedState.encode expected) do
        throw (IO.userError s!"retirement completion observer update {index}/{observer.val} failed")
    IO.println s!"retirement completion case {index} and observer updates passed"
    (← IO.getStdout).flush
  for index in List.range transitionCases.length do
    runTransitionCase index
  runTail
  IO.println s!"{completedCases.length} completion cases, {completedCases.length * 3} observer updates, {transitionCases.length} signature cases passed"

end CCFRaft.SymbolicTransitionSignatureTests
