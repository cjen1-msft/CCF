-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionQuorum
import MachineGenerated.SymbolicTransitionEvaluation
import BoundedSymbolicTrace

set_option autoImplicit false

namespace CCFRaft.SymbolicTransitionElectionTests

open Symbolic SymbolicModel SymbolicTransition

local instance : NeZero NODE_COUNT := ⟨by decide⟩

def bounds : BoundedState.Bounds := ⟨0, 4, 8, 2, 1⟩
def assignment : Assignment := fun _ => 1

structure Case where
  action : BoundedSymbolicTrace.SymbolicAction := .timeout 0
  actor : Node := 0
  role : Role := .follower
  phase : MembershipState := .active
  term : Nat := 1
  log : List (Entry Node Nat) := []
  commit : Nat := 0
  present : Bool := true
  status : PreVoteStatus := .capable
  preVotes : Finset Node := {0, 1, 2}
  selfCompleted : Bool := false
  packet : Bool := true
  enabled : Bool := true
  postWithin : Bool := true

def fixture (scenario : Case) : Expr (stateCodec 0).ty :=
  let value : BoundedState.LocalStateData :=
    { BoundedState.encodeLocal (freshNodeState : NodeState Node Nat) with
      role := scenario.role, currentTerm := scenario.term, log := scenario.log,
      commitIndex := scenario.commit, membershipState := scenario.phase,
      sentIndex := Vector.ofFn (fun _ => 1), votedFor := some 14,
      votesGranted := {7, 14}, preVotesGranted := scenario.preVotes, isNewFollower := false,
      retirementIndex := some 3, retirementCommittableIndex := some 4, retiredCommittedIndex := some 5 }
  (stateCodec 0).literal
    (Vector.ofFn (fun node => if node = scenario.actor ∧ scenario.present then some value else none),
      Vector.ofFn (fun node => if node = 14 ∧ scenario.packet then [.proposeVoteRequest ⟨1, 7, 14⟩] else []),
      ∅, {0, 7}, Vector.ofFn (fun node => if node = scenario.actor then scenario.status else .enabled),
      Vector.ofFn (fun node =>
        if node = scenario.actor then if scenario.selfCompleted then {scenario.actor} else ∅ else {14}))

def cases : List Case :=
  let configuration : Entry Node Nat := ⟨1, .reconfiguration {0, 7}⟩
  let removed : Entry Node Nat := ⟨1, .reconfiguration {7}⟩
  let joint : Entry Node Nat := ⟨1, .reconfiguration {7, 8}⟩
  [ {}, { status := .enabled, enabled := false }, { role := .leader, enabled := false },
    { phase := .retiredCommitted, enabled := false },
    { log := [configuration], commit := 1, enabled := false },
    { log := [configuration], commit := 1, selfCompleted := true },
    { log := [configuration, ⟨1, .signature⟩], commit := 1 },
    { log := [removed], commit := 1, enabled := false },
    { log := [removed], commit := 1, selfCompleted := true },
    { term := 3, postWithin := false },
    { action := .becomePreVoteCandidate 0, status := .enabled },
    { action := .becomePreVoteCandidate 0, enabled := false },
    { action := .becomePreVoteCandidate 0, status := .enabled, term := 3 },
    { action := .becomeCandidate 0, role := .preVoteCandidate, status := .enabled },
    { action := .becomeCandidate 0, status := .enabled, enabled := false },
    { action := .becomeCandidate 0, role := .preVoteCandidate, status := .enabled,
      preVotes := {0, 1}, enabled := false },
    { action := .becomeCandidate 0, role := .preVoteCandidate, enabled := false },
    { action := .becomeCandidate 0, role := .preVoteCandidate, status := .enabled,
      log := [joint], preVotes := {0, 1, 2, 7}, enabled := false },
    { action := .becomeCandidate 0, role := .preVoteCandidate, status := .enabled,
      log := [joint], preVotes := {0, 1, 2, 7, 8} },
    { action := .becomeCandidate 0, role := .preVoteCandidate, status := .enabled, term := 3, postWithin := false },
    { action := .checkQuorum 0, role := .leader },
    { action := .checkQuorum 0, role := .leader, phase := .retiredCommitted },
    { action := .checkQuorum 0, role := .leader, log := [⟨1, .reconfiguration {0}⟩], commit := 1, enabled := false },
    { action := .checkQuorum 0, enabled := false },
    { present := false, enabled := false },
    { action := .becomePreVoteCandidate 0, present := false, enabled := false },
    { action := .becomeCandidate 0, present := false, enabled := false },
    { action := .checkQuorum 0, present := false, enabled := false },
    { action := .timeout 7, actor := 7, log := [removed, ⟨1, .signature⟩], commit := 1 } ]

def expressions (limits : BoundedState.Bounds) (state : Expr (stateCodec limits.transactionCount).ty) :
    BoundedSymbolicTrace.SymbolicAction →
      Except String (Expr .bool × Expr .bool × Expr (stateCodec limits.transactionCount).ty)
  | .timeout node =>
      .ok (timeoutEnabled limits state (nodeCodec.literal node), timeoutAccepted limits state (nodeCodec.literal node),
        candidateNext limits state (nodeCodec.literal node))
  | .becomePreVoteCandidate node =>
      .ok (preCandidateEnabled limits state (nodeCodec.literal node), preCandidateAccepted limits state (nodeCodec.literal node),
        preCandidateNext limits state (nodeCodec.literal node))
  | .becomeCandidate node =>
      .ok (candidateEnabled limits state (nodeCodec.literal node), candidateAccepted limits state (nodeCodec.literal node),
        candidateNext limits state (nodeCodec.literal node))
  | .checkQuorum node =>
      .ok (checkQuorumEnabled limits state (nodeCodec.literal node), checkQuorumAccepted limits state (nodeCodec.literal node),
        checkQuorumNext limits state (nodeCodec.literal node))
  | _ => .error "not an election-start or checkQuorum test action"

def checkTransition (limits : BoundedState.Bounds) (state : Expr (stateCodec limits.transactionCount).ty)
    (action : BoundedSymbolicTrace.SymbolicAction) (ρ : Assignment) : IO Unit := do
  let (before, cache) := (evalEntryMemoM limits ρ state).run {}
  unless decide (BoundedState.WithinBounds limits before) do
    throw (IO.userError "election fixture is outside input bounds")
  let actualAction := evaluateActionMemo ρ action
  let expected := next before actualAction
  let (enabled, accepted, successor) ←
    match expressions limits state action with
    | .ok values => pure values
    | .error message => throw (IO.userError message)
  let (actualEnabled, cache) := (enabled.evalMemoM ρ).run cache
  unless actualEnabled == decide (Enabled before actualAction) do
    throw (IO.userError "election Enabled differs from Model")
  let (actualAccepted, cache) := (accepted.evalMemoM ρ).run cache
  unless actualAccepted == (decide (Enabled before actualAction) && decide (BoundedState.WithinBounds limits expected)) do
    throw (IO.userError "election bounded acceptance differs from Model")
  let (after, _) := (evalEntryMemoM limits ρ successor).run cache
  unless decide (BoundedState.encode after = BoundedState.encode expected) do
    throw (IO.userError "election successor differs from complete Model state")

def runCase (index : Nat) : IO Unit := do
  let some scenario := cases[index]? | throw (IO.userError s!"unknown election case {index}")
  let limits := { bounds with logCapacity := scenario.log.length }
  let state := fixture scenario
  let before := evalEntryMemo limits assignment state
  let action := evaluateActionMemo assignment scenario.action
  unless decide (Enabled before action) == scenario.enabled do
    throw (IO.userError s!"election Enabled expectation {index} failed")
  unless decide (BoundedState.WithinBounds limits (next before action)) == scenario.postWithin do
    throw (IO.userError s!"election successor bounds expectation {index} failed")
  checkTransition limits state scenario.action assignment
  IO.println s!"election case {index} passed"
  (← IO.getStdout).flush

def symbolicState : Expr (stateCodec 0).ty :=
  let base := fixture { packet := false, status := .enabled, role := .preVoteCandidate }
  let value := (readLocal 0 base (nodeCodec.literal 0)).normalizeMemo
  let preVotes := tableExpr fun node : Node =>
    if node = 0 ∨ node = 1 then .bool true else if node = 2 then .lt (.nat 0) (.unknown 1) else .bool false
  let value := setElectionFields value value.fst (.unknown 0) value.snd.snd.snd.snd.snd.snd.fst
    value.snd.snd.snd.snd.snd.snd.snd.fst value.snd.snd.snd.snd.snd.snd.snd.snd.fst preVotes
  (writeLocal 0 base (nodeCodec.literal 0) value).normalizeMemo

def solverBounds : BoundedState.Bounds := { bounds with logCapacity := 0, queueCapacity := 0 }

def solverAssertions : List (Expr .bool) :=
  let successor := candidateNext solverBounds symbolicState (nodeCodec.literal 0)
  let value := (readLocal 0 successor (nodeCodec.literal 0)).normalizeMemo
  [ .eq (.unknown 0) (.nat 1), .eq (.unknown 1) (.nat 1),
    candidateAccepted solverBounds symbolicState (nodeCodec.literal 0),
    .eq value.fst (roleCodec.literal .candidate), .eq value.snd.fst (.add (.unknown 0) (.nat 1)),
    .eq value.snd.snd.snd.snd.snd.snd.fst (.bool false),
    .eq value.snd.snd.snd.snd.snd.snd.snd.fst (nodeCodec.option.literal (some 0)),
    .eq value.snd.snd.snd.snd.snd.snd.snd.snd.fst (nodeSetCodec.literal {0}),
    .eq value.snd.snd.snd.snd.snd.snd.snd.snd.snd.fst (nodeSetCodec.literal ∅),
    .eq successor.snd symbolicState.snd ]

def runTail : IO Unit := do
  for (term, vote) in [(1, 0), (1, 1), (3, 1)] do
    checkTransition solverBounds symbolicState (.becomeCandidate 0)
      (fun i => if i = 0 then term else vote)
  let zeroBounds : BoundedState.Bounds := ⟨0, 0, 0, 0, 0⟩
  for action in [(.timeout 0 : BoundedSymbolicTrace.SymbolicAction), .becomePreVoteCandidate 0, .becomeCandidate 0, .checkQuorum 0] do
    checkTransition zeroBounds (fixture { present := false, packet := false }) action assignment
  for (formula, index) in solverAssertions.zipIdx do
    unless formula.evalMemo assignment do
      throw (IO.userError s!"symbolic election assertion {index} failed")
  IO.println s!"3 shared-assignment election cases, 4 zero-bound actions, {solverAssertions.length} symbolic assertions passed"

def run : IO Unit := do
  for index in List.range cases.length do runCase index
  runTail
  IO.println s!"{cases.length} complete Model election comparisons passed"

end CCFRaft.SymbolicTransitionElectionTests
