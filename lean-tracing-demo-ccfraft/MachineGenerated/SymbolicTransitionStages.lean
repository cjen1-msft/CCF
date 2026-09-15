-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionCommitTests
import Shared.SymbolicSmt

set_option autoImplicit false

namespace CCFRaft.SymbolicTransitionStages

open Symbolic SymbolicModel SymbolicTransition SymbolicTransitionLeadershipTests

inductive Phase where
  | construct | evaluate | serialize | all
  deriving BEq

@[noinline] def construct {s : Ty} (build : Unit → Expr s) : IO (Expr s) :=
  pure (build ())

@[noinline] def evaluate {s : Ty} (ρ : Assignment) (expression : Expr s)
    (cache : Expr.EvaluationState ρ) : IO s.Value :=
  pure ((expression.evalMemoM ρ).run cache).1

@[noinline] def rootTag {s : Ty} : Expr s → String
  | .named _ _ _ => "named"
  | .ite _ _ _ => "ite"
  | .pair _ _ => "pair"
  | .nat _ => "nat"
  | .bool _ => "bool"
  | _ => "other"

def report (message : String) : IO Unit := do
  IO.println message
  (← IO.getStdout).flush

def probe {s : Ty} (label : String) (phase : Phase) (build : Unit → Expr s)
    (ρ : Assignment) (cache : Expr.EvaluationState ρ) (matchesModel : s.Value → Bool) : IO Unit := do
  report s!"{label}: construction starting"
  let start ← IO.monoMsNow
  let expression ← construct build
  report s!"{label}: construction finished in {(← IO.monoMsNow) - start}ms, root={rootTag expression}"
  if phase == .construct then return
  if phase != .serialize then
    report s!"{label}: evaluation starting"
    let start ← IO.monoMsNow
    let actual ← evaluate ρ expression cache
    report s!"{label}: evaluation finished in {(← IO.monoMsNow) - start}ms"
    report s!"{label}: Model comparison starting"
    unless matchesModel actual do throw (IO.userError s!"{label}: Model comparison failed")
    report s!"{label}: Model comparison passed"
  if phase == .evaluate then return
  report s!"{label}: serialization starting"
  let start ← IO.monoMsNow
  let text ← match Symbolic.script [.eq expression (.named 0 1 expression)] with
    | .ok text => pure text
    | .error message => throw (IO.userError message)
  report s!"{label}: serialization finished in {(← IO.monoMsNow) - start}ms, bytes={text.utf8ByteSize}"

def run (index : Nat) (component : String) (phase : Phase) (named : Bool) : IO Unit := do
  let some (scenario, overrides, _) := SymbolicTransitionCommitTests.cases[index]? |
    throw (IO.userError s!"unknown commit case {index}")
  let (source, destination) ← match scenario.action with
    | .advanceCommitIndex source => pure (source, none)
    | .advanceCommitIndexAndProposeVote source destination => pure (source, some destination)
    | _ => throw (IO.userError "construction probe requires a commit action")
  let limits := { bounds with logCapacity := scenario.log.length }
  report "fixture construction starting"
  let input ← construct fun _ => SymbolicTransitionProposalTests.fixtureWithMatches scenario overrides
  let entry := if named then Expr.named 0 0 input else input
  report s!"fixture construction finished, root={rootTag entry}"
  report "reference Model evaluation starting"
  let (before, cache) := (evalEntryMemoM limits assignment entry).run {}
  let action := evaluateActionMemo assignment scenario.action
  unless BoundedState.WithinBounds limits before do
    throw (IO.userError "fixture is outside declared bounds")
  report "reference Model evaluation finished"
  let node := nodeCodec.literal source
  match component with
  | "check" =>
      unless phase == .evaluate do
        throw (IO.userError "the shared-cache check requires the evaluate phase")
      check limits entry scenario.action assignment true
  | "frontier" =>
      probe component phase (fun _ => highestCommitExpr limits entry node)
        assignment cache (fun actual => actual == highestCommittableIndex before source)
  | "local" =>
      probe component phase (fun _ => advancedLocal limits entry node) assignment cache
        (fun actual => (localCodec.equiv actual) ==
          BoundedState.encodeLocal (refreshRetirementState source
            { before.nodes source with commitIndex := highestCommittableIndex before source }))
  | "advanced" =>
      probe component phase (fun _ => advanceStateExpr limits entry node) assignment cache
        (fun actual =>
          BoundedState.encode (BoundedState.decode ((stateCodec 0).equiv actual).toData) ==
            BoundedState.encode (advanceCommitState before source))
  | "enabled" | "accepted" =>
      probe component phase (fun _ =>
        match destination with
        | none =>
            if component = "enabled" then advanceEnabled limits entry node else advanceAccepted limits entry node
        | some destination =>
            if component = "enabled" then advanceProposalEnabled limits entry node (nodeCodec.literal destination)
            else advanceProposalAccepted limits entry node (nodeCodec.literal destination))
        assignment cache (fun actual => actual ==
          (if component = "enabled" then decide (Enabled before action)
            else decide (Enabled before action ∧ BoundedState.WithinBounds limits (next before action))))
  | "successor" =>
      probe component phase (fun _ =>
        match destination with
        | none => advanceNext limits entry node
        | some destination => advanceProposalNext limits entry node (nodeCodec.literal destination))
        assignment cache (fun actual =>
          BoundedState.encode (BoundedState.decode ((stateCodec 0).equiv actual).toData) ==
            BoundedState.encode (next before action))
  | _ => throw (IO.userError s!"unknown component {component}")

end CCFRaft.SymbolicTransitionStages

def main (args : List String) : IO Unit := do
  let [index, component, stage, entry] := args |
    throw (IO.userError "usage: SymbolicTransitionStages.lean INDEX frontier|local|advanced|enabled|accepted|successor|check construct|evaluate|serialize|all raw|named; check requires evaluate")
  let some index := index.toNat? | throw (IO.userError "case index must be a natural number")
  let phase ← match stage with
    | "construct" => pure CCFRaft.SymbolicTransitionStages.Phase.construct
    | "evaluate" => pure .evaluate
    | "serialize" => pure .serialize
    | "all" => pure .all
    | _ => throw (IO.userError s!"unknown stage {stage}")
  let named ← match entry with
    | "raw" => pure false
    | "named" => pure true
    | _ => throw (IO.userError s!"unknown entry representation {entry}")
  CCFRaft.SymbolicTransitionStages.run index component phase named
