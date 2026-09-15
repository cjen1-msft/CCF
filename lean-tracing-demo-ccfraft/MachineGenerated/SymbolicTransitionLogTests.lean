-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionRetirement
import MachineGenerated.SymbolicTransitionEvaluation

set_option autoImplicit false

namespace CCFRaft.SymbolicTransitionLogTests

open Symbolic SymbolicModel SymbolicTransition

local instance : NeZero NODE_COUNT := ⟨by decide⟩

def assignment : Assignment := fun _ => 3

def logAssertions : List (Expr .bool) :=
  let entries : List (Entry Node Nat) :=
    [⟨2, .signature⟩, ⟨2, .transaction 0⟩, ⟨3, .retiredCommitted {0, 7}⟩,
      ⟨3, .signature⟩, ⟨4, .retiredCommitted {7, 8}⟩, ⟨4, .reconfiguration {1}⟩]
  let log := logCodec.literal entries
  [ .eq (entryAtExpr log (.nat 0)) (entryCodec.option.literal none),
    .eq (entryAtExpr log (.nat 2)) (entryCodec.option.literal (some ⟨2, .transaction 0⟩)),
    .eq (entryAtExpr log (.nat 7)) (entryCodec.option.literal none),
    .eq (termAtExpr log (.nat 0)) (.nat 0),
    .eq (termAtExpr log (.nat 4)) (.nat 3),
    .eq (termAtExpr log (.nat 7)) (.nat 0),
    signatureAtExpr log (.nat 1),
    .not (signatureAtExpr log (.nat 0)),
    .not (signatureAtExpr log (.nat 2)),
    .not (signatureAtExpr log (.nat 7)),
    .eq (maxCommittableExpr 6 log) (.nat 4),
    .eq (maxCommittableExpr 0 .nil) (.nat 0),
    .eq (maxCommittableExpr 2 (logCodec.literal [⟨1, .transaction 0⟩, ⟨1, .reconfiguration ∅⟩])) (.nat 0),
    .eq (committedRetiredNodesExpr 6 (.unknown 0) (.nat 1) log) (nodeSetCodec.literal {0, 7}),
    .eq (committedRetiredNodesExpr 6 (.nat 5) (.nat 1) log) (nodeSetCodec.literal {0, 7, 8}),
    .eq (committedRetiredNodesExpr 6 (.nat 2) (.nat 1) log) (nodeSetCodec.literal ∅),
    .eq (committedRetiredNodesExpr 0 (.nat 9) (.nat 1) .nil) (nodeSetCodec.literal ∅),
    .eq (committedRetiredNodesExpr 1 (.nat 0) (.nat 0)
      (logCodec.literal [⟨1, .retiredCommitted {7}⟩])) (nodeSetCodec.literal {7}),
    .eq (maximumExpr (.unknown 0) (.nat 1)) (.unknown 0),
    .eq (maximumExpr (.unknown 0) (.unknown 0)) (.unknown 0),
    .eq (rangeExpr 5 (.unknown 0)) (Codec.nat.list.literal [0, 1, 2]) ]

def oldState (log : List (Entry Node Nat)) (commit : Nat) : NodeState Node Nat :=
  { (freshNodeState : NodeState Node Nat) with
    role := .leader
    currentTerm := 4
    log := log
    commitIndex := commit
    sentIndex := fun node => node.val
    matchIndex := fun node => node.val + 1
    isNewFollower := false
    votedFor := some 7
    votesGranted := {0, 7}
    preVotesGranted := {1, 8}
    membershipState := .retiredCommitted
    retirementIndex := some 99
    retirementCommittableIndex := some 98
    retiredCommittedIndex := some 97 }

def refreshCases : List (List (Entry Node Nat) × Nat × MembershipState) :=
  let configuration : Entry Node Nat := ⟨2, .reconfiguration {1}⟩
  let signature : Entry Node Nat := ⟨2, .signature⟩
  let retired : Entry Node Nat := ⟨2, .retiredCommitted {0}⟩
  [ ([], 0, .active),
    ([configuration], 0, .retirementOrdered),
    ([configuration, signature], 0, .retirementSigned),
    ([configuration, signature], 1, .retirementCompleted),
    ([configuration, signature, retired], 2, .retirementCompleted),
    ([configuration, signature, retired], 3, .retiredCommitted),
    ([signature, configuration], 0, .retirementOrdered),
    ([retired], 1, .active),
    ([configuration, retired, retired], 1, .retirementCompleted),
    ([configuration, retired, retired], 2, .retiredCommitted),
    ([configuration, ⟨3, .reconfiguration {0, 1}⟩], 0, .retirementOrdered) ]

def solverAssertions : List (Expr .bool) :=
  let log : Expr logCodec.ty := .cons (.pair (.unknown 0) (contentCodec.literal .signature)) .nil
  let retirement := Expr.inr (.unknown 0)
  let committable := Expr.inr (Expr.add (.unknown 0) (.nat 1))
  let retired := filterIndexExpr (.inr (.add (.unknown 0) (.nat 2))) (.unknown 1)
  [ .eq (.unknown 0) (.nat 1), .eq (.unknown 1) (.nat 3),
    .eq (maxCommittableExpr 1 log) (.nat 1),
    .eq (termAtExpr log (.nat 1)) (.unknown 0),
    .eq (committedRetiredNodesExpr 1 (.nat 1) (.nat 1)
      (logCodec.literal [⟨1, .retiredCommitted {0}⟩])) (nodeSetCodec.literal {0}),
    .eq (membershipExpr retirement committable retired (.unknown 1))
      (membershipCodec.literal .retiredCommitted),
    .eq retired (Codec.nat.option.literal (some 3)) ]

def run : IO Unit := do
  for (formula, index) in logAssertions.zipIdx do
    unless formula.evalMemo assignment do throw (IO.userError s!"log regression {index} failed")
  for ((entries, commit, phase), index) in refreshCases.zipIdx do
    let before := oldState entries commit
    let value := localCodec.literal (BoundedState.encodeLocal before)
    let actual := decodeMemo localCodec assignment
      (refreshRetirementExpr entries.length (nodeCodec.literal 0) value)
    let expected := BoundedState.encodeLocal (refreshRetirementState 0 before)
    unless decide (actual = expected) do
      throw (IO.userError s!"retirement refresh case {index} differs from Model")
    unless decide (actual.membershipState = phase) do
      throw (IO.userError s!"retirement refresh phase {index} incorrect")
  IO.println s!"{logAssertions.length} log regressions and {refreshCases.length} complete Model retirement refresh comparisons passed"

end CCFRaft.SymbolicTransitionLogTests
