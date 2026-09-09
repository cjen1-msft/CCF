-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTraceObservation
import MachineGenerated.SymbolicBounds
import Shared.SymbolicTrace
import Lean

set_option autoImplicit false

namespace CCFRaft.SymbolicTraceObservation.Tests

open Symbolic SymbolicModel

private def bounds : BoundedState.Bounds := ⟨3, 3, 3, 2, 2⟩
private def node : Node := ⟨1, by decide⟩
private def sender : Node := ⟨0, by decide⟩
private def lastNode : Node := ⟨14, by decide⟩
private def entry := freshEntry bounds
private def zero : Assignment := fun _ => 0
private def one : Assignment := fun _ => 1
private def transaction : Expr .nat := .unknown (entryWidth bounds)
private def outOfRange : Assignment :=
  fun index => if index = entryWidth bounds then bounds.transactionCount else 0

private def summary : TraceMessageSummary.Summary Node :=
  .proposeVoteRequest { term := 1, source := lastNode, destination := lastNode }

private def observations : List Observation :=
  [.role node .none, .role node .leader,
   .currentTerm node 0, .currentTerm node 1,
   .logLength node 0, .logLength node 1,
   .queueLength node 0, .queueLength node 1,
   .commitIndex node 0, .commitIndex node 1,
   .allocated node false, .allocated node true,
   .joined node false, .joined node true,
   .submitted transaction false, .submitted transaction true,
   .state (.preVoteStatus node .capable), .state (.preVoteStatus node .enabled),
   .state (.membershipState node .active), .state (.membershipState node .retiredCommitted),
   .state (.retirementIndex node none), .state (.retirementIndex node (some 1)),
   .state (.retirementCommittableIndex node none),
   .state (.retirementCommittableIndex node (some 1)),
   .state (.retiredCommittedIndex node none), .state (.retiredCommittedIndex node (some 1)),
   .state (.retirementCompleted lastNode node false),
   .state (.retirementCompleted lastNode node true),
   .message summary]

#guard (stateWithin bounds entry).eval zero
#guard (stateWithin bounds entry).eval one
#guard (stateWithin bounds entry).eval outOfRange
#guard [zero, one, outOfRange].all fun assignment =>
  observations.all fun observation =>
    (expression bounds entry observation).eval assignment ==
      decide (observation.Holds bounds assignment (evalEntry bounds assignment entry))

-- The same symbolic entry changes every observed field with its assignment.
#guard (expression bounds entry (.role node .none)).eval zero
#guard (expression bounds entry (.role node .leader)).eval one
#guard (expression bounds entry (.currentTerm node 0)).eval zero
#guard (expression bounds entry (.currentTerm node 1)).eval one
#guard (expression bounds entry (.logLength node 0)).eval zero
#guard (expression bounds entry (.logLength node 1)).eval one
#guard (expression bounds entry (.queueLength node 0)).eval zero
#guard (expression bounds entry (.queueLength node 1)).eval one
#guard (expression bounds entry (.commitIndex node 0)).eval zero
#guard (expression bounds entry (.commitIndex node 1)).eval one
#guard (expression bounds entry (.allocated node false)).eval zero
#guard (expression bounds entry (.allocated node true)).eval one
#guard (expression bounds entry (.joined node true)).eval zero
#guard (expression bounds entry (.joined node false)).eval one
#guard (expression bounds entry (.submitted transaction true)).eval zero
#guard (expression bounds entry (.submitted transaction false)).eval one
#guard (expression bounds entry (.state (.preVoteStatus node .enabled))).eval zero
#guard (expression bounds entry (.state (.preVoteStatus node .capable))).eval one
#guard (expression bounds entry (.state (.membershipState node .active))).eval zero
#guard (expression bounds entry (.state (.membershipState node .retiredCommitted))).eval one
#guard (expression bounds entry (.state (.retirementIndex node none))).eval zero
#guard (expression bounds entry (.state (.retirementIndex node (some 1)))).eval one
#guard (expression bounds entry (.state (.retirementCommittableIndex node none))).eval zero
#guard (expression bounds entry (.state (.retirementCommittableIndex node (some 1)))).eval one
#guard (expression bounds entry (.state (.retiredCommittedIndex node none))).eval zero
#guard (expression bounds entry (.state (.retiredCommittedIndex node (some 1)))).eval one
#guard (expression bounds entry (.state (.retirementCompleted lastNode node true))).eval zero
#guard (expression bounds entry (.state (.retirementCompleted lastNode node false))).eval one
#guard !(expression bounds entry (.message summary)).eval zero
#guard (expression bounds entry (.message summary)).eval one

-- Domain checks apply even when observing non-membership, not only membership.
#guard transaction.eval outOfRange == bounds.transactionCount
#guard !(expression bounds entry (.submitted transaction false)).eval outOfRange
#guard !(expression bounds entry (.submitted transaction true)).eval outOfRange
#guard !(Observation.submitted transaction false).Holds bounds outOfRange
  (evalEntry bounds outOfRange entry)

private def zeroTransactions : BoundedState.Bounds := { bounds with transactionCount := 0 }
#guard [true, false].all fun value =>
  !((expression zeroTransactions (freshEntry zeroTransactions)
    (.submitted (.nat 0) value)).eval zero)

private def distinctScalars : Expr (stateCodec bounds.transactionCount).ty :=
  let nodeState : BoundedState.LocalStateData :=
    { BoundedState.encodeLocal freshNodeState with currentTerm := 2, commitIndex := 1 }
  .pair (tableExpr fun n : Node =>
    if n = node then localCodec.option.literal (some nodeState) else tableGet entry.fst n) entry.snd

#guard (stateWithin bounds distinctScalars).eval zero
#guard (expression bounds distinctScalars (.currentTerm node 2)).eval zero
#guard (expression bounds distinctScalars (.commitIndex node 1)).eval zero
#guard !((expression bounds distinctScalars (.currentTerm node 1)).eval zero)
#guard !((expression bounds distinctScalars (.commitIndex node 2)).eval zero)

private def packets : List (Message Node Nat) :=
  [.appendEntriesRequest ⟨1, 0, 0, [⟨1, .transaction 2⟩], 0, sender, node⟩,
   .appendEntriesResponse ⟨1, true, 1, sender, node⟩,
   .requestVoteRequest ⟨1, 0, 0, sender, node⟩,
   .requestVoteResponse ⟨1, true, sender, node⟩,
   .requestPreVote ⟨1, 0, 0, sender, node⟩,
   .requestPreVoteResponse ⟨1, false, sender, node⟩,
   .proposeVoteRequest ⟨1, sender, node⟩]

private def withQueue (queue : Expr queueCodec.ty) : Expr (stateCodec bounds.transactionCount).ty :=
  .pair entry.fst (.pair (tableExpr fun n : Node =>
    if n = node then queue else .nil) entry.snd.snd)

#guard packets.all fun packet =>
  let state := withQueue (queueCodec.literal [packet])
  let observation := Observation.message (TraceMessageSummary.ofMessage packet)
  (stateWithin bounds state).eval zero &&
    (expression bounds state observation).eval zero &&
    decide (observation.Holds bounds zero (evalEntry bounds zero state))

private def selected : Message Node Nat := .proposeVoteRequest ⟨1, sender, node⟩
private def wrongFirst : Message Node Nat := .proposeVoteRequest ⟨0, sender, node⟩
private def otherSource : Message Node Nat := .proposeVoteRequest ⟨0, lastNode, node⟩
private def selectedSummary := Observation.message (TraceMessageSummary.ofMessage selected)
private def queued : Expr (stateCodec bounds.transactionCount).ty :=
  withQueue (.ite (.eq (.unknown (entryWidth bounds + 1)) (.nat 0))
    (queueCodec.literal [wrongFirst, selected])
    (queueCodec.literal [otherSource, selected]))
#guard (stateWithin bounds queued).eval zero
#guard (stateWithin bounds queued).eval one
#guard !(expression bounds queued selectedSummary).eval zero
#guard (expression bounds queued selectedSummary).eval one
#guard !(selectedSummary.Holds bounds zero (evalEntry bounds zero queued))
#guard selectedSummary.Holds bounds one (evalEntry bounds one queued)

-- Directly matches the observes/observe/observe_correct fields of Trace.Semantics.
example (bounds : BoundedState.Bounds) :
    ∀ assignment entry observation,
      BoundedState.WithinBounds bounds (evalEntry bounds assignment entry) ->
      ((expression bounds entry observation).eval assignment = true ↔
        observation.Holds bounds assignment (evalEntry bounds assignment entry)) :=
  expression_correct bounds

end CCFRaft.SymbolicTraceObservation.Tests

run_cmd do
  for axiomName in ← Lean.collectAxioms ``CCFRaft.SymbolicTraceObservation.expression_correct do
    unless axiomName == ``propext || axiomName == ``Classical.choice ||
        axiomName == ``Quot.sound do
      throwError "symbolic observation dispatch depends on unapproved axiom {axiomName}"
