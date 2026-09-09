-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import SymbolicTraceObservation
import Shared.SymbolicTrace
import MachineGenerated.SymbolicEntry

set_option autoImplicit false

namespace CCFRaft.BoundedSymbolicTrace

open Symbolic SymbolicModel

abbrev SymbolicAction := Action Node (Expr .nat)
abbrev Instruction := Trace.Instruction SymbolicAction SymbolicTraceObservation.Observation

def evaluateAction (assignment : Assignment) : SymbolicAction -> Action Node Nat
  | .clientRequest node transaction => .clientRequest node (transaction.eval assignment)
  | .signCommittableMessages node => .signCommittableMessages node
  | .changeConfiguration node configuration => .changeConfiguration node configuration
  | .appendRetiredCommitted node => .appendRetiredCommitted node
  | .appendEntries source destination batchEnd => .appendEntries source destination batchEnd
  | .receive source destination => .receive source destination
  | .timeout node => .timeout node
  | .becomePreVoteCandidate node => .becomePreVoteCandidate node
  | .becomeCandidate node => .becomeCandidate node
  | .advanceCommitIndex node => .advanceCommitIndex node
  | .checkQuorum node => .checkQuorum node
  | .updateTerm source destination => .updateTerm source destination
  | .becomeLeader node => .becomeLeader node
  | .requestVote source destination => .requestVote source destination
  | .requestPreVote source destination => .requestPreVote source destination
  | .proposeVote source destination => .proposeVote source destination
  | .advanceCommitIndexAndProposeVote source destination =>
      .advanceCommitIndexAndProposeVote source destination

def Follows (bounds : BoundedState.Bounds) (assignment : Assignment)
    (state : State Node Nat) : List Instruction -> Prop
  | [] => BoundedState.WithinBounds bounds state
  | .action action :: rest =>
      BoundedState.WithinBounds bounds state ∧
        Enabled state (evaluateAction assignment action) ∧
        Follows bounds assignment (next state (evaluateAction assignment action)) rest
  | .observation observation :: rest =>
      BoundedState.WithinBounds bounds state ∧
        observation.Holds bounds assignment state ∧
        Follows bounds assignment state rest

/-- Explicit transaction names follow the structural entry holes. -/
def TransactionDomains (bounds : BoundedState.Bounds) (unknownCount : Nat)
    (assignment : Assignment) : Prop :=
  ∀ index < unknownCount, assignment (entryWidth bounds + index) < bounds.transactionCount

def transactionDomains (bounds : BoundedState.Bounds) (unknownCount : Nat) :
    Expr .bool :=
  ((List.range unknownCount).map fun index =>
    Expr.lt (.unknown (entryWidth bounds + index)) (.nat bounds.transactionCount)).foldr
      Expr.and (.bool true)

theorem transactionDomains_correct (bounds : BoundedState.Bounds) (unknownCount : Nat)
    (assignment : Assignment) :
    (transactionDomains bounds unknownCount).eval assignment = true ↔
      TransactionDomains bounds unknownCount assignment := by
  have all (values : List (Expr .bool)) :
      (values.foldr Expr.and (.bool true)).eval assignment = true ↔
        ∀ value ∈ values, value.eval assignment = true := by
    induction values <;> simp_all [Expr.eval]
  simp [transactionDomains, all, TransactionDomains, Expr.eval]

/-- The executable backend must relate the same assignment to the actual model. -/
def VerifiedEncoder
    (encode : (bounds : BoundedState.Bounds) -> Nat ->
      Expr (stateCodec bounds.transactionCount).ty -> List Instruction ->
        List (Expr .bool)) : Prop :=
  ∀ bounds unknownCount entry instructions assignment,
    Trace.Holds assignment (encode bounds unknownCount entry instructions) ↔
      TransactionDomains bounds unknownCount assignment ∧
        Follows bounds assignment (evalEntry bounds assignment entry) instructions

end CCFRaft.BoundedSymbolicTrace
