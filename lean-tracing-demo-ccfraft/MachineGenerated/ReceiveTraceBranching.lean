-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.GuardedReceive

set_option autoImplicit false

namespace CCFRaft.ReceiveTraceBranching

open TraceSmt

def extension {holes : Nat} (before : NodeState Node (NatTerm holes))
    (request : AppendEntriesRequest Node (NatTerm holes)) (condition : Expr holes) :
    Guarded holes (Option (NodeState Node (NatTerm holes) × AppendEntriesResponse Node)) :=
  if request.entries ≠ [] ∧ request.prevLogIndex ≤ before.log.length ∧
      before.log.length < request.prevLogIndex + request.entries.length then
    let log := before.log.take request.prevLogIndex ++ request.entries
    let after := { before with log, commitIndex := committedFromLeader before request log }
    Guarded.branchSmart condition (.pure (some (after, successResponse after request log.length))) (.pure none)
  else .pure none

theorem extension_eval {holes : Nat} (assignment : Fin holes -> Nat)
    (before : NodeState Node (NatTerm holes)) (request : AppendEntriesRequest Node (NatTerm holes))
    (condition : Expr holes)
    (equivalent : condition.Holds assignment ↔ (GuardedReceive.prefixEqual before request).Holds assignment) :
    (extension before request condition).eval assignment = (GuardedReceive.extension before request).eval assignment := by
  simp only [extension, GuardedReceive.extension]
  split <;> simp [Guarded.eval_branchSmart, equivalent]

def accept {holes : Nat} (before : NodeState Node (NatTerm holes))
    (request : AppendEntriesRequest Node (NatTerm holes)) (condition : Expr holes) :
    Guarded holes (Option (NodeState Node (NatTerm holes) × AppendEntriesResponse Node)) :=
  if request.term = before.currentTerm ∧ before.role = .follower ∧
      logOk before request ∧ request.prevLogIndex ≥ before.commitIndex then
    match appendEntriesAlreadyDone? before request with
    | some result => .pure (some result)
    | none =>
        (extension before request condition).bind fun extended =>
          match extended with
          | some result => .pure (some result)
          | none =>
              match conflictAppendEntriesRequest? before request with
              | none => .pure none
              | some truncated =>
                  match appendEntriesAlreadyDone? truncated request with
                  | some result => .pure (some result)
                  | none => GuardedReceive.extension truncated request
  else .pure none

theorem accept_eval {holes : Nat} (assignment : Fin holes -> Nat)
    (before : NodeState Node (NatTerm holes)) (request : AppendEntriesRequest Node (NatTerm holes))
    (condition : Expr holes)
    (equivalent : condition.Holds assignment ↔ (GuardedReceive.prefixEqual before request).Holds assignment) :
    (accept before request condition).eval assignment = (GuardedReceive.accept before request).eval assignment := by
  simp only [accept, GuardedReceive.accept]
  split
  · cases appendEntriesAlreadyDone? before request <;>
      simp [Guarded.eval_bind, extension_eval assignment before request condition equivalent]
    rfl
  · rfl

def handle {holes : Nat} (before : State Node (NatTerm holes)) (source destination : Node) (condition : Expr holes) :
    Guarded holes (Option (State Node (NatTerm holes))) :=
  match takeFirstFrom source (before.network destination) with
  | some (.appendEntriesRequest request, remaining) =>
      if request.destination != destination then .pure none else
        match returnToFollowerState? (before.nodes destination) request with
        | some node => .pure (some { before with nodes := updateNode before.nodes destination node })
        | none =>
            let appended := match rejectAppendEntriesRequest? (before.nodes destination) request with
              | some result => Guarded.pure (some result)
              | none => accept (before.nodes destination) request condition
            appended.map fun result => result.map (ReceiveMapping.finishAppend before destination remaining)
  | _ => GuardedReceive.handle before source destination

def step {holes : Nat} (before : State Node (NatTerm holes)) (source destination : Node) (condition : Expr holes) :
    Guarded holes (GuardedReceive.Result holes) :=
  (handle before source destination condition).map fun result =>
    { enabled := decide (before.allocated destination) && result.isSome, successor := result.getD before }

theorem step_eval {holes : Nat} (assignment : Fin holes -> Nat)
    (before : State Node (NatTerm holes)) (source destination : Node) (condition : Expr holes)
    (request : AppendEntriesRequest Node (NatTerm holes)) (remaining : List (Message Node (NatTerm holes)))
    (selected : takeFirstFrom source (before.network destination) = some (.appendEntriesRequest request, remaining))
    (equivalent : condition.Holds assignment ↔ (GuardedReceive.prefixEqual (before.nodes destination) request).Holds assignment) :
    (step before source destination condition).eval assignment = (GuardedReceive.step before source destination).eval assignment := by
  have handles : (handle before source destination condition).eval assignment =
      (GuardedReceive.handle before source destination).eval assignment := by
    simp only [handle, GuardedReceive.handle, selected]
    split
    · rfl
    · cases returnToFollowerState? (before.nodes destination) request with
      | some => rfl
      | none =>
          simp only [Guarded.eval_map, GuardedReceive.append]
          cases rejectAppendEntriesRequest? (before.nodes destination) request <;>
            simp [accept_eval assignment _ request condition equivalent]
  simp [step, GuardedReceive.step, Guarded.eval_map, handles]

def prefixExpr {holes : Nat} (length : NatTerm holes)
    (positions : Nat -> NatTerm holes) (leftTerms rightTerms : Nat -> Nat -> NatTerm holes) :
    Nat -> List (Entry Node (NatTerm holes)) -> List (Entry Node (NatTerm holes)) -> Expr holes
  | _, [], _ | _, _, [] => .boolean true
  | index, left :: rest, right :: remaining =>
      .and (.not (.and (.not (.lessThan length (positions index)))
        (.not (.and (.equal (leftTerms index left.term) (rightTerms index right.term))
          (MessageEquality.contentEqual left.content right.content)))))
        (prefixExpr length positions leftTerms rightTerms (index + 1) rest remaining)

theorem prefix_correct {holes : Nat} (assignment : Fin holes -> Nat)
    (length : NatTerm holes) (positions : Nat -> NatTerm holes)
    (leftTerms rightTerms : Nat -> Nat -> NatTerm holes)
    (positionsCorrect : ∀ index, (positions index).eval assignment = index)
    (leftCorrect : ∀ index term, (leftTerms index term).eval assignment = term)
    (rightCorrect : ∀ index term, (rightTerms index term).eval assignment = term)
    (left right : List (Entry Node (NatTerm holes))) (index : Nat)
    (bounded : index + left.length ≤ length.eval assignment + 1) :
    (left.length = right.length ∧ (prefixExpr length positions leftTerms rightTerms index left right).Holds assignment) ↔
      left.map (TransactionMapping.mapEntry (NatTerm.eval assignment)) =
        right.map (TransactionMapping.mapEntry (NatTerm.eval assignment)) := by
  induction left generalizing right index with
  | nil => cases right <;> simp [prefixExpr, Expr.Holds]
  | cons first rest ih =>
      cases right with
      | nil => simp [prefixExpr]
      | cons second remaining =>
          have within : index ≤ length.eval assignment := by simp only [List.length_cons] at bounded; omega
          have tailBound : index + 1 + rest.length ≤ length.eval assignment + 1 := by
            simp only [List.length_cons] at bounded
            omega
          have entry :
              (first.term = second.term ∧ (MessageEquality.contentEqual first.content second.content).Holds assignment) ↔
                TransactionMapping.mapEntry (NatTerm.eval assignment) first =
                  TransactionMapping.mapEntry (NatTerm.eval assignment) second := by
            cases first
            cases second
            simp [MessageEquality.contentEqual_correct, TransactionMapping.mapEntry]
          simp only [prefixExpr, Expr.Holds, positionsCorrect, leftCorrect, rightCorrect, not_lt.mpr within,
            not_false_eq_true, true_and, not_not, List.length_cons, Nat.add_right_cancel_iff,
            List.map_cons, List.cons.injEq, entry, ← ih remaining (index + 1) tailBound]
          tauto

end CCFRaft.ReceiveTraceBranching
