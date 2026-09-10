-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.Smt
import Model
import MachineGenerated.MessageEquality

set_option autoImplicit false

namespace CCFRaft.ControlTracePackets

open TraceSmt

def snapshotValue {holes : Nat} : NatTerm holes -> NatTerm holes
  | .named _ _ _ value => value
  | value => value

@[simp]
theorem snapshotValue_eval {holes : Nat} (assignment : Fin holes -> Nat) (value : NatTerm holes) :
    (snapshotValue value).eval assignment = value.eval assignment := by
  cases value <;> rfl

def equalExpr {holes : Nat}
    (leftTerms rightTerms : Message Node (NatTerm holes) -> NatTerm holes)
    (leftFields rightFields : Message Node (NatTerm holes) -> Nat -> Nat -> NatTerm holes)
    (left right : Message Node (NatTerm holes)) : Expr holes :=
  match left, right with
  | .requestVoteRequest first, .requestVoteRequest second =>
      .and (.boolean (decide (first.source = second.source ∧ first.destination = second.destination)))
        (.and (.equal (leftTerms left) (rightTerms right))
          (.and (.equal (leftFields left 3 first.lastCommittableIndex) (rightFields right 3 second.lastCommittableIndex))
            (.equal (leftFields left 4 first.lastCommittableTerm) (rightFields right 4 second.lastCommittableTerm))))
  | .requestPreVote first, .requestPreVote second =>
      .and (.boolean (decide (first.source = second.source ∧ first.destination = second.destination)))
        (.and (.equal (leftTerms left) (rightTerms right))
          (.and (.equal (leftFields left 3 first.lastCommittableIndex) (rightFields right 3 second.lastCommittableIndex))
            (.equal (leftFields left 4 first.lastCommittableTerm) (rightFields right 4 second.lastCommittableTerm))))
  | .proposeVoteRequest first, .proposeVoteRequest second =>
      .and (.boolean (decide (first.source = second.source ∧ first.destination = second.destination)))
        (.equal (leftTerms left) (rightTerms right))
  | _, _ => .boolean (decide (left = right))

theorem equalExpr_correct {holes : Nat} (assignment : Fin holes -> Nat)
    (leftTerms rightTerms : Message Node (NatTerm holes) -> NatTerm holes)
    (leftFields rightFields : Message Node (NatTerm holes) -> Nat -> Nat -> NatTerm holes)
    (leftCorrect : ∀ message, (leftTerms message).eval assignment = message.term)
    (rightCorrect : ∀ message, (rightTerms message).eval assignment = message.term)
    (leftFieldsCorrect : ∀ message field value, (leftFields message field value).eval assignment = value)
    (rightFieldsCorrect : ∀ message field value, (rightFields message field value).eval assignment = value)
    (left right : Message Node (NatTerm holes)) :
    (equalExpr leftTerms rightTerms leftFields rightFields left right).Holds assignment ↔ left = right := by
  cases left <;> cases right <;>
    simp [equalExpr, Expr.Holds, leftCorrect, rightCorrect, leftFieldsCorrect, rightFieldsCorrect]
  all_goals
    rename_i left right
    cases left
    cases right
    simp
    tauto

def entriesPrefixEqual {holes : Nat}
    (leftTerms rightTerms : Nat -> Nat -> NatTerm holes) :
    Nat -> List (Entry Node (NatTerm holes)) -> List (Entry Node (NatTerm holes)) -> Expr holes
  | _, [], _ | _, _, [] => .boolean true
  | index, left :: leftRest, right :: rightRest =>
      .and (.and (.equal (leftTerms index left.term) (rightTerms index right.term))
        (MessageEquality.contentEqual left.content right.content))
        (entriesPrefixEqual leftTerms rightTerms (index + 1) leftRest rightRest)

theorem entriesPrefixEqual_correct {holes : Nat} (assignment : Fin holes -> Nat)
    (leftTerms rightTerms : Nat -> Nat -> NatTerm holes)
    (leftCorrect : ∀ index term, (leftTerms index term).eval assignment = term)
    (rightCorrect : ∀ index term, (rightTerms index term).eval assignment = term)
    (left right : List (Entry Node (NatTerm holes))) (index : Nat) :
    (left.length = right.length ∧ (entriesPrefixEqual leftTerms rightTerms index left right).Holds assignment) ↔
      left.map (TransactionMapping.mapEntry (NatTerm.eval assignment)) =
        right.map (TransactionMapping.mapEntry (NatTerm.eval assignment)) := by
  induction left generalizing right index with
  | nil => cases right <;> simp [entriesPrefixEqual, Expr.Holds]
  | cons first rest ih =>
      cases right with
      | nil => simp [entriesPrefixEqual, Expr.Holds]
      | cons second remaining =>
          have entry :
              (first.term = second.term ∧ (MessageEquality.contentEqual first.content second.content).Holds assignment) ↔
                TransactionMapping.mapEntry (NatTerm.eval assignment) first =
                  TransactionMapping.mapEntry (NatTerm.eval assignment) second := by
            cases first
            cases second
            simp [MessageEquality.contentEqual_correct, TransactionMapping.mapEntry]
          simp only [entriesPrefixEqual, Expr.Holds, leftCorrect, rightCorrect,
            List.length_cons, Nat.add_right_cancel_iff, List.map_cons, List.cons.injEq]
          rw [entry, ← ih remaining (index + 1)]
          tauto

def appendEqualExpr {holes : Nat} (term : NatTerm holes) (fields : Nat -> Nat -> NatTerm holes)
    (rightTerms : Message Node (NatTerm holes) -> NatTerm holes)
    (rightFields : Message Node (NatTerm holes) -> Nat -> Nat -> NatTerm holes)
    (left : AppendEntriesRequest Node (NatTerm holes)) (right : Message Node (NatTerm holes)) : Expr holes :=
  match right with
  | .appendEntriesRequest other =>
      .and (.boolean (decide (left.source = other.source ∧ left.destination = other.destination)))
        (.and (.equal term (rightTerms right))
          (.and (.equal (fields 0 left.prevLogIndex) (rightFields right 0 other.prevLogIndex))
            (.and (.equal (fields 1 left.prevLogTerm) (rightFields right 1 other.prevLogTerm))
              (.and (.equal (fields 2 left.leaderCommit) (rightFields right 2 other.leaderCommit))
                (.and (.equal (fields 5 left.entries.length) (rightFields right 5 other.entries.length))
                  (entriesPrefixEqual (fun index => fields (6 + index))
                    (fun index => rightFields right (6 + index)) 1 left.entries other.entries))))))
  | _ => .boolean false

theorem appendEqualExpr_correct {holes : Nat} (assignment : Fin holes -> Nat)
    (term : NatTerm holes) (fields : Nat -> Nat -> NatTerm holes)
    (rightTerms : Message Node (NatTerm holes) -> NatTerm holes)
    (rightFields : Message Node (NatTerm holes) -> Nat -> Nat -> NatTerm holes)
    (left : AppendEntriesRequest Node (NatTerm holes))
    (termCorrect : term.eval assignment = left.term)
    (fieldsCorrect : ∀ field value, (fields field value).eval assignment = value)
    (rightCorrect : ∀ message, (rightTerms message).eval assignment = message.term)
    (rightFieldsCorrect : ∀ message field value, (rightFields message field value).eval assignment = value)
    (right : Message Node (NatTerm holes)) :
    (appendEqualExpr term fields rightTerms rightFields left right).Holds assignment ↔
      TransactionMapping.mapMessage (NatTerm.eval assignment) (.appendEntriesRequest left) =
        TransactionMapping.mapMessage (NatTerm.eval assignment) right := by
  cases right <;> simp only [appendEqualExpr, Expr.Holds, termCorrect, fieldsCorrect, rightCorrect,
    rightFieldsCorrect, decide_eq_true_eq]
  all_goals try { simp [TransactionMapping.mapMessage] }
  rename_i other
  rw [entriesPrefixEqual_correct assignment _ _ (fun _ value => fieldsCorrect _ value)
    (fun _ value => rightFieldsCorrect _ _ value)]
  cases left
  cases other
  simp [TransactionMapping.mapMessage]
  tauto

end CCFRaft.ControlTracePackets
