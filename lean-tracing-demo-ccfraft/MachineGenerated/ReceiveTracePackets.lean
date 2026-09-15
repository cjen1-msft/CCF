-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.ControlTracePackets

set_option autoImplicit false

namespace CCFRaft.ReceiveTracePackets

open TraceSmt

def equalExpr {holes : Nat}
    (leftTerms rightTerms : Message Node (NatTerm holes) -> NatTerm holes)
    (leftFields rightFields : Message Node (NatTerm holes) -> Nat -> Nat -> NatTerm holes)
    (left right : Message Node (NatTerm holes)) : Expr holes :=
  let routed := Expr.boolean (decide (left.source = right.source ∧ left.destination = right.destination))
  let term := Expr.equal (leftTerms left) (rightTerms right)
  match left, right with
  | .appendEntriesResponse first, .appendEntriesResponse second =>
      .and routed (.and term
        (.and (.equal (leftFields left 3 first.lastLogIndex) (rightFields right 3 second.lastLogIndex))
          (.equal (leftFields left 6 (if first.success then 1 else 0))
            (rightFields right 6 (if second.success then 1 else 0)))))
  | .requestVoteResponse first, .requestVoteResponse second =>
      .and routed (.and term (.equal (leftFields left 7 (if first.voteGranted then 1 else 0))
        (rightFields right 7 (if second.voteGranted then 1 else 0))))
  | .requestPreVoteResponse first, .requestPreVoteResponse second =>
      .and routed (.and term (.equal (leftFields left 7 (if first.voteGranted then 1 else 0))
        (rightFields right 7 (if second.voteGranted then 1 else 0))))
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
    simp [equalExpr, Expr.Holds, leftCorrect, rightCorrect, leftFieldsCorrect, rightFieldsCorrect,
      Message.term, Message.source, Message.destination]
  all_goals
    rename_i left right
    cases left
    cases right
    simp
    split_ifs <;> simp_all
    all_goals tauto

def termsEqual {holes : Nat} (leftTerms rightTerms : Nat -> Nat -> NatTerm holes) :
    Nat -> List (Entry Node (NatTerm holes)) -> List (Entry Node (NatTerm holes)) -> Expr holes
  | _, [], _ | _, _, [] => .boolean true
  | index, left :: rest, right :: remaining =>
      .and (.equal (leftTerms index left.term) (rightTerms index right.term))
        (termsEqual leftTerms rightTerms (index + 1) rest remaining)

theorem termsEqual_correct {holes : Nat} (assignment : Fin holes -> Nat)
    (leftTerms rightTerms : Nat -> Nat -> NatTerm holes)
    (leftCorrect : ∀ index term, (leftTerms index term).eval assignment = term)
    (rightCorrect : ∀ index term, (rightTerms index term).eval assignment = term)
    (left right : List (Entry Node (NatTerm holes))) (index : Nat) :
    (left.length = right.length ∧ (termsEqual leftTerms rightTerms index left right).Holds assignment) ↔
      left.map Entry.term = right.map Entry.term := by
  induction left generalizing right index with
  | nil => cases right <;> simp [termsEqual, Expr.Holds]
  | cons first rest ih =>
      cases right with
      | nil => simp [termsEqual]
      | cons second remaining =>
          simp only [termsEqual, Expr.Holds, leftCorrect, rightCorrect,
            List.length_cons, Nat.add_right_cancel_iff, List.map_cons, List.cons.injEq, ← ih remaining (index + 1)]
          tauto

end CCFRaft.ReceiveTracePackets
