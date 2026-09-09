-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.Smt

set_option autoImplicit false

namespace TraceSmt

def listEqual {holes : Nat} {α : Type}
    (equal : α -> α -> Expr holes) : List α -> List α -> Expr holes
  | [], [] => .boolean true
  | left :: lefts, right :: rights =>
      .and (equal left right) (listEqual equal lefts rights)
  | _, _ => .boolean false

theorem listEqual_correct {holes : Nat} {α β : Type}
    (assignment : Fin holes -> Nat) (decode : α -> β)
    (equal : α -> α -> Expr holes)
    (correct : ∀ left right,
      (equal left right).Holds assignment ↔ decode left = decode right)
    (left right : List α) :
    (listEqual equal left right).Holds assignment ↔
      left.map decode = right.map decode := by
  induction left generalizing right with
  | nil => cases right <;> simp [listEqual, Expr.Holds]
  | cons head tail ih =>
      cases right <;> simp [listEqual, Expr.Holds, correct, ih]

end TraceSmt
