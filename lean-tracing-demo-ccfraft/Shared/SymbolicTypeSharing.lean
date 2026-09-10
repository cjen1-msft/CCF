-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.Symbolic

set_option autoImplicit false

namespace Symbolic

/-- Exact type equality, with pointer shortcuts at every recursive child. -/
def Ty.sharedDecEq (left right : Ty) : Decidable (left = right) :=
  withPtrEqDecEq left right fun _ =>
    match left, right with
    | .pair a b, .pair c d =>
        match a.sharedDecEq c with
        | .isFalse different => .isFalse (fun equal => different (Ty.pair.inj equal).1)
        | .isTrue sameLeft =>
            match b.sharedDecEq d with
            | .isFalse different => .isFalse (fun equal => different (Ty.pair.inj equal).2)
            | .isTrue sameRight => .isTrue (by cases sameLeft; cases sameRight; rfl)
    | .sum a b, .sum c d =>
        match a.sharedDecEq c with
        | .isFalse different => .isFalse (fun equal => different (Ty.sum.inj equal).1)
        | .isTrue sameLeft =>
            match b.sharedDecEq d with
            | .isFalse different => .isFalse (fun equal => different (Ty.sum.inj equal).2)
            | .isTrue sameRight => .isTrue (by cases sameLeft; cases sameRight; rfl)
    | .seq a, .seq b =>
        match a.sharedDecEq b with
        | .isFalse different => .isFalse (fun equal => different (Ty.seq.inj equal))
        | .isTrue same => .isTrue (by cases same; rfl)
    -- A derived-equality wildcard fallback is eagerly lifted before dispatch.
    | .nat, .nat | .bool, .bool | .unit, .unit => .isTrue rfl
    | .nat, .bool | .nat, .unit | .nat, .pair _ _ | .nat, .sum _ _ | .nat, .seq _
    | .bool, .nat | .bool, .unit | .bool, .pair _ _ | .bool, .sum _ _ | .bool, .seq _
    | .unit, .nat | .unit, .bool | .unit, .pair _ _ | .unit, .sum _ _ | .unit, .seq _
    | .pair _ _, .nat | .pair _ _, .bool | .pair _ _, .unit
    | .pair _ _, .sum _ _ | .pair _ _, .seq _
    | .sum _ _, .nat | .sum _ _, .bool | .sum _ _, .unit
    | .sum _ _, .pair _ _ | .sum _ _, .seq _
    | .seq _, .nat | .seq _, .bool | .seq _, .unit
    | .seq _, .pair _ _ | .seq _, .sum _ _ => .isFalse (by intro equal; cases equal)
termination_by left

theorem Ty.sharedDecEq_correct (left right : Ty) :
    @decide (left = right) (left.sharedDecEq right) = decide (left = right) := by
  cases left.sharedDecEq right <;> simp_all

end Symbolic
