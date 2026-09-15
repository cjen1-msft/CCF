-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionCompleted

set_option autoImplicit false

namespace CCFRaft.SymbolicTransitionNormalizeTests

open Symbolic SymbolicModel SymbolicTransition

example (body : Unit → Expr .bool) : andLazy (.bool false) body = .bool false := rfl

example (body : Unit → Expr .bool) :
    andLazy (.eq (.nat 2) (.nat 3)) body = .bool false := rfl

example (body : Unit → Expr .bool) :
    andLazy (.bool true) body = .and (.bool true) (body ()) := rfl

example (body : Unit → Expr .bool) :
    andLazy (.named 0 0 (.bool false)) body = .and (.named 0 0 (.bool false)) (body ()) := rfl

def conditional : Expr .bool :=
  andLazy (.eq (.unknown 0) (.nat 0)) (fun _ => .eq (.unknown 1) (.nat 1))

example : conditional.eval (fun index => if index = 0 then 0 else 1) = true := by decide
example : conditional.eval (fun _ => 1) = false := by decide
example : conditional.eval (fun _ => 0) = false := by decide

#eval (show IO Unit from do
  unless decide (filterNodeSet (nodeSetCodec.literal ∅) (fun _ => .eq (.unknown 0) (.nat 0)) =
      nodeSetCodec.literal ∅) do
    throw (IO.userError "empty set filter retained a guarded predicate"))

end CCFRaft.SymbolicTransitionNormalizeTests
