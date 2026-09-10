-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.SymbolicSmt

open Symbolic

def main : IO Unit := do
  let value := (List.range 64).foldl (fun value _ => Expr.add value value)
    (.named 0 0 (.unknown 0))
  let mut baseline : Option Nat := none
  for count in [1, 32, 128] do
    match prepareGroups (List.replicate count [Expr.eq value (.nat 0)]) with
    | .error message => throw (IO.userError message)
    | .ok (_, printed) =>
        if let some expected := baseline then
          unless printed.validatedNodes == expected do
            throw (IO.userError "later groups revalidated unchanged symbolic syntax")
        else
          baseline := some printed.validatedNodes
        IO.println s!"groups={count} validated_nodes={printed.validatedNodes}"
