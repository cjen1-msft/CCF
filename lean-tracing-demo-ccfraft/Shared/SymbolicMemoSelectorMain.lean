-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.SymbolicMemoSelectorTests

def main (args : List String) : IO Unit :=
  match args with
  | [] => Symbolic.MemoSelectorTests.run
  | [solver] => Symbolic.MemoSelectorTests.run (some solver)
  | _ => throw (IO.userError "usage: SymbolicMemoSelectorMain.lean [CVC5]")
