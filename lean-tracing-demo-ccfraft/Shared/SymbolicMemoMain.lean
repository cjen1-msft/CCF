-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.SymbolicMemoTests

def main (args : List String) : IO Unit :=
  match args with
  | [] => Symbolic.MemoTests.run
  | [solver] => Symbolic.MemoTests.run (some solver)
  | _ => throw (IO.userError "usage: SymbolicMemoMain.lean [CVC5]")
