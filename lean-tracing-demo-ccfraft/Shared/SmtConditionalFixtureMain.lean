-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.SmtTests

set_option autoImplicit false

def main (args : List String) : IO UInt32 := do
  unless args == ["--conditional"] do
    (← IO.getStderr).putStrLn "usage: SmtConditionalFixtureMain.lean --conditional"
    return 1
  match TraceSmt.Tests.conditionalFrontier.prepare with
  | .ok prepared => IO.print prepared.toSmt; return 0
  | .error error => (← IO.getStderr).putStrLn error; return 1
