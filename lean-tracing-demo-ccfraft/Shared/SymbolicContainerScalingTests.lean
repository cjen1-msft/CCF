-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.BoundedContainer
import Shared.SymbolicSmt

set_option autoImplicit false

namespace Symbolic.Container.ScalingTests

def input (capacity : Nat) : Expr (.seq .nat) :=
  .take (.unknown 0) (.ofList ((List.range capacity).map fun i => .unknown (i + 1)))

def formula (capacity : Nat) : Expr .bool :=
  let selected := takeFirst (fun value => .eq value (.nat 7)) capacity (input capacity)
  .eq selected selected

end Symbolic.Container.ScalingTests

def main (args : List String) : IO Unit := do
  match args with
  | ["--smt", value] =>
      let some capacity := value.toNat?
        | throw (IO.userError "capacity must be a natural number")
      IO.print (Symbolic.script [Symbolic.Container.ScalingTests.formula capacity])
  | [] =>
      for capacity in [16, 32] do
        let text := Symbolic.script [Symbolic.Container.ScalingTests.formula capacity]
        if text.utf8ByteSize > 200000 then
          throw (IO.userError s!"queue capacity {capacity} produced {text.utf8ByteSize} bytes")
        IO.println s!"capacity={capacity} bytes={text.utf8ByteSize}"
  | _ => throw (IO.userError "usage: SymbolicContainerScalingTests.lean [--smt CAPACITY]")
