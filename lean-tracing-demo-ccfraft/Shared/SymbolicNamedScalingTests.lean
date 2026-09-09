-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.SymbolicSmt

set_option autoImplicit false

namespace Symbolic.NamedScalingTests

def state : Nat -> Expr (.pair .nat .nat)
  | 0 => .named 0 0 (.pair (.unknown 0) (.unknown 1))
  | depth + 1 =>
      let previous := state depth
      .named (depth + 1) 0
        (.pair (.add previous.fst (.nat 1)) (.add previous.snd (.nat 1)))

def formula (depth : Nat) : Except String String :=
  scriptGroups (List.replicate (depth + 1) [] ++
    [[.eq (state depth).fst (.nat depth)]])

end Symbolic.NamedScalingTests

def main (args : List String) : IO Unit := do
  let parseDepth := fun value : String =>
    match value.toNat? with
    | some depth => pure depth
    | none => throw (IO.userError "depth must be a natural number")
  if let ["--smt", value] := args then
    let depth ← parseDepth value
    match Symbolic.NamedScalingTests.formula depth with
    | .ok text => IO.print text
    | .error message => throw (IO.userError message)
    return
  let depths ← if args.isEmpty then pure [16, 32, 64] else args.mapM parseDepth
  for depth in depths do
    let started ← IO.monoMsNow
    let text ← match Symbolic.NamedScalingTests.formula depth with
      | .ok text => pure text
      | .error message => throw (IO.userError message)
    if text.utf8ByteSize > 200000 then
      throw (IO.userError s!"named-state depth {depth} produced {text.utf8ByteSize} bytes")
    IO.println s!"depth={depth} bytes={text.utf8ByteSize} ms={(← IO.monoMsNow) - started}"
