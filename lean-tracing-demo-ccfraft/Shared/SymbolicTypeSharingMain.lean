-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.SymbolicTypeSharing
import Shared.SymbolicSharing
import MachineGenerated.SymbolicEntry

set_option autoImplicit false

namespace Symbolic.TypeSharingTests

private def samples : List Ty :=
  [.nat, .bool, .unit, .seq .nat, .seq .bool, .pair .nat .bool,
    .pair .bool .nat, .sum .nat .bool, .sum .bool .nat,
    .pair (.sum .nat .bool) (.seq .unit), .sum (.pair .nat .nat) (.seq .bool)]

#guard samples.all fun a => samples.all fun b =>
  @decide (a = b) (a.sharedDecEq b) == decide (a = b)

private def sharedType (depth : Nat) : Ty :=
  (List.range depth).foldl (fun value _ => .pair value value) .nat

private def agrees (left right : Ty) : Bool :=
  @decide (left = right) (left.sharedDecEq right)

private def checkShared (depth : Nat) : Bool :=
  let payload := sharedType depth
  agrees (.pair payload .nat) (.pair payload .nat) &&
    !(agrees (.pair payload .nat) (.pair payload .bool)) &&
    !(agrees (.sum .nat payload) (.sum .bool payload)) &&
    !(agrees (.pair .nat payload) (.sum .nat payload))

#guard checkShared 4

private def rootOnly (left right : Ty) : Decidable (left = right) :=
  withPtrEqDecEq left right fun _ => inferInstance

private def packedNil (left right : Ty) : Bool :=
  let a : (s : Ty) × Expr s := ⟨.seq left, .nil⟩
  let b : (s : Ty) × Expr s := ⟨.seq right, .nil⟩
  @decide (a = b) (packedExprEq a b)

private def bench (label : String) (count : Nat) (left right : IO.Ref Ty)
    (compare : Ty → Ty → Bool) : IO Unit := do
  let start ← IO.monoMsNow
  for _ in List.range count do
    unless compare (← left.get) (← right.get) do
      throw (IO.userError s!"{label}: equal types rejected")
  IO.println s!"{label} comparisons={count} ms={(← IO.monoMsNow) - start}"

private def compareRoots (label : String) (count : Nat) (build : Nat → Ty) (size : Nat) :
    IO Unit := do
  let sizeA ← IO.mkRef size
  let sizeB ← IO.mkRef size
  let left ← IO.mkRef (build (← sizeA.get))
  let right ← IO.mkRef (build (← sizeB.get))
  let a ← left.get
  let b ← right.get
  let confirmation := withPtrEqDecEq a b fun _ =>
    dbgTrace s!"TYPE_ROOT_FALLBACK:{label}" fun _ => a.sharedDecEq b
  unless @decide (a = b) confirmation do
    throw (IO.userError "fixture roots are unequal")
  -- The packed-expression case is two nil constructors: no bucket or child scan.
  bench s!"{label} root-only" count left right
    (fun a b => @decide (a = b) (rootOnly a b))
  bench s!"{label} recursive" count left right agrees
  bench s!"{label} packed-nil" count left right packedNil

def run : IO Unit := do
  unless checkShared 64 do
    throw (IO.userError "shared type equality or mismatch regression")
  for depth in [12, 16] do
    let payload := sharedType depth
    compareRoots s!"shared-payload-{depth}" 1 (fun slots => vectorTy slots payload) 15
  compareRoots "actual-state-type" 100
    (fun transactions => (CCFRaft.SymbolicModel.stateCodec transactions).ty) 16

end Symbolic.TypeSharingTests

run_cmd do
  for axiomName in ← Lean.collectAxioms ``Symbolic.Ty.sharedDecEq_correct do
    unless axiomName == ``propext || axiomName == ``Classical.choice ||
        axiomName == ``Quot.sound do
      throwError "Ty.sharedDecEq_correct depends on unapproved axiom {axiomName}"

def main : IO Unit := Symbolic.TypeSharingTests.run
