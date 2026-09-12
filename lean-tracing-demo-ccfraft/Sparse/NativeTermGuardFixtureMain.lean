-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeTermGuardEncoding

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeTermGuardFixtures

open Lean NativeSmt NativeEncode

def decodeGuardInstruction (width : PNat) (names : Array String) (value : Json) :
    Except String (FrameInstruction width) := do
  if (<- (<- field value "kind").getStr?) = "updateTerm" then
    fields value ["kind", "source", "destination"]
    return .updateTerm (<- resolve width names (<- field value "source"))
      (<- resolve width names (<- field value "destination"))
  decodeFrameInstruction width names value

def modelFixture (index : Nat) (item : Json) : Except String Json := do
  let input <- decodeDocumentWith decodeGuardInstruction (<- field item "trace")
  let program : EncodeM input.width Unit := do
    initialFrameDomains input.width
    for instruction in input.instructions do
      match instruction with
      | .updateTerm source destination =>
        assertAll (termUpdateGuards (<- get).toColumns source destination)
        return ()
      | other => frameInstruction other
    throw "term guard fixture has no updateTerm instruction"
  let (_, final) <- program.run (initialEncoding input.width input.bootstrap)
  return Json.mkObj [("name", toJson s!"term-guard-model-{index}"),
    ("script", toJson (renderScript final.assertions.toList)), ("expected", <- field item "expected")]

def proposal (term : Nat) (source : Fin 3) : Message (Fin 3) Nat :=
  .proposeVoteRequest { term, source, destination := 1 }

def rawPackets : List (Expr (packetTy 3) × Bool) :=
  [(packetTerm (width := 3) (proposal 3 0), true),
    (packetTerm (width := 3) (proposal 1 0), false),
    (.pair (packetHeaderTerm (width := 3) (3, (0 : Fin 3), (1 : Fin 3)))
      (.inr (.inr (.inl (.pair (.integer (-1)) (.integer 0))))), false),
    (packetTerm (width := 3) (proposal 3 2), false)]

def rawFixture (index : Nat) (packet : Expr (packetTy 3)) (newer : Bool) (head count : Int) : Json :=
  let cell := fun (position : Expr .int) => .select
    (queueCellsTerm (width := 3) 23 (.integer 1) (.integer 0)) position
  let assertions : List (Expr .bool) := [
    .equal (allocated 0) (.boolean true),
    .equal (allocated 1) (.boolean true),
    .equal (read 5 1 (.integer 0)) (.integer 2),
    .equal (.select (.select (.free (.array .int (.array .int .int)) 21) (.integer 1)) (.integer 0))
      (.integer count),
    .equal (.select (.select (.free (.array .int (.array .int .int)) 22) (.integer 1)) (.integer 0))
      (.integer head),
    .equal (cell (.integer head.toNat)) packet]
  let trap := if head < 0 then
    [Term.equal (cell (.integer head)) (packetTerm (width := 3) (proposal 99 0))] else []
  Json.mkObj [("name", toJson s!"term-guard-raw-{index}-{head}-{count}"),
    ("script", toJson (renderScript (assertions ++ trap ++ termUpdateGuards (width := 3) {} 0 1))),
    ("expected", toJson (if newer && 0 < count then "sat" else "unsat"))]

def cases (input : Json) : Except String (List Json) := do
  let models <- ((<- input.getArr?).toList.zipIdx).mapM fun (item, index) => modelFixture index item
  let raw := rawPackets.zipIdx.flatMap fun ((packet, newer), index) =>
    ([-9, 0, 10 ^ 30] : List Int).flatMap fun head =>
      ([-1, 0, 1, 10 ^ 30] : List Int).map fun count => rawFixture index packet newer head count
  return models ++ raw

end CCFRaft.NativeTermGuardFixtures

def main : IO Unit := do
  let input <- (<- IO.getStdin).readToEnd
  let result := do
    let input <- Lean.Json.parse input
    CCFRaft.NativeTermGuardFixtures.cases input
  match result with
  | .ok fixtures => IO.println (Lean.toJson fixtures).compress
  | .error error => throw (IO.userError error)
