-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeNatSetInsert
import Sparse.NativeScript
import Lean.Data.Json

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeNatSetInsertFixtures

open Lean NativeSmt NativeEncode

private def rawCells {context : List Ty} (positions : List Int) :
    Term context (.array .int (.bits 1)) :=
  positions.foldl (fun cells index => .store cells (.integer index) (.bits 1))
    (.defaultValue _)

private def fixture (index limit value : Nat) (positions : List Int) (agrees : Bool) : Json :=
  let oldSet :=
    ((positions.filter fun position => 0 <= position && position < (limit : Int)).map
      Int.toNat).toFinset
  let expected := insert value oldSet
  let points : List Int := [-1, 0, 1, 2, 3, 4, limit, (limit : Int) + 1,
    value, (value : Int) + 1]
  let observations : List (Term [.bool, .int] .bool) :=
    points.map fun point =>
      .equal (natSetMember 2 3 (.integer point))
        (.boolean (decide (0 <= point /\ point.toNat ∈ expected)))
  let accepted : Term [.bool, .int] .bool :=
    natSetInsertConstraints 0 1 2 3 (.bound (.there .here))
  let query : Term [] .bool :=
    .forall_ .int (implies (.equal (.bound .here) (.integer value))
      (.forall_ .bool (implies (.equal (.bound .here) (.boolean true))
        (all (
          [.equal (.free .int 1) (.integer limit),
            .equal (.free (.array .int (.bits 1)) 0)
              (.ite (.bound .here) (rawCells positions) (.defaultValue _)),
            accepted,
            .equal (.select (.free (.array .int (.bits 1)) 2) (.integer (-1))) (.bits 1),
            .equal (.select (.free (.array .int (.bits 1)) 2) (.free .int 3)) (.bits 1)] ++
          (if agrees then observations else
            [.equal (natSetMember 2 3 (.integer 0)) (.boolean (!decide (0 ∈ expected)))]))))))
  Json.mkObj [
    ("name", toJson s!"nat-set-insert-{index}-{agrees}"),
    ("limit", toJson limit), ("value", toJson value),
    ("script", toJson (renderScript [query])),
    ("expected", toJson (if agrees then "sat" else "unsat"))]

private def naiveResurrection (gapPresent : Bool) : Json :=
  let query : Expr .bool := all [
    .equal (.free (.array .int (.bits 1)) 0) (rawCells [3]),
    .equal (.free .int 1) (.integer 2),
    .equal (.free (.array .int (.bits 1)) 2)
      (.store (.free (.array .int (.bits 1)) 0) (.integer 5) (.bits 1)),
    .equal (.free .int 3) (.integer 6),
    .equal (natSetMember 2 3 (.integer 3)) (.boolean gapPresent)]
  Json.mkObj [
    ("name", toJson s!"naive-store-resurrects-gap-{gapPresent}"),
    ("script", toJson (renderScript [query])),
    ("expected", toJson (if gapPresent then "sat" else "unsat"))]

def cases : List Json :=
  let scenarios : List (Nat × Nat × List Int) :=
    [0, 2, 10^30].flatMap fun (limit : Nat) =>
    [0, 1, 5, 10^30].flatMap fun (value : Nat) =>
      let variants : List (List Int) :=
        [[], [-1, 0, 1, limit, (limit : Int) + 1], [(limit : Int) + 1]]
      variants.map fun positions => (limit, value, positions)
  (scenarios.zipIdx.flatMap fun ((limit, value, positions), index) =>
    [fixture index limit value positions true, fixture index limit value positions false]) ++
    [naiveResurrection false, naiveResurrection true]

end CCFRaft.NativeNatSetInsertFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeNatSetInsertFixtures.cases).compress
