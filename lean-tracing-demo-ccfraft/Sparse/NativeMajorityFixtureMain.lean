-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeMajorityTerms
import Sparse.NativeScript
import Lean.Data.Json

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeMajorityFixtures

open Lean NativeSmt NativeEncode

private def impliesTerm {context : List Ty} (premise conclusion : Term context .bool) :
    Term context .bool :=
  .or (.not premise) conclusion

private def boundQuery (width : PNat) (body : Term [.bool, .int] .bool) :
    Term [] .bool :=
  .forall_ .int (impliesTerm
    (.equal (.bound .here) (.integer (width.val - 1)))
    (.forall_ .bool (impliesTerm
      (.equal (.bound .here) (.boolean true)) body)))

private def selectedBits {width : PNat} (bits : BitVec width) :
    Term [.bool, .int] (.bits width) :=
  .ite (.bound .here) (.bits bits) (.bits 0)

private def selectedNode {width : PNat} (bits : BitVec width) (node : Fin width) :
    Term [.bool, .int] .bool :=
  .and (.bound .here)
    (.and (.bit (.bits bits) node)
      (.le (.integer node.val) (.bound (.there .here))))

private def boundZero : Term [.bool, .int] .int :=
  .sub (.bound (.there .here)) (.bound (.there .here))

private def fixtureJson (name kind expected : String) (width : Nat)
    (configuration support : Nat) (expectedValue : Json)
    (query : Term [] .bool) : Json :=
  let script := renderScript [query]
  Json.mkObj [
    ("name", toJson name),
    ("kind", toJson kind),
    ("width", toJson width),
    ("configuration", toJson configuration),
    ("support", toJson support),
    ("value", expectedValue),
    ("termBytes", toJson query.syntax.render.utf8ByteSize),
    ("scriptBytes", toJson script.utf8ByteSize),
    ("script", toJson script),
    ("expected", toJson expected)]

private def countFixture {width : PNat} (support : BitVec width) (agrees : Bool) : Json :=
  let expected := (decodeBits support).card
  let proposed := if agrees then expected else expected + 1
  let body : Term [.bool, .int] .bool :=
    .equal (countNodesTerm fun node => selectedNode support node)
      (.add (.integer proposed) boundZero)
  fixtureJson s!"count-{width.val}-{support.toNat}-{agrees}" "count"
    (if agrees then "sat" else "unsat") width.val 0 support.toNat
    (toJson expected) (boundQuery width body)

private def cardinalityFixture {width : PNat} (value : BitVec width)
    (agrees : Bool) : Json :=
  let expected := (decodeBits value).card
  let proposed := if agrees then expected else expected + 1
  let body : Term [.bool, .int] .bool :=
    .equal (bitCardinalityTerm (selectedBits value))
      (.add (.integer proposed) boundZero)
  fixtureJson s!"cardinality-{width.val}-{value.toNat}-{agrees}" "cardinality"
    (if agrees then "sat" else "unsat") width.val value.toNat 0
    (toJson expected) (boundQuery width body)

private def majorityFixture {width : PNat} (label : String)
    (configuration support : BitVec width) (agrees : Bool) : Json :=
  let modelConfiguration : Configuration (Fin width) :=
    { index := 0, nodes := decodeBits configuration }
  let expected := decide
    (hasConfigurationMajority (decodeBits support) modelConfiguration)
  let proposed := if agrees then expected else !expected
  let body : Term [.bool, .int] .bool :=
    .equal
      (configurationMajorityTerm (selectedBits configuration)
        fun node => selectedNode support node)
      (.boolean proposed)
  fixtureJson s!"majority-{label}-{width.val}-{configuration.toNat}-{support.toNat}-{agrees}"
    "majority" (if agrees then "sat" else "unsat") width.val
    configuration.toNat support.toNat (toJson expected) (boundQuery width body)

private def exhaustiveWidthThree : List Json :=
  let width : PNat := ⟨3, by decide⟩
  let masks := (List.range 8).map (BitVec.ofNat 3)
  masks.flatMap fun mask =>
    [countFixture (width := width) mask true, countFixture (width := width) mask false,
      cardinalityFixture (width := width) mask true,
      cardinalityFixture (width := width) mask false] ++
    masks.flatMap fun support =>
      [majorityFixture (width := width) "exhaustive" mask support true,
        majorityFixture (width := width) "exhaustive" mask support false]

private def lowMask (count : Nat) : Nat :=
  2 ^ count - 1

private def selectedWidthCases (width : PNat) : List Json :=
  let all := BitVec.ofNat width (lowMask width.val)
  let singleton := BitVec.ofNat width 1
  let evenCount := width.val - width.val % 2
  let evenConfiguration := BitVec.ofNat width (lowMask evenCount)
  let half := BitVec.ofNat width (lowMask (evenCount / 2))
  let strictConfiguration := if evenCount = 0 then singleton else evenConfiguration
  let strictSupport :=
    if evenCount = 0 then singleton else BitVec.ofNat width (lowMask (evenCount / 2 + 1))
  [
    ("empty", BitVec.ofNat width 0, all),
    ("all", all, all),
    ("singleton", singleton, singleton),
    ("half", evenConfiguration, half),
    ("strict-majority", strictConfiguration, strictSupport)
  ].flatMap fun (label, configuration, support) =>
    [majorityFixture label configuration support true,
      majorityFixture label configuration support false]

def cases : List Json :=
  exhaustiveWidthThree ++
    selectedWidthCases ⟨1, by decide⟩ ++
    selectedWidthCases ⟨17, by decide⟩ ++
    selectedWidthCases ⟨21, by decide⟩ ++
    selectedWidthCases ⟨65, by decide⟩

end CCFRaft.NativeMajorityFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeMajorityFixtures.cases).compress
