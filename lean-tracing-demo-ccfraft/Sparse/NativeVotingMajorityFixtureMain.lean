-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeVotingMajority
import Sparse.NativeLogTerm
import Sparse.NativeScript
import Lean.Data.Json

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeVotingMajorityFixtures

open Lean NativeSmt NativeEncode

private def fixture {width : PNat} [Bootstrap (Fin width)] (name : String)
    (log : List (Entry (Fin width) Nat)) (commit : Nat)
    (support : Finset (Fin width)) (agrees : Bool) : Json :=
  let row : NodeState (Fin width) Nat :=
    { (freshNodeState : NodeState (Fin width) Nat) with log, commitIndex := commit }
  let current := (currentConfiguration row).index
  let expected := (activeConfigurations row).all fun configuration =>
    decide (hasConfigurationMajority support configuration)
  let proposed := if agrees then expected else !expected
  let cells : Term [.bool, .int] (.array .int (entryTy width)) :=
    .store
      (.store (logCellsTerm log log.length) (.integer (-1))
        (entryTerm { term := 99, content := .reconfiguration {} }))
      (.integer log.length) (entryTerm { term := 0, content := .reconfiguration {} })
  let query : Term [] .bool :=
    .forall_ .int (implies
      (.equal (.bound .here) (.integer current))
      (.forall_ .bool (implies
        (.equal (.bound .here) (.boolean true))
        (.equal
          (votingMajorityTerm width (encodeBits INITIAL_CONFIGURATION)
            (.integer log.length) (.bound (.there .here))
            (.ite (.bound .here) cells (.defaultValue _))
            (.ite (.bound .here) (.bits (encodeBits support)) (.bits 0)))
          (.boolean proposed)))))
  let script := renderScript [query]
  Json.mkObj [
    ("name", toJson s!"{name}-commit-{commit}-support-{(encodeBits support).toNat}-{agrees}"),
    ("width", toJson width.val),
    ("current", toJson current),
    ("majority", toJson expected),
    ("script", toJson script),
    ("expected", toJson (if agrees then "sat" else "unsat"))]

private def widthThree : List Json :=
  letI : Bootstrap (Fin (3 : PNat)) :=
    { configuration := {0, 1}, leader := 0, leader_mem := by simp }
  let configuration (nodes : Finset (Fin 3)) : Entry (Fin 3) Nat :=
    { term := 10^30, content := .reconfiguration nodes }
  let signature : Entry (Fin 3) Nat := { term := 0, content := .signature }
  let logs : List (String × List (Entry (Fin 3) Nat)) :=
    [("empty", []), ("signature", [signature]),
      ("future-configuration", [configuration {1, 2}]),
      ("joint", [configuration {1, 2}, signature, configuration {0, 2}]),
      ("empty-configuration", [configuration {}]),
      ("obsolete-configuration", [configuration {}, configuration {0, 1}])]
  logs.flatMap fun (name, log) =>
    [0, 1, 10^30].flatMap fun commit =>
      (List.range 8).flatMap fun mask =>
        [fixture (width := 3) name log commit
            (decodeBits (BitVec.ofNat 3 mask)) true,
          fixture (width := 3) name log commit
            (decodeBits (BitVec.ofNat 3 mask)) false]

private def selectedWidth (width : PNat) : List Json :=
  let first : Fin width := ⟨0, width.property⟩
  let last : Fin width := ⟨width.val - 1, by
    exact Nat.sub_lt width.property (by decide)⟩
  letI : Bootstrap (Fin width) :=
    { configuration := Finset.univ, leader := first, leader_mem := by simp }
  let log : List (Entry (Fin width) Nat) :=
    [{ term := 0, content := .reconfiguration {last} }]
  let cases : List (String × List (Entry (Fin width) Nat) × Nat × Finset (Fin width)) :=
    [("wide-all", [], 0, Finset.univ), ("wide-empty", [], 0, {}),
      ("wide-singleton", log, 1, {last}), ("wide-missing", log, 1, {}),
      ("wide-joint", log, 0, {last})]
  cases.flatMap fun (name, entries, commit, support) =>
    [fixture (width := width) s!"{name}-{width.val}" entries commit support true,
      fixture (width := width) s!"{name}-{width.val}" entries commit support false]

def cases : List Json :=
  widthThree ++ selectedWidth ⟨1, by decide⟩ ++
    selectedWidth ⟨17, by decide⟩ ++ selectedWidth ⟨65, by decide⟩

end CCFRaft.NativeVotingMajorityFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeVotingMajorityFixtures.cases).compress
