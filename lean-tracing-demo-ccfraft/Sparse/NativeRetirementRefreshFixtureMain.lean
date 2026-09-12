-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeRetirementRefreshTerms
import Sparse.NativeScript
import Lean.Data.Json

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeRetirementRefreshFixtures

open Lean NativeSmt NativeEncode

private instance : Bootstrap (Fin 3) :=
  { configuration := {0, 1}, leader := 0, leader_mem := by simp }

def different (value : Option Nat) : Option Nat :=
  if value.isSome then none else some 0

def predicate {context : List Ty} (commit retirement : Term context .int)
    (expected : NodeState (Fin 3) Nat) (mutation : Nat) : Term context .bool :=
  let terms := retirementRefreshTerms commit retirement (.free .int 2) (.free .int 3)
  let index := if mutation = 1 then different expected.retirementIndex else expected.retirementIndex
  let signature := if mutation = 2 then different expected.retirementCommittableIndex
    else expected.retirementCommittableIndex
  let retired := if mutation = 3 then different expected.retiredCommittedIndex else expected.retiredCommittedIndex
  let membership := if mutation = 4 then
      if expected.membershipState = .active then MembershipState.retirementOrdered else .active
    else expected.membershipState
  all [
    .equal terms.retirementIndex (optionalTerm Nat.cast index),
    .equal terms.retirementCommittableIndex (optionalTerm Nat.cast signature),
    .equal terms.retiredCommittedIndex (optionalTerm Nat.cast retired),
    .equal terms.membershipState (.integer (membershipCode membership))]

def fixture (name : String) (log : List (Entry (Fin 3) Nat))
    (node : Fin 3) (commit mutation : Nat) (nested : Bool) : Json :=
  let row : NodeState (Fin 3) Nat :=
    { (freshNodeState : NodeState (Fin 3) Nat) with
      log, commitIndex := commit, membershipState := .retiredCommitted,
      retirementIndex := some 99, retirementCommittableIndex := some 88, retiredCommittedIndex := some 77 }
  let retirement := retirementIndexInLog node log
  let signature := (retirement.bind (retirementCommittableIndexInLog log)).map (· - 1)
  let retired := (retiredCommittedIndexInLog node log).map (· - 1)
  let expected := refreshRetirementState node row
  let query : Expr .bool := if nested then
      .forall_ .int (implies (.equal (.bound .here) (.integer (firstMatchValue retirement)))
        (.forall_ .int (implies (.equal (.bound .here) (.integer commit))
          (predicate (.bound .here) (.bound (.there .here)) expected mutation))))
    else predicate (.free .int 0) (.free .int 1) expected mutation
  let assertions : List (Expr .bool) := [
    .equal (.free .int 0) (.integer commit),
    .equal (.free .int 1) (.integer (firstMatchValue retirement)),
    .equal (.free .int 2) (.integer (firstMatchValue signature)),
    .equal (.free .int 3) (.integer (firstMatchValue retired)), query]
  Json.mkObj [("name", toJson name), ("script", toJson (renderScript assertions)),
    ("membership", toJson (membershipCode expected.membershipState)),
    ("activeWithCommittedRetired", toJson
      (expected.membershipState == .active && expected.retiredCommittedIndex.isSome)),
    ("expected", toJson (if mutation = 0 then "sat" else "unsat"))]

def cases : List Json :=
  let contents : List (List (EntryContent (Fin 3) Nat)) := [
    [],
    [.reconfiguration {}],
    [.reconfiguration {}, .signature],
    [.reconfiguration {}, .signature, .retiredCommitted {0, 1, 2}],
    [.retiredCommitted {2}],
    [.reconfiguration {0, 1, 2}, .signature, .reconfiguration {0, 1}, .retiredCommitted {2}],
    [.reconfiguration {}, .signature, .reconfiguration {0, 1, 2}, .signature, .retiredCommitted {1}],
    [.reconfiguration {0}, .retiredCommitted {1}, .signature]]
  contents.zipIdx.flatMap fun (entries, index) =>
    let log := entries.zipIdx.map fun (content, position) =>
      { term := if position % 2 = 0 then 5 else 0, content }
    (List.finRange 3).flatMap fun node =>
      ([0, 1, 2, 3, 5, 10 ^ 30] : List Nat).flatMap fun commit =>
        (List.range 5).flatMap fun mutation =>
          [false, true].map fun nested =>
            fixture s!"retirement-refresh-{index}-{node.val}-{commit}-{mutation}-{nested}"
              log node commit mutation nested

end CCFRaft.NativeRetirementRefreshFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeRetirementRefreshFixtures.cases).compress
