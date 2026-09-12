-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeRetirementRefreshConstraints
import Sparse.NativeLogTerm
import Sparse.NativeScript
import Lean.Data.Json

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeRetirementRefreshConstraintFixtures

open Lean NativeSmt NativeEncode

private instance : Bootstrap (Fin 3) :=
  { configuration := {0, 1}, leader := 0, leader_mem := by simp }

def different (value : Option Nat) : Option Nat :=
  if value.isSome then none else some 0

def predicate {context : List Ty} (node : Fin 3)
    (length : Term context .int) (entries : Term context (.array .int (entryTy 3)))
    (commit : Term context .int) (expected : NodeState (Fin 3) Nat) (mutation : Nat) :
    Term context .bool :=
  let terms := retirementRefreshTerms commit (.free .int 3) (.free .int 4) (.free .int 5)
  let retirement := if mutation = 1 then different expected.retirementIndex else expected.retirementIndex
  let signature := if mutation = 2 then different expected.retirementCommittableIndex
    else expected.retirementCommittableIndex
  let retired := if mutation = 3 then different expected.retiredCommittedIndex else expected.retiredCommittedIndex
  let membership := if mutation = 4 then
      if expected.membershipState = .active then MembershipState.retirementOrdered else .active
    else expected.membershipState
  all [
    retirementRefreshConstraints 3 (encodeBits ({0, 1} : Finset (Fin 3))) length entries node
      (.free .int 2) (.free .int 3) (.free .int 4) (.free .int 5),
    .equal terms.retirementIndex (optionalTerm Nat.cast retirement),
    .equal terms.retirementCommittableIndex (optionalTerm Nat.cast signature),
    .equal terms.retiredCommittedIndex (optionalTerm Nat.cast retired),
    .equal terms.membershipState (.integer (membershipCode membership))]

def fixture (name : String) (log : List (Entry (Fin 3) Nat)) (node : Fin 3)
    (commit mutation : Nat) (nested : Bool) : Json :=
  let row : NodeState (Fin 3) Nat :=
    { (freshNodeState : NodeState (Fin 3) Nat) with
      log, commitIndex := commit, membershipState := .retiredCommitted,
      retirementIndex := some 99, retirementCommittableIndex := some 88, retiredCommittedIndex := some 77 }
  let first := ((allConfigurations log).find?
    (fun configuration => decide (node ∈ configuration.nodes))).map Configuration.index
  let retirement := retirementIndexInLog node log
  let signature := (retirement.bind (retirementCommittableIndexInLog log)).map (· - 1)
  let retired := (retiredCommittedIndexInLog node log).map (· - 1)
  let expected := refreshRetirementState node row
  let indices := ([first, retirement, signature, retired].zipIdx).map fun (choice, index) =>
    firstMatchValue (if mutation = 5 + index then different choice else choice)
  let query : Expr .bool := if nested then
      .forall_ (logTy 3) (implies
        (.equal (.bound .here) (.pair (.free .int 0) (.free (.array .int (entryTy 3)) 1)))
        (.forall_ .int (implies (.equal (.bound .here) (.free .int 6))
          (predicate node (.fst (.bound (.there .here))) (.snd (.bound (.there .here)))
            (.bound .here) expected mutation))))
    else predicate node (.free .int 0) (.free (.array .int (entryTy 3)) 1) (.free .int 6)
      expected mutation
  let trap := entryTerm (width := 3) { term := 0, content := .reconfiguration {node} }
  let cells := .store (.store (.snd (logTerm log)) (.integer (-7)) trap) (.integer (10 ^ 30)) trap
  let assertions : List (Expr .bool) := [
    .equal (.free .int 0) (.integer log.length),
    .equal (.free (.array .int (entryTy 3)) 1) cells,
    .equal (.free .int 6) (.integer commit)] ++
    (indices.zipIdx.map fun (value, index) => .equal (.free .int (2 + index)) (.integer value)) ++ [query]
  Json.mkObj [("name", toJson name), ("script", toJson (renderScript assertions)),
    ("membership", toJson (membershipCode expected.membershipState)),
    ("activeWithCommittedRetired", toJson
      (expected.membershipState == .active && expected.retiredCommittedIndex.isSome)),
    ("expected", toJson (if mutation = 0 then "sat" else "unsat"))]

def cases : List Json :=
  let contents : List (List (EntryContent (Fin 3) Nat)) := [
    [], [.reconfiguration {}], [.reconfiguration {}, .signature],
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
        (List.range 9).flatMap fun mutation =>
          [false, true].map fun nested =>
            fixture s!"retirement-constraints-{index}-{node.val}-{commit}-{mutation}-{nested}"
              log node commit mutation nested

end CCFRaft.NativeRetirementRefreshConstraintFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeRetirementRefreshConstraintFixtures.cases).compress
