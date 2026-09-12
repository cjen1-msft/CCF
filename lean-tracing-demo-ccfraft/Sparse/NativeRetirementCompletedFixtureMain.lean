-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeRetirementCompletedTerm
import Sparse.NativeRetirementEncoding
import Sparse.NativeLogSummaryTerms
import Sparse.NativeLogTerm
import Sparse.NativeScript
import Lean.Data.Json

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeRetirementCompletedFixtures

open Lean NativeSmt NativeEncode

private instance : Bootstrap (Fin 3) :=
  { configuration := {0, 1}, leader := 0, leader_mem := by simp }

def predicate {context : List Ty} (node : Fin 3)
    (current : Term context .int) (members : Term context (.bits 3)) : Term context .bool :=
  retirementCompletedMemberTerm (width := 3) node current members (.free .int 2) (.free .int 3) (.free .int 4)

def fixture (name : String) (log : List (Entry (Fin 3) Nat))
    (node : Fin 3) (commit : Nat) (nested claimed : Bool) : Json :=
  let committedLog := log.take commit
  let current := currentConfigurationAt log commit
  let first := ((allConfigurations committedLog).find?
    (fun configuration => decide (node ∈ configuration.nodes))).map Configuration.index
  let retirement := retirementIndexInLog node committedLog
  let retired := (retiredCommittedIndexInLog node committedLog).map (· - 1)
  let expected := decide (node ∈ retirementCompletedNodes log commit)
  let entries : Expr (.array .int (entryTy 3)) := .free (.array .int (entryTy 3)) 5
  let query : Expr .bool := if nested then
      .forall_ (.bits 3) (implies (.equal (.bound .here) (.bits (encodeBits current.nodes)))
        (.forall_ .int (implies (.equal (.bound .here) (.integer current.index))
          (predicate node (.bound .here) (.bound (.there .here))))))
    else predicate node (.free .int 0) (.free (.bits 3) 1)
  let assertions : List (Expr .bool) := [
    .equal (.free .int 0) (.integer current.index),
    .equal (.free (.bits 3) 1) (.bits (encodeBits current.nodes)),
    .equal (.free .int 2) (.integer (firstMatchValue first)),
    .equal (.free .int 3) (.integer (firstMatchValue retirement)),
    .equal (.free .int 4) (.integer (firstMatchValue retired)),
    .equal entries (.snd (logTerm log)),
    currentConfigurationIndexTerm 3 (.integer log.length) entries (.integer commit) (.free .int 0),
    .equal (.free (.bits 3) 1)
      (currentConfigurationMembersTerm 3 (encodeBits ({0, 1} : Finset (Fin 3))) entries (.free .int 0)),
    retirementIndexTerm 3 (encodeBits ({0, 1} : Finset (Fin 3)))
      (.integer committedLog.length) entries node (.free .int 2) (.free .int 3),
    retiredRecordTerm 3 (.integer committedLog.length) entries node (.free .int 4),
    if claimed then query else .not query]
  Json.mkObj [("name", toJson name), ("script", toJson (renderScript assertions)),
    ("modelCompleted", toJson expected),
    ("expected", toJson (if claimed == expected then "sat" else "unsat"))]

def cases : List Json :=
  let contents : List (List (EntryContent (Fin 3) Nat)) := [
    [],
    [.reconfiguration {}],
    [.reconfiguration {}, .signature],
    [.reconfiguration {}, .signature, .retiredCommitted {0, 1, 2}],
    [.retiredCommitted {2}],
    [.reconfiguration {0, 1, 2}, .signature, .reconfiguration {0, 1}, .retiredCommitted {2}],
    [.reconfiguration {}, .signature, .reconfiguration {0, 1, 2}, .signature, .retiredCommitted {1}],
    [.reconfiguration {0}, .retiredCommitted {1}, .signature],
    [.reconfiguration {}, .reconfiguration {2}, .reconfiguration {}, .reconfiguration {0, 1}],
    [.reconfiguration {0, 2}, .reconfiguration {2}, .reconfiguration {0}, .retiredCommitted {2}]]
  contents.zipIdx.flatMap fun (entries, index) =>
    let log := entries.zipIdx.map fun (content, position) =>
      { term := if position % 2 = 0 then 5 else 0, content }
    (List.finRange 3).flatMap fun node =>
      ([0, 1, 2, 3, 5, 10 ^ 30] : List Nat).flatMap fun commit =>
        [false, true].flatMap fun nested =>
          [false, true].map fun claimed =>
            fixture s!"retirement-completed-{index}-{node.val}-{commit}-{nested}-{claimed}"
              log node commit nested claimed

end CCFRaft.NativeRetirementCompletedFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeRetirementCompletedFixtures.cases).compress
