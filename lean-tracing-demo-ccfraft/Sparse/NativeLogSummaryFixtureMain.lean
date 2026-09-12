-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeLogSummaryTerms
import Sparse.NativeScript
import Lean.Data.Json

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeLogSummaryFixtures

open Lean NativeSmt NativeEncode

private instance : Bootstrap (Fin 3) :=
  { configuration := {0, 1}, leader := 0, leader_mem := by simp }

def rawEntry (entry : Entry (Fin 3) Nat) (noncanonical : Bool) : Expr (entryTy 3) :=
  let term : Int := if noncanonical && entry.term == 0 then -17 else entry.term
  let content : Expr (contentTy 3) := if noncanonical && entry.content == .transaction 0 then
      Term.inr (Term.inl (Term.integer (-29)))
    else contentTerm entry.content
  .pair (.integer term) content

def predicate {context : List Ty} (kind : Nat) (expectedMembers : Finset (Fin 3))
    (entries : Term context (.array .int (entryTy 3))) (cap selected threshold : Term context .int) :
    Term context .bool :=
  if kind = 0 then boundedSignatureTerm 3 (.free .int 0) entries cap selected
  else if kind = 1 then
    .and (currentConfigurationIndexTerm 3 (.free .int 0) entries cap selected)
      (.equal (currentConfigurationMembersTerm 3 (encodeBits ({0, 1} : Finset (Fin 3))) entries selected)
        (.bits (encodeBits expectedMembers)))
  else nackMatchTerm 3 (.free .int 0) entries cap threshold selected

def fixture (name : String) (log : List (Entry (Fin 3) Nat)) (cap kind mutation : Nat)
    (noncanonical nested : Bool) : Json :=
  let threshold : Nat := if kind = 2 then 0 else if kind = 3 then 3 else 10 ^ 30
  let configuration := currentConfigurationAt log cap
  let expected := if kind = 0 then maxCommittableIndexUpTo log cap
    else if kind = 1 then configuration.index
    else findHighestPossibleMatch log cap threshold
  let selected : Int := match mutation with
    | 1 => -1
    | 2 => expected + 1
    | 3 => if expected = 0 then 1 else 0
    | 4 => 10 ^ 30 + 1
    | _ => expected
  let expectedMembers := if mutation = 5 then
      if 0 ∈ configuration.nodes then configuration.nodes.erase 0 else insert 0 configuration.nodes
    else configuration.nodes
  let cells := log.zipIdx.foldl
    (fun result (entry, index) => Term.store result (.integer index) (rawEntry entry noncanonical))
    (.defaultValue (.array .int (entryTy 3)))
  let tail := entryTerm (width := 3)
    { term := 0, content := if kind = 0 then .signature else .reconfiguration {2} }
  let cells := .store (.store cells (.integer (-1)) tail) (.integer log.length) tail
  let entries : Expr (.array .int (entryTy 3)) := .free (.array .int (entryTy 3)) 1
  let query : Expr .bool := if nested then
      .forall_ (.array .int (entryTy 3)) (implies (.equal (.bound .here) (entries.weaken _))
        (.forall_ .int (implies (.equal (.bound .here) (.free .int 2))
          (.forall_ .int (implies (.equal (.bound .here) (.free .int 3))
            (.forall_ .int (implies (.equal (.bound .here) (.free .int 4))
              (predicate kind expectedMembers (.bound (.there (.there (.there .here))))
                (.bound (.there (.there .here))) (.bound (.there .here)) (.bound .here)))))))))
    else predicate kind expectedMembers entries (.free .int 2) (.free .int 3) (.free .int 4)
  let assertions : List (Expr .bool) := [
    .equal (.free .int 0) (.integer log.length), .equal entries cells,
    .equal (.free .int 2) (.integer cap), .equal (.free .int 3) (.integer selected),
    .equal (.free .int 4) (.integer threshold), query]
  Json.mkObj [("name", toJson name), ("script", toJson (renderScript assertions)),
    ("kind", toJson kind), ("modelIndex", toJson expected),
    ("noncanonical", toJson noncanonical), ("nested", toJson nested),
    ("expected", toJson (if mutation = 0 then "sat" else "unsat"))]

def cases : List Json :=
  let contents : List (List (EntryContent (Fin 3) Nat)) := [
    [], [.signature], [.transaction 0], [.reconfiguration {}], [.retiredCommitted {0, 1, 2}],
    [.signature, .transaction (10 ^ 30), .signature],
    [.reconfiguration {0, 2}, .signature, .reconfiguration {}, .retiredCommitted {1}, .reconfiguration {1}],
    [.signature, .reconfiguration {2}, .transaction 0, .signature, .retiredCommitted {1, 2}]]
  contents.zipIdx.flatMap fun (entries, index) =>
    let log := entries.zipIdx.map fun (content, position) =>
      { term := if position % 2 = 0 then 0 else 5, content }
    ([0, 1, 2, 5, 10 ^ 30] : List Nat).flatMap fun cap =>
      (List.range 5).flatMap fun kind =>
        (List.range (if kind = 1 then 6 else 5)).flatMap fun mutation =>
          [false, true].flatMap fun noncanonical =>
            [false, true].map fun nested =>
              fixture s!"log-summary-{index}-{cap}-{kind}-{mutation}-{noncanonical}-{nested}"
                log cap kind mutation noncanonical nested

end CCFRaft.NativeLogSummaryFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeLogSummaryFixtures.cases).compress
