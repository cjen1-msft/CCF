-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeCommitIndexTerms
import Sparse.NativeScript
import Lean.Data.Json

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeCommitIndexFixtures

open Lean NativeSmt NativeEncode

structure Scenario (width : PNat) where
  name : String
  bootstrap : Finset (Fin width)
  source : Fin width
  sourceMem : source ∈ bootstrap
  log : List (Entry (Fin width) Nat)
  commit : Nat
  currentTerm : Nat
  matchIndex : Fin width -> Nat
  allocated : Finset (Fin width)
  noncanonical : Bool := false

private def impliesTerm {context : List Ty} (premise conclusion : Term context .bool) :
    Term context .bool :=
  .or (.not premise) conclusion

private def rawContent {context : List Ty} {width : PNat}
    (content : EntryContent (Fin width) Nat) (noncanonical : Bool) :
    Term context (contentTy width) :=
  match content with
  | .transaction 0 =>
    if noncanonical then .inr (.inl (.integer (-29))) else contentTerm content
  | _ => contentTerm content

private def rawEntry {context : List Ty} {width : PNat}
    (entry : Entry (Fin width) Nat) (noncanonical : Bool) :
    Term context (entryTy width) :=
  let term : Int := if noncanonical && entry.term == 0 then -17 else entry.term
  .pair (.integer term) (rawContent entry.content noncanonical)

private def rawCells {context : List Ty} {width : PNat}
    (entries : List (Entry (Fin width) Nat)) (noncanonical : Bool)
    (offset : Term context .int) : Term context (.array .int (entryTy width)) :=
  let live := entries.zipIdx.foldl (fun cells (entry, index) =>
    .store cells (.add (.integer index) offset) (rawEntry entry noncanonical))
    (.defaultValue _)
  let retiredTail := entryTerm (width := width)
    { term := 99, content := .retiredCommitted Finset.univ }
  let transactionTail := entryTerm (width := width)
    { term := 88, content := .transaction 777 }
  .store
    (.store
      (.store live (.add (.integer (-1)) offset) retiredTail)
      (.add (.integer entries.length) offset) transactionTail)
    (.add (.integer (entries.length + 7)) offset) retiredTail

private def matchCells {context : List Ty} {width : PNat}
    (matchValues : Fin width -> Nat) (offset : Term context .int) :
    Term context (.array .int .int) :=
  (List.finRange width).foldl (fun cells peer =>
    .store cells (.add (.integer peer.val) offset) (.integer (matchValues peer)))
    (.defaultValue _)

private def boundQuery {width : PNat} (bootstrap : BitVec width)
    (source : Fin width) (log : List (Entry (Fin width) Nat))
    (commit currentTerm current : Nat) (matchValues : Fin width -> Nat)
    (noncanonical : Bool) (selected : Int) : Term [] .bool :=
  .forall_ .int (impliesTerm
    (.equal (.bound .here) (.integer 0))
    (.forall_ .bool (impliesTerm
      (.equal (.bound .here) (.boolean true))
      (let zero : Term [.bool, .int] .int := .bound (.there .here)
       let enabled : Term [.bool, .int] .bool := .bound .here
       let entries :=
         .ite enabled (rawCells log noncanonical zero)
           (.defaultValue (.array .int (entryTy width)))
       let matchIndex :=
         .ite enabled (matchCells matchValues zero)
           (.defaultValue (.array .int .int))
       highestCommitIndexTerm width bootstrap
         (.add (.integer log.length) zero) entries matchIndex source
         (.add (.integer commit) zero) (.add (.integer currentTerm) zero)
         (.add (.integer current) zero) (.add (.integer selected) zero)))))

private def selectedValues (best length : Nat) : List (String × Int) :=
  [("exact", (best : Int))] ++
    (if best = 0 then [] else [("zero", 0)]) ++
    (if best <= 1 then [] else [("nonmaximum", ((best - 1 : Nat) : Int))]) ++
    [("out-of-bounds", ((length + 1 : Nat) : Int)), ("negative", (-1 : Int))]

private def fixtures {width : PNat} (scenario : Scenario width) : List Json :=
  letI : Bootstrap (Fin width) :=
    { configuration := scenario.bootstrap
      leader := scenario.source
      leader_mem := scenario.sourceMem }
  let row : NodeState (Fin width) Nat :=
    { (freshNodeState : NodeState (Fin width) Nat) with
      role := .leader
      currentTerm := scenario.currentTerm
      log := scenario.log
      commitIndex := scenario.commit
      matchIndex := scenario.matchIndex
      isNewFollower := false }
  let state : State (Fin width) Nat :=
    { nodes := NodeStore.ofFinset (insert scenario.source scenario.allocated) fun node =>
        if node = scenario.source then row else freshNodeState
      network := fun _ => []
      submittedTxIds := {}
      hasJoined := scenario.allocated }
  let current := (currentConfigurationAt row.log row.commitIndex).index
  let best := highestCommittableIndex state scenario.source
  let lastSignature := maxCommittableIndex row.log
  let configurationMajorities := (activeConfigurations row).map fun configuration =>
    Json.mkObj [
      ("index", toJson configuration.index),
      ("majority", toJson (decide (hasConfigurationMajority
        (acknowledgingNodes state scenario.source lastSignature) configuration)))]
  (selectedValues best row.log.length).map fun (kind, selected) =>
    let query := boundQuery (encodeBits scenario.bootstrap) scenario.source scenario.log
      scenario.commit scenario.currentTerm current scenario.matchIndex
      scenario.noncanonical selected
    let script := renderScript [query]
    Json.mkObj [
      ("name", toJson s!"commit-index-{scenario.name}-{kind}"),
      ("width", toJson width.val),
      ("variant", toJson kind),
      ("commit", toJson scenario.commit),
      ("current", toJson current),
      ("best", toJson best),
      ("lastSignature", toJson lastSignature),
      ("configurationMajorities", toJson configurationMajorities),
      ("selected", toJson selected),
      ("noncanonical", toJson scenario.noncanonical),
      ("termBytes", toJson query.syntax.render.utf8ByteSize),
      ("scriptBytes", toJson script.utf8ByteSize),
      ("script", toJson script),
      ("expected", toJson (if selected = (best : Int) then "sat" else "unsat"))]

private def widthThreeScenarios : List (Scenario ⟨3, by decide⟩) :=
  let signature (term : Nat) : Entry (Fin 3) Nat := { term, content := .signature }
  let transaction (term tx : Nat) : Entry (Fin 3) Nat :=
    { term, content := .transaction tx }
  let configuration (term : Nat) (nodes : Finset (Fin 3)) : Entry (Fin 3) Nat :=
    { term, content := .reconfiguration nodes }
  let retired (term : Nat) (nodes : Finset (Fin 3)) : Entry (Fin 3) Nat :=
    { term, content := .retiredCommitted nodes }
  let allAt (value : Nat) : Fin 3 -> Nat := fun _ => value
  [
    { name := "bootstrap-empty-log", bootstrap := {0, 1}, source := 0,
      sourceMem := by simp, log := [], commit := 0, currentTerm := 1,
      matchIndex := allAt 0, allocated := {0, 1} },
    { name := "bootstrap-strict-majority", bootstrap := {0, 1, 2}, source := 0,
      sourceMem := by simp, log := [signature 1], commit := 0, currentTerm := 1,
      matchIndex := fun peer => if peer = 1 then 1 else 0, allocated := {0, 1} },
    { name := "bootstrap-exact-half", bootstrap := {0, 1}, source := 0,
      sourceMem := by simp, log := [signature 1], commit := 0, currentTerm := 1,
      matchIndex := allAt 0, allocated := {0, 1} },
    { name := "physical-current", bootstrap := {0}, source := 0,
      sourceMem := by simp, log := [configuration 1 {0, 1, 2}, signature 1],
      commit := 1, currentTerm := 1, matchIndex := allAt 2, allocated := {0} },
    { name := "pending-joint-rejects", bootstrap := {0, 1}, source := 0,
      sourceMem := by simp, log := [configuration 1 {0, 1, 2}, signature 1],
      commit := 0, currentTerm := 1,
      matchIndex := fun peer => if peer = 2 then 2 else 0, allocated := {0} },
    { name := "future-configuration-ignored", bootstrap := {0, 1}, source := 0,
      sourceMem := by simp, log := [signature 1, configuration 1 {1, 2}],
      commit := 0, currentTerm := 1,
      matchIndex := fun peer => if peer = 1 then 1 else 0, allocated := {0} },
    { name := "obsolete-configuration-ignored", bootstrap := {0}, source := 0,
      sourceMem := by simp,
      log := [configuration 1 {1, 2}, configuration 1 {0, 1}, signature 1],
      commit := 2, currentTerm := 1,
      matchIndex := fun peer => if peer = 1 then 3 else 0, allocated := {0} },
    { name := "empty-active-configuration", bootstrap := {0}, source := 0,
      sourceMem := by simp, log := [configuration 1 {}, signature 1],
      commit := 1, currentTerm := 1, matchIndex := allAt 2, allocated := {0} },
    { name := "self-acknowledgement", bootstrap := {0}, source := 0,
      sourceMem := by simp, log := [signature 1], commit := 0, currentTerm := 1,
      matchIndex := allAt 0, allocated := {0} },
    { name := "unallocated-remote-counts", bootstrap := {0, 1}, source := 0,
      sourceMem := by simp, log := [signature 1], commit := 0, currentTerm := 1,
      matchIndex := fun peer => if peer = 1 then 1 else 0, allocated := {0} },
    { name := "source-outside-physical", bootstrap := {0}, source := 0,
      sourceMem := by simp, log := [configuration 1 {1, 2}, signature 1],
      commit := 1, currentTerm := 1,
      matchIndex := fun peer => if peer = 0 then 0 else 2, allocated := {0} },
    { name := "old-commit-inside-log", bootstrap := {0}, source := 0,
      sourceMem := by simp, log := [signature 1, signature 1], commit := 1,
      currentTerm := 1, matchIndex := allAt 2, allocated := {0} },
    { name := "old-commit-beyond-log", bootstrap := {0}, source := 0,
      sourceMem := by simp, log := [signature 1, signature 1], commit := 99,
      currentTerm := 1, matchIndex := allAt 100, allocated := {0} },
    { name := "no-signatures", bootstrap := {0}, source := 0,
      sourceMem := by simp,
      log := [transaction 1 7, configuration 1 {0}, retired 1 {1}],
      commit := 0, currentTerm := 1, matchIndex := allAt 3, allocated := {0} },
    { name := "non-current-unsorted-terms", bootstrap := {0}, source := 0,
      sourceMem := by simp, log := [signature 2, signature 3, signature 1],
      commit := 0, currentTerm := 2, matchIndex := allAt 3, allocated := {0} },
    { name := "no-current-term-signature", bootstrap := {0}, source := 0,
      sourceMem := by simp, log := [signature 3, signature 1],
      commit := 0, currentTerm := 2, matchIndex := allAt 2, allocated := {0} },
    { name := "nonzero-source-with-remote", bootstrap := {1, 2}, source := 2,
      sourceMem := by simp, log := [signature 1], commit := 0, currentTerm := 1,
      matchIndex := fun peer => if peer = 1 then 1 else 0, allocated := {2} },
    { name := "joint-falls-back", bootstrap := {0}, source := 0,
      sourceMem := by simp,
      log := [configuration 1 {0, 1}, signature 1,
        configuration 1 {0, 1, 2}, signature 1],
      commit := 1, currentTerm := 1,
      matchIndex := fun peer => if peer = 1 then 2 else if peer = 2 then 4 else 0,
      allocated := {0} },
    { name := "duplicate-signatures", bootstrap := {0}, source := 0,
      sourceMem := by simp, log := [signature 1, signature 1, signature 1],
      commit := 0, currentTerm := 1, matchIndex := allAt 3, allocated := {0} },
    { name := "signatures-after-configurations", bootstrap := {0}, source := 0,
      sourceMem := by simp,
      log := [configuration 1 {0, 1, 2}, signature 1,
        configuration 1 {0, 1}, signature 1],
      commit := 1, currentTerm := 1,
      matchIndex := fun peer => if peer = 1 then 4 else if peer = 2 then 2 else 0,
      allocated := {0} },
    { name := "content-tag-discrimination", bootstrap := {0}, source := 0,
      sourceMem := by simp,
      log := [retired 1 {0, 1}, transaction 1 0, signature 1, retired 1 {2}],
      commit := 0, currentTerm := 1, matchIndex := allAt 4, allocated := {0} },
    { name := "noncanonical-zero-signature", bootstrap := {0}, source := 0,
      sourceMem := by simp, log := [signature 0], commit := 0, currentTerm := 0,
      matchIndex := allAt 1, allocated := {0}, noncanonical := true },
    { name := "noncanonical-transaction-tag", bootstrap := {0}, source := 0,
      sourceMem := by simp, log := [transaction 0 0, signature 0],
      commit := 0, currentTerm := 0, matchIndex := allAt 2,
      allocated := {0}, noncanonical := true }
  ]

private def lowNodes {width : PNat} (count : Nat) : Finset (Fin width) :=
  Finset.univ.filter fun node => node.val < count

private def wideScenarios (width : PNat) : List (Scenario width) :=
  let source : Fin width := ⟨0, width.pos⟩
  let signature : Entry (Fin width) Nat := { term := 1, content := .signature }
  let allNodes : Finset (Fin width) := Finset.univ
  let evenCount := width.val - width.val % 2
  let evenNodes := lowNodes (width := width) evenCount
  let halfCount := evenCount / 2
  [
    { name := s!"width-{width.val}-self", bootstrap := {source}, source,
      sourceMem := by simp, log := [signature], commit := 0, currentTerm := 1,
      matchIndex := fun _ => 0, allocated := {source} },
    { name := s!"width-{width.val}-all-strict", bootstrap := allNodes, source,
      sourceMem := Finset.mem_univ source, log := [signature], commit := 0,
      currentTerm := 1,
      matchIndex := fun peer => if peer.val < width.val / 2 + 1 then 1 else 0,
      allocated := {source} },
    { name := s!"width-{width.val}-physical-half", bootstrap := {source}, source,
      sourceMem := by simp,
      log := [{ term := 1, content := .reconfiguration evenNodes }, signature],
      commit := 1, currentTerm := 1,
      matchIndex := fun peer => if peer.val < halfCount then 2 else 0,
      allocated := {source} }
  ]

def cases : List Json :=
  widthThreeScenarios.flatMap fixtures ++
    (wideScenarios ⟨1, by decide⟩).flatMap fixtures ++
    (wideScenarios ⟨17, by decide⟩).flatMap fixtures ++
    (wideScenarios ⟨21, by decide⟩).flatMap fixtures

end CCFRaft.NativeCommitIndexFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeCommitIndexFixtures.cases).compress
