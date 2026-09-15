-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayAppendReceiveFixtures

open CCFRaft CCFRaft.NativeArrayAppendReceiveFixtures

def main : IO Unit := do
  let mut cases : Array Lean.Json := #[]
  for size in [0, 3] do
    for selfRoute in [false, true] do
      for newFollower in [false, true] do
        for content in ([.transaction 7, .signature, .reconfiguration {0, 1},
            .retiredCommitted {1}] : List (EntryContent (Fin 3) Nat)) do
          let source : Fin 3 := 0
          let destination : Fin 3 := if selfRoute then 0 else 1
          let old : Entry (Fin 3) Nat := { term := 2, content := .transaction 7 }
          let entry : Entry (Fin 3) Nat := { term := 5, content }
          let scenario : Scenario := {
            name := s!"direct-{size}-{selfRoute}-{newFollower}"
            log := List.replicate size old, entries := [entry], previous := size,
            previousTerm := if size == 0 then 0 else 2, leaderCommit := size + 1 }
          for conflict in [false, true] do
            cases := cases.push (fixture scenario .follower newFollower 5 source destination true true 0 conflict)
            cases := cases.push (fixture
              { scenario with name := s!"reject-{size}-{selfRoute}-{newFollower}", previous := size + 2 }
              .follower newFollower 5 source destination true true 0 conflict)
  IO.println (Lean.toJson cases).compress
