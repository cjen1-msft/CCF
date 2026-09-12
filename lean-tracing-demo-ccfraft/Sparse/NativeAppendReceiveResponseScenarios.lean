-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Model

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeAppendReceiveResponseFixtures

structure Scenario where
  name : String
  terms : List Nat
  term : Nat := 5
  previous : Nat
  previousTerm : Nat
  entries : List (Entry (Fin 3) Nat) := []
  hint : Bool

def scenarios : List Scenario := [
  { name := "stale", terms := [5, 9], term := 4, previous := 1, previousTerm := 0, hint := false },
  { name := "zero-previous", terms := [5, 9], previous := 0, previousTerm := 99, hint := false },
  { name := "past-end", terms := [5, 9], previous := 4, previousTerm := 2, hint := false },
  { name := "zero-last-term", terms := [5, 0], previous := 1, previousTerm := 4, hint := false },
  { name := "zero-previous-term", terms := [0, 9], previous := 1, previousTerm := 1, hint := true },
  { name := "no-match", terms := [5, 9], previous := 2, previousTerm := 0, hint := true },
  { name := "positive-match", terms := [5, 9, 3], previous := 2, previousTerm := 6, hint := true },
  { name := "unordered", terms := [9, 1, 7, 3], previous := 4, previousTerm := 2, hint := true },
  { name := "match-beyond-cap", terms := [9, 1], previous := 1, previousTerm := 2, hint := true },
  { name := "already-done", terms := [5, 9], previous := 1, previousTerm := 5,
    entries := [{ term := 9, content := .signature }], hint := true },
  { name := "extension", terms := [5], previous := 1, previousTerm := 5,
    entries := [{ term := 9, content := .signature }], hint := true }]

end CCFRaft.NativeAppendReceiveResponseFixtures
