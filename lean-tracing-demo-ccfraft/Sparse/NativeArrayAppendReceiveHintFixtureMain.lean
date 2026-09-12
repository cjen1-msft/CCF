-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendReceiveResponseScenarios
import Sparse.NativeArrayAppendReceiveFixtures

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeArrayAppendReceiveHintFixtures

open Lean

def cases : List Json :=
  NativeAppendReceiveResponseFixtures.scenarios.flatMap fun scenario =>
    let receiveScenario : NativeArrayAppendReceiveFixtures.Scenario :=
      { name := scenario.name
        log := scenario.terms.map fun term => { term, content := .signature }
        entries := scenario.entries
        previous := scenario.previous
        previousTerm := scenario.previousTerm
        leaderCommit := 0 }
    ([(0, 1, false), (0, 1, true), (1, 0, false), (1, 0, true), (1, 1, true)] :
      List (Fin 3 × Fin 3 × Bool)).flatMap fun (source, destination, sourcePresent) =>
        [false, true].map fun conflict =>
          NativeArrayAppendReceiveFixtures.fixture receiveScenario .follower true
            scenario.term source destination sourcePresent true 0 conflict

end CCFRaft.NativeArrayAppendReceiveHintFixtures

def main : IO Unit :=
  IO.println (Lean.toJson CCFRaft.NativeArrayAppendReceiveHintFixtures.cases).compress
