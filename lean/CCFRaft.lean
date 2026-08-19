-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs
import CCFRaft.Simulation

/-!
# CCF Raft arbitrary-term proof

An executable, directly proved, five-node arbitrary-term Raft model.
-/

#print axioms CCFRaft.reachableConsensusSafety
#print axioms CCFRaft.reachableLogMatching
#print axioms CCFRaft.reachableMonoLog
#print axioms CCFRaft.reachableLeaderCompleteness
#print axioms CCFRaft.Simulation.materializeComplete
#print axioms CCFRaft.Simulation.candidateChoicesComplete

run_cmd do
  let env <- Lean.getEnv
  let mut checked := 0
  for (name, info) in env.constants.toList do
    if `CCFRaft |>.isPrefixOf name then
      match info with
      | .thmInfo _ =>
          checked := checked + 1
          let axioms <- Lean.collectAxioms name
          if axioms.contains ``sorryAx then
            throwError "theorem {name} depends on sorryAx"
      | _ => pure ()
  if checked = 0 then
    throwError "no CCFRaft theorems were audited"
  Lean.logInfo m!"Audited {checked} CCF Raft theorems for sorryAx."
