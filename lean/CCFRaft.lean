-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Examples
import CCFRaft.Simulation
import CCFRaft.Slice3Proofs

/-!
# CCF Raft slice 1

An executable, directly proved, five-node single-term AppendEntries model.
-/

#print axioms CCFRaft.reachableConsensusSafety
#print axioms CCFRaft.reachableStepCommittedLogMonotonicity
#print axioms CCFRaft.Slice3.reachableConsensusSafety
#print axioms CCFRaft.Slice3.reachableLogMatching
#print axioms CCFRaft.Slice3.reachableMonoLog
#print axioms CCFRaft.Slice3.reachableLeaderCompleteness
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
  Lean.logInfo m!"Audited {checked} CCF Raft slice theorems for sorryAx."
