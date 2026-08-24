-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs
import CCFRaft.Simulation
import CCFRaft.TraceValidation

/-!
# CCF Raft arbitrary-term reconfiguration proof

An executable, directly proved, 15-node arbitrary-term Raft model with
arbitrary nonempty configuration changes.
-/

#print axioms CCFRaft.reachableConsensusSafety
#print axioms CCFRaft.reachableSystemInductiveInvariant
#print axioms CCFRaft.reachableCommittedLogsPrefix
#print axioms CCFRaft.reachableLogMatching
#print axioms CCFRaft.reachableMonoLog
#print axioms CCFRaft.reachableElectionSafety
#print axioms CCFRaft.reachableLeaderCompleteness
#print axioms CCFRaft.reachableCommittedFrontierIsSignature
#print axioms CCFRaft.ReconfigurationProof.reachableConsensusSafety
#print axioms CCFRaft.ReconfigurationProof.reachableSystemInductiveInvariant
#print axioms CCFRaft.ReconfigurationProof.reachableCommittedLogsPrefix
#print axioms CCFRaft.ReconfigurationProof.reachableLogMatching
#print axioms CCFRaft.ReconfigurationProof.reachableMonoLog
#print axioms CCFRaft.ReconfigurationProof.reachableElectionSafety
#print axioms CCFRaft.ReconfigurationProof.reachableLeaderCompleteness
#print axioms CCFRaft.ReconfigurationProof.reachableCommittedFrontierIsSignature
#print axioms CCFRaft.Simulation.materializeComplete
#print axioms CCFRaft.Simulation.candidateChoicesComplete
#print axioms CCFRaft.TraceValidation.exactRunReachable

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
          if axioms.contains ``Lean.trustCompiler then
            throwError "theorem {name} depends on Lean.trustCompiler"
          if axioms.contains ``Lean.ofReduceBool then
            throwError "theorem {name} depends on Lean.ofReduceBool"
      | _ => pure ()
  if checked = 0 then
    throwError "no CCFRaft theorems were audited"
  Lean.logInfo m!"Audited {checked} CCF Raft theorems for forbidden axioms."
