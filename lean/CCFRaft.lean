-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs
import CCFRaft.Examples

/-!
# Static CCF Raft safety core

This library is an experimental pure Lean safety model derived from
`tla/consensus/ccfraft.tla`. It proves selected committed-log safety
consequences of `tla/consensus/abs.tla`, not the refinement theorem itself.
-/

#print axioms CCFRaft.reachableProved
#print axioms CCFRaft.reachableStepCommittedLogAppendOnly

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
