-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.Proof
import MachineGenerated.BootstrapExamples
import Reduction
import TraceProperties

/-!
# CCFRaft trace validation demo

This target checks the model safety proof and the trace-lowering contract.
-/

#print axioms CCFRaft.reachableConsensusSafety
#print axioms CCFRaft.TraceValidation.lowerTrace_correct

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
  Lean.logInfo m!"Audited {checked} CCFRaft theorems for forbidden axioms."
