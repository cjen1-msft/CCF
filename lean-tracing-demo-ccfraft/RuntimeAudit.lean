-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.Runtime.LongTraceSmtProbe
import MachineGenerated.Runtime.NaiveFullStateWitness
import MachineGenerated.Runtime.RetirementConsistencyExamples
import MachineGenerated.Runtime.SuccessorNominationExamples
import MachineGenerated.Runtime.TraceValidation

/-!
# CCFRaft runtime-module proof audit

The legacy runtime validator defines names that collide with the new trace
contract, so its import closure is audited in a separate Lean environment.
-/

run_cmd do
  let env <- Lean.getEnv
  let mut checked := 0
  let mut explicitAxioms := 0
  for (name, info) in env.constants.toList do
    if `CCFRaft |>.isPrefixOf name then
      match info with
      | .thmInfo _ =>
          checked := checked + 1
          let axioms <- Lean.collectAxioms name
          for axiomName in axioms do
            if axiomName != ``propext &&
                axiomName != ``Classical.choice &&
                axiomName != ``Quot.sound then
              throwError
                "theorem {name} depends on unapproved axiom {axiomName}"
      | .axiomInfo _ =>
          explicitAxioms := explicitAxioms + 1
          throwError "CCFRaft declares explicit axiom {name}"
      | _ => pure ()
  if checked = 0 then
    throwError "no CCFRaft runtime theorems were audited"
  Lean.logInfo
    m!"Audited {checked} runtime theorems with {explicitAxioms} explicit axioms."
