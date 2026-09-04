-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.Proof
import MachineGenerated.BootstrapExamples
import MachineGenerated.PreVoteExamples
import MachineGenerated.CheckQuorumExamples
import MachineGenerated.RetirementExamples
import MachineGenerated.SuccessorNominationExamples
import TraceProperties

/-!
# CCFRaft trace validation demo

This target checks the model safety proof and the trace-lowering contract.
-/

#print axioms CCFRaft.reachableConsensusSafety
#print axioms CCFRaft.MachineGenerated.lowerAction_correct
#print axioms CCFRaft.TraceValidation.lowerTrace_correct
#print axioms CCFRaft.becomePreVoteCandidatePreservesSystemInductiveInvariant
#print axioms CCFRaft.becomeCandidatePreservesSystemInductiveInvariant
#print axioms CCFRaft.requestPreVotePreservesSystemInductiveInvariant
#print axioms CCFRaft.checkQuorumPreservesSystemInductiveInvariant
#print axioms CCFRaft.appendRetiredCommittedPreservesSystemInductiveInvariant
#print axioms CCFRaft.proposeVotePreservesSystemInductiveInvariant
#print axioms CCFRaft.advanceCommitAndProposeVotePreservesSystemInductiveInvariant
#print axioms CCFRaft.PreVoteExamples.successfulPreVote
#print axioms CCFRaft.CheckQuorumExamples.canonicalLeaderCanCheckQuorum
#print axioms CCFRaft.RetirementExamples.selfRemovalOrdersRetirement
#print axioms CCFRaft.SuccessorNominationExamples.sameTermProposalStartsCandidate

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
    throwError "no CCFRaft theorems were audited"
  Lean.logInfo
    m!"Audited {checked} CCFRaft theorems with {explicitAxioms} explicit axioms."
