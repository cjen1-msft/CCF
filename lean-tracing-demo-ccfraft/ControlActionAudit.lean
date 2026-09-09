-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.ControlActionMappingProofs
import Lean

run_cmd do
  for theoremName in [
      ``CCFRaft.TransactionMapping.mapState_advanceCommitIndex,
      ``CCFRaft.TransactionMapping.enabled_mapState_advanceCommitIndex_iff,
      ``CCFRaft.TransactionMapping.mapState_timeout,
      ``CCFRaft.TransactionMapping.enabled_mapState_timeout_iff,
      ``CCFRaft.TransactionMapping.mapState_becomePreVoteCandidate,
      ``CCFRaft.TransactionMapping.enabled_mapState_becomePreVoteCandidate_iff,
      ``CCFRaft.TransactionMapping.mapState_becomeCandidate,
      ``CCFRaft.TransactionMapping.enabled_mapState_becomeCandidate_iff,
      ``CCFRaft.TransactionMapping.mapState_requestVote,
      ``CCFRaft.TransactionMapping.enabled_mapState_requestVote_iff,
      ``CCFRaft.TransactionMapping.mapState_requestPreVote,
      ``CCFRaft.TransactionMapping.enabled_mapState_requestPreVote_iff,
      ``CCFRaft.TransactionMapping.mapState_checkQuorum,
      ``CCFRaft.TransactionMapping.enabled_mapState_checkQuorum_iff,
      ``CCFRaft.TransactionMapping.mapState_updateTerm,
      ``CCFRaft.TransactionMapping.enabled_mapState_updateTerm_iff,
      ``CCFRaft.TransactionMapping.mapState_becomeLeader,
      ``CCFRaft.TransactionMapping.enabled_mapState_becomeLeader_iff,
      ``CCFRaft.TransactionMapping.mapState_proposeVote,
      ``CCFRaft.TransactionMapping.enabled_mapState_proposeVote_iff,
      ``CCFRaft.TransactionMapping.mapState_advanceCommitIndexAndProposeVote,
      ``CCFRaft.TransactionMapping.enabled_mapState_advanceCommitIndexAndProposeVote_iff] do
    for axiomName in ← Lean.collectAxioms theoremName do
      unless axiomName == ``propext || axiomName == ``Classical.choice ||
          axiomName == ``Quot.sound do
        throwError "{theoremName} depends on unapproved axiom {axiomName}"
