module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ReadersPolarShards
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersPolar
import all ConsensusCoverage.ReadersPolarCompiler
import all ConsensusCoverage.ReadersCompiler
import all ConsensusCoverage.SolvedWitnesses
meta import ConsensusCoverage.ReadersPolarShards

set_option maxHeartbeats 0
set_option maxRecDepth 16384
set_option Elab.async false

compile_required_reader_shard ConsensusCoverage.ReadersPolarSummary budget 400000
  + [step_summary_event_internal, step_summary_input_append, step_summary_input_sendEntries,
    step_summary_input_timeout, step_summary_kind_checkQuorum, step_summary_kind_election,
    step_summary_input_nominateSuccessor,
    step_summary_input_initAsBackup, step_summary_event_receive, step_summary_message_appendEntriesRequest,
    step_summary_message_appendEntriesResponse, step_summary_message_requestVoteRequest,
    step_summary_message_requestVoteResponse, step_summary_message_requestPreVoteRequest,
    step_summary_message_requestPreVoteResponse, step_summary_message_proposeRequestVoteRequest]
  - [step_summary_kind_checkQuorum, step_summary_input_nominateSuccessor]
