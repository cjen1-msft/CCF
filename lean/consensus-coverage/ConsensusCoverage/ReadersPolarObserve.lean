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

compile_required_reader_shard ConsensusCoverage.ReadersPolarObserve budget 400000
  + [step_observeTerm_log_message_appendEntriesResponse,
    step_observeTerm_commitIndex_message_appendEntriesResponse, step_vals_upToDate_lt_or_eq_of_le_inl,
    step_vals_upToDate_lt_or_eq_of_le_inr, step_initAsBackup_summary_eq_zero_or_pos_inr,
    step_appendEntriesRequest_summary_observe_bumping_inr, step_voteRequest_summary_observe_bumping_inr,
    step_voteResponse_summary_observe_bumping_inr, step_preVoteRequest_summary_observe_bumping_inr,
    step_preVoteResponse_summary_observe_bumping_inr, step_foldl_select_max_values_nil,
    step_foldlM__items_nil_2, step_observe_bumping_message_appendEntriesRequest,
    step_observe_bumping_message_requestVoteRequest, step_observe_bumping_message_requestVoteResponse,
    step_observe_bumping_message_requestPreVoteRequest, step_observe_bumping_message_requestPreVoteResponse,
    step_observe_bumping_bump_neg, step_observe_response_leader_pos, step_observe_response_bump_pos,
    step_observe_response_bump_neg, step_observe_response_leader_neg]
  - []
