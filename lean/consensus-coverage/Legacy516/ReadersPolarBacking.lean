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

compile_required_reader_shard ConsensusCoverage.ReadersPolarBacking budget 400000
  + [step_commit_backed_fromSource_neg, step_match_ack_now_after_inl,
    step_match_ack_matchIndex_inl, step_commitChains_step_backing_inl,
    step_commitChains_step_backing_inr, step_commitChains_step_led_inl,
    step_grantFactsBefore_grant_inr, step_grantFactsBefore_supported_inl, step_seen_after_seen_inl,
    step_seen_after_seen_inr, step_seen_after_now_after_inl, step_weaken_backed_inr,
    step_prefix_small_inr, step_appendEntry_configuration_none, step_appendEntry_configuration_some,
    step_handleAppendEntriesRequest_stepDown_neg, step_handleAppendEntriesRequest_conflict_none,
    step_handleAppendEntriesRequest_conflict_some]
  - [step_commit_backed_fromSource_neg, step_commitChains_step_backing_inl,
    step_commitChains_step_backing_inr, step_seen_after_seen_inl, step_seen_after_seen_inr,
    step_seen_after_now_after_inl, step_prefix_small_inr]
