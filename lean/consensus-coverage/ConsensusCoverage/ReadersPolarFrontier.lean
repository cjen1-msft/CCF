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

compile_required_reader_shard ConsensusCoverage.ReadersPolarFrontier budget 400000
  + [step_commitChains_step_led_inr, step_elect_backed_termCase_inl,
    step_elect_backed_termCase_inr, step_pre_split_pre_backed_inl, step_pre_split_pre_backed_inr,
    step_pre_split_backing_inl, step_campaign_three_campaign_inl, step_weaken_backed_inl,
    step_transfer_backed_inl, step_transfer_backed_inr]
  - []
