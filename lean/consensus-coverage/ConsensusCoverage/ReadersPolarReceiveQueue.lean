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

compile_required_reader_shard ConsensusCoverage.ReadersPolarReceiveQueue budget 900000
  + [step_fromLeader_loop_entries_nil]
  - []
