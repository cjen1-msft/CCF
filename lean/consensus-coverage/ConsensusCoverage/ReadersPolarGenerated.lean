module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ReadersGenerated
public import ConsensusCoverage.ReadersPolarCompiler
public import ConsensusCoverage.ReadersPolarBacking
public import ConsensusCoverage.ReadersPolarSummary
public import ConsensusCoverage.ReadersPolarObserve
public import ConsensusCoverage.ReadersPolarFrontier
import all ConsensusCoverage.SolvedWitnesses
meta import ConsensusCoverage.ReadersPolarShards

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxHeartbeats 0
set_option maxRecDepth 16384
set_option Elab.async false

-- The rosters are the entire production allowlist. Unlisted polarities,
-- including budget-exhausted roots, are omitted rather than retried here.
join_reader_shards ConsensusCoverage.ReadersPolarCompiler from
  [ConsensusCoverage.ReadersPolarBacking, ConsensusCoverage.ReadersPolarSummary,
   ConsensusCoverage.ReadersPolarObserve, ConsensusCoverage.ReadersPolarFrontier]
