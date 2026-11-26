module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkAFactor
import all ConsensusCoverage.SolvedWitnesses
public meta import ConsensusCoverage.HandReadersTrunkAFactor

namespace ConsensusCoverage.HandReadersTrunkC.VoteSites

open Lean Elab Command
set_option maxRecDepth 16384
set_option maxHeartbeats 2000000

run_cmd liftTermElabM do
  for n in #[``SolvedWitnesses.step_votedFor_advance_inl,``SolvedWitnesses.step_votedFor_advance_inr] do
    HandReadersTrunkA.Factor.compile n

end ConsensusCoverage.HandReadersTrunkC.VoteSites
