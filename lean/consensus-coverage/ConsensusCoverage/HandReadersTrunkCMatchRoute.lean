module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkAFactor
import all ConsensusCoverage.SolvedWitnesses
public meta import ConsensusCoverage.HandReadersTrunkAFactor

namespace ConsensusCoverage.HandReadersTrunkC.Match

set_option maxRecDepth 16384
set_option maxHeartbeats 2500000

open Lean Elab Command in
run_cmd liftTermElabM do
  for n in #[``SolvedWitnesses.step_matchIndex_advance_inl,``SolvedWitnesses.step_matchIndex_advance_inr] do
    HandReadersTrunkA.Factor.compile n

end ConsensusCoverage.HandReadersTrunkC.Match
