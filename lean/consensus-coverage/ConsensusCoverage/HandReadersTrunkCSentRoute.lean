module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkBFactor
import all ConsensusCoverage.SolvedWitnesses
public meta import ConsensusCoverage.HandReadersTrunkBFactor

namespace ConsensusCoverage.HandReadersTrunkC.Sent

set_option maxRecDepth 16384
set_option maxHeartbeats 2000000

open Lean Elab Command in
run_cmd liftTermElabM do
  HandReadersTrunkBFactor.compile ``SolvedWitnesses.step_sentIndex_advance_inl

end ConsensusCoverage.HandReadersTrunkC.Sent
