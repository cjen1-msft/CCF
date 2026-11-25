module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkAFactor
import all ConsensusCoverage.SolvedWitnesses
public meta import ConsensusCoverage.HandReadersTrunkAFactor

namespace ConsensusCoverage.HandReadersTrunkC.RoleSites

open Lean Elab Command
set_option maxRecDepth 16384
set_option maxHeartbeats 2000000

run_cmd liftTermElabM do
  HandReadersTrunkA.Factor.compile ``SolvedWitnesses.step_role_advance_inl

end ConsensusCoverage.HandReadersTrunkC.RoleSites
