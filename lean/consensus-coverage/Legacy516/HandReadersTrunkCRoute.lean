module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkCFold
import all ConsensusCoverage.HandReadersTrunkAFactor
public meta import ConsensusCoverage.HandReadersTrunkAFactor

namespace ConsensusCoverage.HandReadersTrunkC.Fold

set_option maxRecDepth 16384
set_option maxHeartbeats 2000000

open Lean Elab Command in
run_cmd liftTermElabM do
  for n in #[``SameSummary,``RetiredSummary] do
    HandReadersTrunkA.Factor.compile n

end ConsensusCoverage.HandReadersTrunkC.Fold
