module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ExplorerGhost
public import ConsensusCoverage.ReplayAnswers

namespace ConsensusCoverage

open Consensus

/-- Optional generated-reader operations. The native legacy target has no
implementation and rejects every command that requests these answers. -/
public structure CensusExplorerHooks where
  covered : List Classes.StepBranch
  history : FullProfile.Configuration → Model.State → Model.Action → Model.State → List Model.State →
    (Classes.StepBranch → Option Bool) × (ReplayAnswers.Evidence → ByteArray)
  finite : FullProfile.Configuration → ExplorerGhost.Ghost → ExplorerGhost.Ghost →
    Model.State → Model.State → Model.Action → Option (Classes.StepBranch → Option Bool)

end ConsensusCoverage
