module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.CensusExplorerHooks
import ConsensusCoverage.CensusBallots
import ConsensusCoverage.CensusGhost
import ConsensusCoverage.CensusRaw
import ConsensusCoverage.Readers

namespace ConsensusCoverage

public def CensusExplorerHooks.generated : CensusExplorerHooks where
  covered := Readers.covered
  history cfg s a t past :=
    let e := Readers.read cfg s a t past
    (Readers.read? e, fun old => CensusRaw.row old e)
  finite cfg g h s t a :=
    (CensusGhost.answers cfg g h s t a).map fun query b =>
      (CensusBallots.answer b).orElse fun _ => query b

end ConsensusCoverage
