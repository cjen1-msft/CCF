module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.HandReadersElectionBPrefixParts
public import ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.HandReadersElectionBPrefixParts
public meta import ConsensusCoverage.HandReadersElectionBPrefixParts
public meta import Lean

open Lean Elab Command ConsensusCoverage.HandReadersElectionB

set_option maxRecDepth 16384
set_option maxHeartbeats 0
set_option Elab.async false
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

run_cmd liftTermElabM do PrefixParts.compileBatch 0
