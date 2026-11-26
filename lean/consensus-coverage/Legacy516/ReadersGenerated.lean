module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ReadersCompiler
public import ConsensusCoverage.ReadersShapes
public import Consensus.Proofs.VoteFacts
import all ConsensusCoverage.ReadersCompiler
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReadersShapes
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
meta import ConsensusCoverage.ReadersCompiler
meta import Lean

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxHeartbeats 0
set_option maxRecDepth 16384
set_option pp.maxSteps 1500
set_option Elab.async false
set_option diagnostics false

open Lean Meta Elab Command

local elab "compile_readers" : command =>
  liftCoreM ConsensusCoverage.ReadersCompiler.driver.run'

compile_readers
