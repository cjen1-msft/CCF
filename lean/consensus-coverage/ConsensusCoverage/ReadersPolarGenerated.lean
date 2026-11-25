module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ReadersGenerated
public import ConsensusCoverage.ReadersPolarCompiler
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersPolarCompiler
import all ConsensusCoverage.ReadersPolar
import all ConsensusCoverage.ReadersCompiler
import all ConsensusCoverage.SolvedWitnesses
meta import ConsensusCoverage.ReadersPolarCompiler
meta import ConsensusCoverage.ReadersCompiler
meta import Lean

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxHeartbeats 0
set_option maxRecDepth 16384
set_option Elab.async false

open Lean Elab Command

local elab "compile_polar_readers" : command =>
  liftCoreM (ConsensusCoverage.ReadersCompiler.driverWith (some fun env names args =>
    ConsensusCoverage.ReadersPolarCompiler.generate env names args)).run'

compile_polar_readers
