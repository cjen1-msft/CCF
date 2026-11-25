module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ReadersPolarCompiler
public import ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersPolarCompiler
public meta import ConsensusCoverage.ReadersPolarCompiler
public meta import ConsensusCoverage.ReadersCompiler
public meta import Lean

namespace ConsensusCoverage.ReadersPolarShards

open Lean Elab Command

set_option maxHeartbeats 0
set_option maxRecDepth 16384
set_option Elab.async false

/-- Generate a positive-only shard. Negative subtests are still generated when
needed for a positive root, but are never dispatched as answers. -/
elab "compile_reader_shard " scope:ident " budget " budget:num
    " roots " "[" roots:ident,* "]" " reuse " "[" reuse:ident,* "]" : command => do
  let names := roots.getElems.map (·.getId)
  liftCoreM (ReadersCompiler.driverWith (some fun env arms args => do
    let order ← names.mapM fun name => do
      let some arm := arms.find? (·.getString! == name.toString) |
        throwError "unknown reader root {name}"
      pure arm
    unless order.toList.Nodup do throwError "duplicate reader root"
    ReadersPolarCompiler.generate env arms args (order.contains ·) {
      scope := scope.getId
      reuse := reuse.getElems.map (·.getId)
      order
      heartbeats := budget.getNat * 1000
      yesOnly := true
    })).run'

/-- Combine already built shard dispatchers and retain their soundness. -/
elab "join_reader_shards " scope:ident " from " "[" shards:ident,* "]" : command =>
  liftCoreM (ReadersCompiler.driverWith (some fun env _ args =>
    ReadersPolarCompiler.join env args scope.getId (shards.getElems.map (·.getId)))).run'

end ConsensusCoverage.ReadersPolarShards
