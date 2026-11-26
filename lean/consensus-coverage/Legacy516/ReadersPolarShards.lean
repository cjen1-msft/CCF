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

private meta def buildShard (scope : Name) (budget : Nat) (positive negative reuse : Array Name)
    (required : Bool) : CommandElabM Unit :=
  liftCoreM (ReadersCompiler.driverWith (some fun env arms args => do
    let resolve := fun name => do
      let some arm := arms.find? (·.getString! == name.toString) |
        throwError "unknown reader root {name}"
      pure arm
    let yes ← positive.mapM resolve
    let no ← negative.mapM resolve
    unless yes.toList.Nodup ∧ no.toList.Nodup do throwError "duplicate reader root"
    let order := yes ++ no.filter (!yes.contains ·)
    ReadersPolarCompiler.generate env arms args (order.contains ·) {
      scope, reuse, order, required
      heartbeats := budget * 1000
      positive := yes.contains
      negative := no.contains
    })).run'

/-- Generate a positive-only shard. Negative subtests are still generated when
needed for a positive root, but are never dispatched as answers. -/
elab "compile_reader_shard " scope:ident " budget " budget:num
    " roots " "[" roots:ident,* "]" " reuse " "[" reuse:ident,* "]" : command =>
  buildShard scope.getId budget.getNat (roots.getElems.map (·.getId)) #[] (reuse.getElems.map (·.getId)) false

/-- Production shards do not attempt omitted roots or silently lose required tests. -/
elab "compile_required_reader_shard " scope:ident " budget " fuel:num
    " + " "[" positive:ident,* "]" " - " "[" negative:ident,* "]" : command =>
  buildShard scope.getId fuel.getNat (positive.getElems.map (·.getId))
    (negative.getElems.map (·.getId)) #[] true

/-- Combine already built shard dispatchers and retain their soundness. -/
elab "join_reader_shards " scope:ident " from " "[" shards:ident,* "]" : command =>
  liftCoreM (ReadersCompiler.driverWith (some fun env _ args =>
    ReadersPolarCompiler.join env args scope.getId (shards.getElems.map (·.getId)))).run'

end ConsensusCoverage.ReadersPolarShards
