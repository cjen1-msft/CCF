module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public meta import ConsensusCoverage.ReachPath
public meta import Lean

namespace ConsensusCoverage.CensusReach

open Lean Elab Command ReachPath

/-- Name the actual declaration at a rooted path, so `unfold`, `simp` and
metaprograms can use the same name without introducing a wrapper function. -/
elab "census_reach " alias:ident " := " "reach% " path:reachPath : command => liftTermElabM do
  let target ← resolve path
  let name := (← getCurrNamespace) ++ alias.getId
  modifyEnv fun env => addAlias env name target

end ConsensusCoverage.CensusReach
