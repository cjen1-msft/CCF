module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkBFactor
import all ConsensusCoverage.HandReadersTrunkAFactor
import all ConsensusCoverage.HandReadersTrunkDSignatureData
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersTrunkBFactor
public meta import ConsensusCoverage.HandReadersTrunkAFactor

namespace ConsensusCoverage.HandReadersTrunkD.Leader

open Consensus Model Model.Node Proofs Safety SolvedWitnesses Lean Meta Elab Command
set_option maxRecDepth 16384
set_option maxHeartbeats 2500000

abbrev Check := NodeID → NodeState → Prop

meta section
private def ns := `ConsensusCoverage.HandReadersTrunkD.Leader
private def kids (q : Name) : MetaM (Array Name) := do
  return ReachPath.children q.getPrefix (←getConstInfo q).value!
private def sources : MetaM (Array Name) := do
  let mut out := #[]
  let prefixSites ←kids ``step_fromLeader_loop_entries_cons
  for r in (←kids ``step_recordCommit_eq_retire_pos).extract 2 38 do
    for d in ←kids r do
      if prefixSites.contains d || out.contains d then continue
      let yes ←forallTelescope (←getConstInfo d).type fun xs _=>pure (xs.size == 6)
      if yes then out:=out.push d
  return out

run_cmd liftTermElabM do
  let roots ←sources
  lambdaTelescope (←getConstInfo roots[0]!).value! fun xs _=>do
    let ctx:=xs.extract 0 4
    let args:=xs.extract 4 6
    withLocalDeclD `pick (mkConst ``Check) fun pick=>do
      let mut parts := []
      for d in roots do
        let b:=mkApp2 (mkConst ``And) (mkAppN (mkConst d) xs) (mkAppN pick args)
        let i ←mkLambdaFVars #[args[1]!] b >>= fun q=>mkAppM ``Exists #[q]
        let p ←mkLambdaFVars #[args[0]!] i >>= fun q=>mkAppM ``Exists #[q]
        parts:=parts++[p]
      let v ←mkLambdaFVars (ctx.push pick) (HandReadersTrunkA.Factor.disj parts)
      addDecl (.defnDecl {name:=ns++`Working,levelParams:=[],type:=←inferType v,value:=v,hints:=.abbrev,safety:=.safe})
  HandReadersTrunkBFactor.compile (ns++`Working)
end

end ConsensusCoverage.HandReadersTrunkD.Leader
