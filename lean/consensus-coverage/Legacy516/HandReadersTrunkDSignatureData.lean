module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ReadersGenerated
public import Consensus.Proofs.SafetyInvariant
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersPolarCompiler
import all ConsensusCoverage.ReadersCompiler
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.HandReadersTrunkAFactor
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ReachPath
public meta import ConsensusCoverage.ReadersCompiler
public meta import ConsensusCoverage.ReadersPolarCompiler
public meta import ConsensusCoverage.HandReadersTrunkAFactor

namespace ConsensusCoverage.HandReadersTrunkD.Signed

open Consensus Model Model.Node Proofs Safety SolvedWitnesses Lean Meta Elab Command
set_option maxRecDepth 16384
set_option maxHeartbeats 4000000
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

meta section
private def kids (n : Name) : MetaM (Array Name) := do
  return ReachPath.children n.getPrefix (←getConstInfo n).value!

private def erasedSites : MetaM (Array Name) := do
  let q := ``step_signatureIndex_le_maxCommittableIndex_values_nil
  let rs ←kids q
  rs.filterM fun n => do forallTelescope (←getConstInfo n).type fun xs _ => pure (xs.size == 4)

private def indexedSites := kids ``step_signatureIndex_le_maxCommittableIndex_mem_cons_inl
private def disj := HandReadersTrunkA.Factor.disj
private def ns := `ConsensusCoverage.HandReadersTrunkD.Signed

private def otherArms (xs : Array Expr) : MetaM (Array Expr) := do
  let bounded ← kids ``step_maxCommittableIndex_le_of_prefix_zero_neg
  let rank ← kids ``step_rankAtGrant_persist_inl
  let mut out := #[]
  for n in ←erasedSites do
    let p := (←getConstInfo n).value!.beta xs
    for a in HandReadersBFactor.disjuncts p do
      let #[r] := ReachPath.children n.getPrefix a | throwError "expected one signed-bound origin"
      unless bounded.contains r || rank.contains r do out := out.push a
  return out

run_cmd liftTermElabM do
  let q := ``step_signatureIndex_le_maxCommittableIndex_values_nil
  lambdaTelescope (←getConstInfo q).value! fun xs _ => do
    let es ←erasedSites
    let other ←otherArms xs
    for (n,body) in [(ns++`Erased,disj (es.toList.map fun r=>mkAppN (mkConst r) xs)),
        (ns++`NonRanking,disj other.toList)] do
      addDecl (.defnDecl {name := n,levelParams := [],type := ←mkForallFVars xs (mkSort .zero),value := ←mkLambdaFVars xs body,hints := .abbrev,safety := .safe})

-- Reuse the original compiler's finite views for the election and persistence
-- paths. The other two groups have known whole-question readers, rather than
-- independent finite domains at every occurrence of their input parameters.
run_cmd liftTermElabM do
  let target := ns++`Compiled
  ReadersCompiler.driverWith (some (fun env _ _ => do
    let n := ns++`NonRanking
    let roots := ReachPath.children `ConsensusCoverage.SolvedWitnesses (←getConstInfo n).value!
    let mut st : ReadersCompiler.St := {}
    let mut pending := roots
    let mut visited := ({ } : NameSet)
    while !pending.isEmpty do
      let r := pending.back!
      pending := pending.pop
      if visited.contains r then continue
      visited := visited.insert r
      let info ←ReadersPolarCompiler.retained env r
      if info.reader.isSome then st := {st with memo := st.memo.insert r info}
      else pending := pending ++ (←kids r)
    let (info,result) ← (ReadersCompiler.compileConst env n).run st
    unless info.reader.isSome do throwError "uncompiled historical signed-bound origin: {result.blockers.toList.take 4}"))
    {namespaceName := target,extraRules := true}
end

end ConsensusCoverage.HandReadersTrunkD.Signed
