module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkDConditionData
import all ConsensusCoverage.HandReadersTrunkAFactor
import all ConsensusCoverage.HandReadersTrunkBFactor
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
public meta import ConsensusCoverage.HandReadersTrunkDConditionData
public meta import ConsensusCoverage.HandReadersTrunkBFactor

namespace ConsensusCoverage.HandReadersTrunkD.Condition

open Lean Meta Elab Command SolvedWitnesses
set_option maxRecDepth 16384
set_option maxHeartbeats 6000000

meta section
private def groupNS := `ConsensusCoverage.HandReadersTrunkD.Condition.Family
private def kinds := #[`Timeout,`Ack,`Vote,`PreVote,`Proposal,`Batch,`Advance,`Request,`Elect]
private def disj := HandReadersTrunkA.Factor.disj
private def orParts := HandReadersBFactor.disjuncts

private partial def guardAt (b t : Expr) (xs : Array Expr) : MetaM (Name × Expr) := do
  if t.isAppOfArity ``Exists 2 then
    return ←withLocalDeclD t.appArg!.bindingName! (t.getArg! 0) fun x=>guardAt b (t.appArg!.beta #[x]) (xs.push x)
  let root := t.getArg! 0
  unless root.getAppArgs.extract 4 root.getAppNumArgs == xs do throwError "handler arguments not anchored at the call"
  return (root.getAppFn.constName!,←mkLambdaFVars (#[b]++xs) t.appArg!)

private structure Group where
  name : Name
  guards : Array Expr
  sources : Array Name
  deriving Inhabited

private def groups : MetaM (Array Group) := do
  let q := ``step_ite__condition_pos_2
  let rs := ReachPath.children q.getPrefix (←getConstInfo q).value!
  let mut all := #[]
  for r in rs do
    let rows ←lambdaTelescope (←getConstInfo (query.str r.getString!)).value! fun xs p=>do
      (orParts p).mapM (fun a=>guardAt xs.back! a #[])
    let unique := (rows.map Prod.fst).eraseDups
    for (source,j) in unique.zipIdx do
      let gs := ((rows.filter (·.1 == source)).map Prod.snd).eraseDups.toArray
      if r == rs[0]! then all:=all.push (⟨groupNS++kinds[j]!,gs,#[source]⟩ : Group)
      else
        let some k := all.findIdx? (fun g=>g.guards.size == gs.size && gs.all g.guards.contains) |
          throwError "missing handler prototype at {source}"
        unless all[k]!.sources.contains source do all := all.modify k fun g=>{g with sources:=g.sources.push source}
  return all

private def ticket (site test : Expr) : MetaM Expr := do
  forallTelescope (←inferType site) fun xs _=>do
    let p := mkApp2 (mkConst ``And) (mkAppN site xs) (test.beta xs)
    xs.foldrM (fun x a=>mkLambdaFVars #[x] a >>= fun f=>mkAppM ``Exists #[f]) p

run_cmd liftTermElabM do
  let q := ``step_ite__condition_pos_2
  let gs ←groups
  for g in gs do
    lambdaTelescope (←getConstInfo q).value! fun xs _=>do
      let first := mkAppN (mkConst g.sources[0]!) xs
      let type ←inferType first
      withLocalDeclD `accept type fun k=>do
        let ps ←g.sources.mapM fun r=>ticket (mkAppN (mkConst r) xs) k
        let v ←mkLambdaFVars (xs.push k) (disj ps.toList)
        addDecl (.defnDecl {name:=g.name,levelParams:=[],type:=←inferType v,value:=v,hints:=.abbrev,safety:=.safe})
      withLocalDeclD `want (mkConst ``Bool) fun b=>do
        forallTelescope type fun vs _=>do
          let ps := g.guards.toList.map fun guard=>guard.beta (#[b]++vs)
          let v ←mkLambdaFVars (#[b]++vs) (disj ps)
          addDecl (.defnDecl {name:=g.name++`guard,levelParams:=[],type:=←inferType v,value:=v,hints:=.abbrev,safety:=.safe})
    HandReadersTrunkBFactor.compile g.name
end

end ConsensusCoverage.HandReadersTrunkD.Condition
