module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkDTableBound
import all ConsensusCoverage.HandReadersTrunkAFactor
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.PromotionImpossibleB
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersTrunkDTableBound
public meta import ConsensusCoverage.HandReadersTrunkAFactor

namespace ConsensusCoverage.HandReadersTrunkD.Table

open Consensus Model Model.Node Proofs Safety SolvedWitnesses Lean Meta Elab Command
set_option maxRecDepth 8192
set_option maxHeartbeats 1600000

private theorem pin [Config.InitialConfiguration] {f : Frame} {t u : Model.State} {c : Ctx f t}
    {tr : LocalTransition f.current u} {n v} (eq : u = t) (he : HEq tr c.tr)
    (node : n = tr.actor) (value : v = tr.post) : n = c.actor ∧ v = c.post := by
  subst u; cases eq_of_heq he; exact ⟨node,value⟩

run_cmd liftTermElabM do
  let q := ``step_mem_replaceNode_here_pos
  let cs := ReachPath.children q.getPrefix (←getConstInfo q).value!
  lambdaTelescope (←getConstInfo cs[0]!).value! fun xs _ => do
    let n := xs[4]!
    let v := xs[6]!
    let c := xs[3]!
    let tr ←mkAppM ``Ctx.tr #[c]
    let tgt := mkApp2 (mkConst ``And) (←mkEq n (←mkAppM ``Ctx.actor #[c])) (←mkEq v (←mkAppM ``Ctx.post #[c]))
    let f1 := mkAppN (mkConst cs[16]!) xs
    let f2 := mkAppN (mkConst cs[25]!) xs
    let rest := mkApp2 (mkConst ``Or) f1 f2
    withLocalDeclD `stable (mkAppN (mkConst ``Still) (xs.extract 0 3)) fun stable => do
      let mut arms := []
      let mut pins := []
      let mut filtered := []
      for (r,i) in cs.toList.zipIdx do
        let a := mkAppN (mkConst r) xs
        arms := arms ++ [a]
        let p := (←getConstInfo r).value!.beta xs
        let h ←withLocalDeclD `site a fun h => do
          let proof ← PromotionImpossibleB.withFields p h #[] fun fs => do
            let (call,hc,body) ←PromotionImpossibleB.firstReach fs
            let (_,node) ←PromotionImpossibleB.nodeEq n fs
            let (_,value) ←PromotionImpossibleB.nodeEq v fs
            let pf ←PromotionImpossibleB.withFields body hc #[] fun gs => do
              let some he := gs.find? (fun (q,_) => q.isAppOfArity ``HEq 4 && q.appArg! == tr) | do
                let some eq := gs.find? (fun (q,_) => q.isAppOfArity ``Eq 3 && q.appArg! == tr) | throwError "pin[{i}]"
                mkAppM ``pin #[←mkEqRefl xs[2]!,←mkAppM ``heq_of_eq #[eq.2],node,value]
              let some e ← gs.findSomeM? (fun (q,e) => do
                if q.isAppOfArity ``Eq 3 && (←isDefEq q.appArg! xs[2]!) then return some e
                return none) |
                throwError "missing destination for {call.getAppFn}"
              mkAppM ``pin #[e,he.2,node,value]
            mkExpectedTypeHint pf tgt
          mkLambdaFVars #[h] proof
        pins := pins ++ [h]
        let k ←withLocalDeclD `site a fun h => do
          let pf ← if i == 16 then mkAppOptM ``Or.inl #[none,f2,h]
            else if i == 25 then mkAppOptM ``Or.inr #[f1,none,h]
            else pure (mkApp2 (mkConst ``False.elim [.zero]) rest (mkAppN (mkConst (excluded r)) (xs ++ #[stable,h])))
          mkLambdaFVars #[h] pf
        filtered := filtered ++ [k]
      let all := HandReadersTrunkA.Factor.disj arms
      let name := `ConsensusCoverage.HandReadersTrunkD.Table.Sites
      addDecl (.defnDecl {name,levelParams := [],type := ←mkForallFVars xs (mkSort .zero),value := ←mkLambdaFVars xs all,hints := .abbrev,safety := .safe})
      withLocalDeclD `all (mkAppN (mkConst name) xs) fun h => do
        let p ←mkLambdaFVars (xs.push h) (←HandReadersBFactor.outOf all h tgt pins)
        addDecl (.thmDecl {name := `ConsensusCoverage.HandReadersTrunkD.Table.pinned,levelParams := [],type := ←inferType p,value := p})
        let p ← mkLambdaFVars (xs ++ #[stable,h]) (←HandReadersBFactor.outOf all h rest filtered)
        addDecl (.thmDecl {name := `ConsensusCoverage.HandReadersTrunkD.Table.residual,levelParams := [],type := ←inferType p,value := p})

end ConsensusCoverage.HandReadersTrunkD.Table
