module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkDConditionQueries
import all ConsensusCoverage.HandReadersTrunkDConditionData
import all ConsensusCoverage.HandReadersTrunkAFactor
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.ProofWalk
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
public meta import ConsensusCoverage.HandReadersTrunkDConditionQueries

namespace ConsensusCoverage.HandReadersTrunkD.Condition

open Lean Meta Elab Command SolvedWitnesses
set_option maxRecDepth 16384
set_option maxHeartbeats 10000000

meta section
private partial def liftTicket (p h q : Expr) (k : Expr → Expr → MetaM Expr) : MetaM Expr := do
  if p.isAppOfArity ``Exists 2 then
    return ←withLocalDeclD `w (p.getArg! 0) fun w=>do
      let a := p.appArg!.beta #[w]
      withLocalDeclD `e a fun e=>do
        let v ←liftTicket a e (q.appArg!.beta #[w]) k
        let b ←mkAppOptM ``Exists.intro #[none,q.appArg!,w,v]
        return ProofWalk.casesExists p h q (←mkLambdaFVars #[w,e] b)
  mkAppM ``And.intro #[mkProj ``And 0 h,←k q.appArg! (mkProj ``And 1 h)]

private partial def useTicket (p h dest : Expr) (vs : Array Expr)
    (k : Array Expr → Expr → Expr → Expr → MetaM Expr) : MetaM Expr := do
  if p.isAppOfArity ``Exists 2 then
    return ←withLocalDeclD `w (p.getArg! 0) fun w=>do
      let a:=p.appArg!.beta #[w]
      withLocalDeclD `e a fun e=>do
        let body ←useTicket a e dest (vs.push w) k
        return ProofWalk.casesExists p h dest (←mkLambdaFVars #[w,e] body)
  k vs (mkProj ``And 0 h) p.appArg! (mkProj ``And 1 h)

private partial def putTicket (p : Expr) (vs : List Expr) (site cut : Expr) : MetaM Expr := do
  match vs with
  | [] => return ←mkAppM ``And.intro #[site,cut]
  | w::ws => mkAppOptM ``Exists.intro #[none,p.appArg!,w,←putTicket (p.appArg!.beta #[w]) ws site cut]

private partial def armKey (t : Expr) (xs : Array Expr := #[]) : MetaM (Name × Expr) := do
  if t.isAppOfArity ``Exists 2 then
    return ←withLocalDeclD `w (t.getArg! 0) fun w=>armKey (t.appArg!.beta #[w]) (xs.push w)
  return ((t.getArg! 0).getAppFn.constName!,←mkLambdaFVars xs t.appArg!)

run_cmd liftTermElabM do
  let gs ←groups
  let qq := ``step_ite__condition_pos_2
  let rs := ReachPath.children qq.getPrefix (←getConstInfo qq).value!
  lambdaTelescope (←getConstInfo query).value! fun xs outer=>do
    let ctx:=xs.extract 0 4
    let b:=xs.back!
    let lhs:=mkAppN (mkConst query) xs
    let ys:=orParts outer
    let ts:=gs.toList.map fun g=>mkAppN (mkConst g.name) (ctx.push (mkApp (mkConst (g.name++`guard)) b))
    let dest:=disj ts
    let sub ←gs.mapM fun g=>do
      let f ←forallTelescope (←inferType (mkAppN (mkConst g.sources[0]!) ctx)) fun vs _=>do
        mkLambdaFVars vs (disj (g.guards.toList.map fun k=>k.beta (#[b]++vs)))
      g.sources.mapM fun r=>ticket (mkAppN (mkConst r) ctx) f
    let mut fw := []
    let mut paths : Std.HashMap (Name × Nat) (Nat × Nat × Expr × Expr) := {}
    for (r,i) in rs.zipIdx do
      let inner := (←getConstInfo (query.str r.getString!)).value!.beta xs
      let arms := orParts inner
      let mut fws := []
      for (a,j) in arms.zipIdx do
        let (d,guard) ←armKey a
        let some k:=gs.findIdx? (fun g=>g.sources.contains d) | throwError "unclassified caller {d}"
        let g:=gs[k]!
        let l:=g.sources.idxOf d
        let some z ←g.guards.findIdxM? (fun v=>withReducible (isDefEq (v.beta #[b]) guard)) | throwError "missing source guard"
        paths:=paths.insert (d,z) (i,j,inner,a)
        let w ←withLocalDeclD `h a fun h=>do
          let v ←liftTicket a h sub[k]![l]! fun t e=>HandReadersBFactor.into t e z g.guards.size
          let fam ←HandReadersBFactor.into (disj sub[k]!.toList) v l g.sources.size
          mkLambdaFVars #[h] (←HandReadersBFactor.into dest fam k gs.size)
        fws:=fws++[w]
      let f ←withLocalDeclD `a ys[i]! fun h=>do
        mkLambdaFVars #[h] (←HandReadersBFactor.outOf inner h dest fws)
      fw:=fw++[f]
    let mut bw := []
    for (g,k) in gs.zipIdx do
      let arms:=sub[k]!
      let mut backs := []
      for (d,l) in g.sources.zipIdx do
        let v ←withLocalDeclD `ticket arms[l]! fun h=>do
          let v ←useTicket arms[l]! h lhs #[] fun vs site t cut=>do
            let gs':=orParts t
            let bs ←gs'.zipIdx.mapM fun (u,z)=>withLocalDeclD `guard u fun w=>do
              let (i,j,inner,a):=paths[(d,z)]!
              let v ←putTicket a vs.toList site w
              let s ←HandReadersBFactor.into inner v j (orParts inner).length
              mkLambdaFVars #[w] (←HandReadersBFactor.into outer s i rs.size)
            HandReadersBFactor.outOf t cut lhs bs
          mkLambdaFVars #[h] v
        backs:=backs++[v]
      let back ←withLocalDeclD `family ts[k]! fun h=>do
        mkLambdaFVars #[h] (←HandReadersBFactor.outOf (disj arms.toList) h lhs backs)
      bw:=bw++[back]
    let f ←withLocalDeclD `h lhs fun h=>do mkLambdaFVars #[h] (←HandReadersBFactor.outOf outer h dest fw)
    let z ←withLocalDeclD `h dest fun h=>do mkLambdaFVars #[h] (←HandReadersBFactor.outOf dest h lhs bw)
    let v ←mkLambdaFVars xs (←mkAppM ``Iff.intro #[f,z])
    let ty ←mkForallFVars xs (←mkAppM ``Iff #[lhs,dest])
    addDecl (.thmDecl {name:=query.str "byFamily",levelParams:=[],type:=ty,value:=v})
end

end ConsensusCoverage.HandReadersTrunkD.Condition
