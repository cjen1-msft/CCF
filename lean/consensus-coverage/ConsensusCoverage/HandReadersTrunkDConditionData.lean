module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkDConditionProof
import all ConsensusCoverage.HandReadersTrunkAFactor
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
public meta import ConsensusCoverage.HandReadersTrunkAFactor
public meta import ConsensusCoverage.HandReadersTrunkDConditionProof

namespace ConsensusCoverage.HandReadersTrunkD.Condition

open Consensus Model Model.Node Proofs Safety SolvedWitnesses Lean Meta Elab Command
set_option maxRecDepth 16384
set_option maxHeartbeats 2000000

private theorem pickedOr (A B : Site) (b : Bool) :
    Picked (fun P p m n => A P p m n ∨ B P p m n) b ↔ Picked A b ∨ Picked B b := by
  constructor
  · rintro ⟨P,p,m,n,h | h,cut⟩ <;> first | exact .inl ⟨P,p,m,n,h,cut⟩ | exact .inr ⟨P,p,m,n,h,cut⟩
  · rintro (⟨P,p,m,n,h,cut⟩ | ⟨P,p,m,n,h,cut⟩) <;> first | exact ⟨P,p,m,n,.inl h,cut⟩ | exact ⟨P,p,m,n,.inr h,cut⟩

private theorem pickedEx {α : Type} (R : α → Site) (b : Bool) :
    Picked (fun P p m n => ∃ x, R x P p m n) b ↔ ∃ x, Picked (R x) b :=
  ⟨fun ⟨P,p,m,n,⟨x,h⟩,cut⟩ => ⟨x,P,p,m,n,h,cut⟩,fun ⟨x,P,p,m,n,h,cut⟩ => ⟨P,p,m,n,⟨x,h⟩,cut⟩⟩

private theorem pickedAnd (A : Prop) (R : Site) (b : Bool) :
    Picked (fun P p m n => A ∧ R P p m n) b ↔ A ∧ Picked R b :=
  ⟨fun ⟨P,p,m,n,⟨a,h⟩,cut⟩ => ⟨a,P,p,m,n,h,cut⟩,fun ⟨a,P,p,m,n,h,cut⟩ => ⟨P,p,m,n,⟨a,h⟩,cut⟩⟩

private theorem pickedPins (Q q a d b) : Picked (fun P p m n => P = Q ∧ p = q ∧ m = a ∧ n = d) b ↔ Picks b q :=
  ⟨fun ⟨_,_,_,_,⟨rfl,rfl,rfl,rfl⟩,cut⟩ => cut,fun cut => ⟨_,_,_,_,⟨rfl,rfl,rfl,rfl⟩,cut⟩⟩

meta section
private def query := `ConsensusCoverage.HandReadersTrunkD.Condition.LocalGuards

private partial def project (xs : Array Expr) (b p : Expr) : MetaM (Expr × Expr) := do
  if p.isAppOfArity ``Or 2 then
    let a := p.getArg! 0
    let d := p.appArg!
    let eq ←mkAppM ``pickedOr #[←mkLambdaFVars xs a,←mkLambdaFVars xs d,b]
    let (a,ha) ←project xs b a
    let (d,hd) ←project xs b d
    return (mkApp2 (mkConst ``Or) a d,←mkAppM ``Iff.trans #[eq,←mkAppM ``or_congr #[ha,hd]])
  if p.isAppOfArity ``Exists 2 then
    return ←withLocalDeclD p.appArg!.bindingName! (p.getArg! 0) fun x=>do
      let t := p.appArg!.beta #[x]
      let eq ←mkAppM ``pickedEx #[←mkLambdaFVars (#[x]++xs) t,b]
      let (body,h) ←project xs b t
      return (←mkAppM ``Exists #[←mkLambdaFVars #[x] body],←mkAppM ``Iff.trans #[eq,←mkAppM ``exists_congr #[←mkLambdaFVars #[x] h]])
  unless p.isAppOfArity ``And 2 do throwError "expected a pinned guard"
  let a := p.getArg! 0
  let d := p.appArg!
  if xs.any (fun x=>a.containsFVar x.fvarId!) then
    let mut t := p
    let mut vs := #[]
    for i in [:4] do
      let e := if i == 3 then t else t.getArg! 0
      unless e.isAppOfArity ``Eq 3 && e.getArg! 1 == xs[i]! do throwError "unrecognized conditional pin"
      vs := vs.push e.appArg!
      t := t.appArg!
    return (←mkAppM ``Picks #[b,vs[1]!],←mkAppM ``pickedPins (vs.push b))
  let eq ←mkAppM ``pickedAnd #[a,←mkLambdaFVars xs d,b]
  let (d,h) ←project xs b d
  let refl := mkApp (mkConst ``Iff.rfl) a
  return (mkApp2 (mkConst ``And) a d,←mkAppM ``Iff.trans #[eq,←mkAppM ``and_congr #[refl,h]])

run_cmd liftTermElabM do
  let q := ``step_ite__condition_pos_2
  let ci ←getConstInfo q
  let rs := ReachPath.children q.getPrefix ci.value!
  for r in rs do
    lambdaTelescope (←getConstInfo r).value! fun xs p=>do
      let ctx := xs.extract 0 4
      withLocalDeclD `want (mkConst ``Bool) fun b=>do
        let (data,h) ←project (xs.extract 4 8) b p
        let vars := ctx.push b
        let name := query.str r.getString!
        let v ←mkLambdaFVars vars data
        addDecl (.defnDecl {name,levelParams:=[],type:=←inferType v,value:=v,hints:=.abbrev,safety:=.safe})
        let lhs ←mkAppM ``Picked #[mkAppN (mkConst r) ctx,b]
        let ty ←mkForallFVars vars (←mkAppM ``Iff #[lhs,mkAppN (mkConst name) vars])
        addDecl (.thmDecl {name:=name.appendAfter "_iff",levelParams:=[],type:=ty,value:=←mkLambdaFVars vars h})
  lambdaTelescope ci.value! fun xs _=>withLocalDeclD `want (mkConst ``Bool) fun b=>do
    let vars := xs.push b
    let rows := rs.toList.map fun r=> mkAppN (mkConst (query.str r.getString!)) vars
    let v ←mkLambdaFVars vars (HandReadersTrunkA.Factor.disj rows)
    addDecl (.defnDecl {name:=query,levelParams:=[],type:=←inferType v,value:=v,hints:=.abbrev,safety:=.safe})
    for (g,value) in [(``Guards.Positive,true),(``Guards.Negative,false)] do
      let args := xs.push (toExpr value)
      let ps := rs.toList.map fun r=>mkAppN (mkConst ((query.str r.getString!).appendAfter "_iff")) args
      let mut h := ps.getLast!
      for pf in ps.dropLast.reverse do h ←mkAppM ``or_congr #[pf,h]
      let orig ←mkAppM ``Iff.trans #[mkAppN (mkConst (g.appendAfter "_iff")) xs,h]
      let ty ←mkForallFVars xs (←mkAppM ``Iff #[mkAppN (mkConst (if value then q else ``step_ite__condition_neg_2)) xs,mkAppN (mkConst query) args])
      addDecl (.thmDecl {name:=query.str (if value then "positive" else "negative"),levelParams:=[],type:=ty,value:=←mkLambdaFVars xs orig})
end

end ConsensusCoverage.HandReadersTrunkD.Condition
