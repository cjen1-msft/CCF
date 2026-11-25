module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkDNominateBound
import all ConsensusCoverage.HandReadersTrunkDLeaderQuery
import all ConsensusCoverage.HandReadersTrunkDRecordRoute
import all ConsensusCoverage.HandReadersTrunkBFactor
import all ConsensusCoverage.HandReadersTrunkAFactor
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.NominationRetirementB
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersTrunkDRecordRoute
public meta import ConsensusCoverage.HandReadersTrunkBFactor

namespace ConsensusCoverage.HandReadersTrunkD.Nominate

open Consensus Model Model.Node Proofs Safety SolvedWitnesses Lean Meta Elab Command
set_option maxRecDepth 8192
set_option maxHeartbeats 1600000
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private abbrev Body (want : Bool) (n : NodeID) (st : NodeState) :=
  st.role = .primary ∧ (findSuccessor st n).isSome = want
private abbrev Ticket (R : NodeID → NodeState → Prop) (p : Leader.Check) := ∃ n m, R n m ∧ p n m

private theorem positive (R : NodeID → NodeState → Prop) :
    (∃ n st, R n st ∧ st.role = .primary ∧ st.role = .primary ∧ st.role = .primary ∧ ∃ v, findSuccessor st n = some v) ↔
    Ticket R (Body true) := by simp [Ticket,Body,Option.isSome_iff_exists]
private theorem negative (R : NodeID → NodeState → Prop) :
    (∃ n st, R n st ∧ st.role = .primary ∧ st.role = .primary ∧ st.role = .primary ∧ ∀ v, findSuccessor st n ≠ some v) ↔
    Ticket R (Body false) := by
  unfold Ticket Body; apply exists_congr; intro n; apply exists_congr; intro st
  cases eq : findSuccessor st n <;> simp

private theorem either {a b : NodeID → NodeState → Prop} (p : Leader.Check) :
    Ticket (fun n m=> a n m ∨ b n m) p ↔ Ticket a p ∨ Ticket b p := by
  constructor
  · rintro ⟨n,s,h | h,g⟩ <;> first | exact .inl ⟨n,s,h,g⟩ | exact .inr ⟨n,s,h,g⟩
  · rintro (⟨n,s,h,g⟩ | ⟨n,s,h,g⟩) <;> first | exact ⟨n,s,.inl h,g⟩ | exact ⟨n,s,.inr h,g⟩

private theorem called [Config.InitialConfiguration] (R : NodeID → NodeState → Prop) (want : Bool) :
    Ticket (fun n m=>R n m ∧ ¬high n m ≤ m.commitIndex ∧ (m.recordCommit n (high n m)).isRetiredCommitted n ∧
      m.role = .primary ∧ Advance n m (m.recordCommit n (high n m))) (Body want) ↔ Ticket R (Pick want) := by
  constructor
  · rintro ⟨n,m,⟨h,gt,ret,role,_⟩,_,choose⟩
    exact ⟨n,m,h,Nat.lt_of_not_ge gt,ret,role,choose⟩
  · rintro ⟨n,m,h,gt,ret,role,suc⟩
    exact ⟨n,m,⟨h,Nat.not_le_of_gt gt,ret,role,NominationRetirementB.recorded n m gt⟩,role,suc⟩

meta section
private def ns := `ConsensusCoverage.HandReadersTrunkD.Nominate

run_cmd liftTermElabM do
  let q:=``step_nominate_sends_successor_some
  let rs ←Leader.kids q
  let work ←Leader.sources
  lambdaTelescope (←getConstInfo q).value! fun xs _=>withLocalDeclD `want (mkConst ``Bool) fun b=>do
    let mut ls := []
    for r in rs do
      let ds ←Leader.kids r
      for d in ds do
        unless work.contains d do
          let a ←mkAppM ``Ticket #[mkAppN (mkConst d) xs,mkApp (mkConst ``Body) b]
          let body := (←getConstInfo ``Ticket).value!.beta a.getAppArgs
          unless ls.contains body do ls :=ls++[body]
    let v ←mkLambdaFVars (xs.push b) (Signed.disj ls)
    addDecl (.defnDecl {name:=ns++`Standalone,levelParams:=[],type:=←inferType v,value:=v,hints:=.abbrev,safety:=.safe})
  HandReadersTrunkBFactor.compile (ns++`Standalone)

  for (want,q,loc) in [(true,``step_nominate_sends_successor_some,``positive),(false,``step_nominate_sends_successor_none,``negative)] do
    lambdaTelescope (←getConstInfo q).value! fun xs body=>do
      let b :=toExpr want
      let left :=mkAppN (mkConst (ns++`Standalone)) (xs.push b)
      let right:=mkAppN (mkConst ``Leader.Working) (xs.push (mkApp (mkConst ``Pick) b))
      let result :=mkApp2 (mkConst ``Or) left right
      let atL := Signed.choices (←Record.expand left)
      let atR := Signed.choices (←Record.expand right)
      let arms:= Signed.choices body
      let mut forwards := []
      let mut backL := #[]
      let mut backR := #[]
      for (r,i) in rs.toList.zipIdx do
        let call:=mkAppN (mkConst r) xs
        let reps ←lambdaTelescope (←getConstInfo r).value! fun ys p=>do
          let args:=ys.extract 4 6
          (Signed.choices p).mapM fun e=>do mkLambdaFVars args (e.replaceFVars (ys.extract 0 4) xs)
        let ds ←Leader.kids r
        let ce := ds.back!
        let reg:=mkAppN (mkConst ce) xs
        let convert ←mkAppM ``called #[reg,b]
        let ex:=mkApp (mkConst loc) call
        let hs ←ds.zipIdx.mapM fun (d,k)=>do
          let (terms,which):=if work.contains d then (atR,false) else (atL,true)
          let j:=Record.findRoot terms d
          let src:=terms[j]!
          let back ←withLocalDeclD `a src fun a=>do
            let s ←if which then pure a else mkAppM ``Iff.mpr #[convert,a]
            let full ←if reps.length==1 then pure s else do
              let iff ←mkAppOptM ``either #[reps[0]!,reps[1]!,mkApp (mkConst ``Body) b]
              let opts:=(←inferType iff).appArg!
              let o ←HandReadersBFactor.into opts s k 2
              mkAppM ``Iff.mpr #[iff,o]
            mkLambdaFVars #[a] (←HandReadersBFactor.into body (←mkAppM ``Iff.mpr #[ex,full]) i arms.length)
          let fw ←withLocalDeclD `a (←mkAppM ``Ticket #[reps[k]!,mkApp (mkConst ``Body) b]) fun a=>do
            let v ←if which then pure a else mkAppM ``Iff.mp #[convert,a]
            let joined ←HandReadersBFactor.into (Signed.disj terms) v j terms.length
            mkLambdaFVars #[a] (←HandReadersBFactor.into result joined (if which then 0 else 1) 2)
          return (j,which,back,fw)
        let mut fs := []
        for (j,which,bw,fw) in hs do
          if which then backL:=backL.push (j,bw) else backR:=backR.push (j,bw)
          fs:=fs++[fw]
        let proof ←withLocalDeclD `a arms[i]! fun a=>do
          let raw ←mkAppM ``Iff.mp #[ex,a]
          let out ←if reps.length == 1 then pure (mkApp fs.head! raw) else do
            let iff ←mkAppOptM ``either #[reps[0]!,reps[1]!,mkApp (mkConst ``Body) b]
            HandReadersBFactor.outOf (←inferType iff).appArg! (←mkAppM ``Iff.mp #[iff,raw]) result fs
          mkLambdaFVars #[a] out
        forwards:=forwards++[proof]
      let back (ls : List Expr) (hs : Array (Nat × Expr)) :=do
        let fs := (List.range ls.length).map fun i=>(hs.find? (fun pair=>pair.1==i)).get!.2
        let p:=Signed.disj ls
        withLocalDeclD `a p fun a=>do mkLambdaFVars #[a] (←HandReadersBFactor.outOf p a body fs)
      let fw ←withLocalDeclD `a body fun a=>do mkLambdaFVars #[a] (←HandReadersBFactor.outOf body a result forwards)
      let bw ←withLocalDeclD `a result fun a=>do
        mkLambdaFVars #[a] (←HandReadersBFactor.outOf result a body [←back atL backL,←back atR backR])
      addDecl (.thmDecl {
        name:=ns++(if want then `some_iff else `none_iff),levelParams:=[],type:=←mkForallFVars xs (←mkAppM ``Iff #[mkAppN (mkConst q) xs,result])
        value:=←mkLambdaFVars xs (←mkAppM ``Iff.intro #[fw,bw])})
end

end ConsensusCoverage.HandReadersTrunkD.Nominate
