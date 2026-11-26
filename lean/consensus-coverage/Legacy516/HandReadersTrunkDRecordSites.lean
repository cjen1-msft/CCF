module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkDRecordSample
import all ConsensusCoverage.HandReadersTrunkDLeaderQuery
import all ConsensusCoverage.HandReadersTrunkDLeader
import all ConsensusCoverage.HandReadersTrunkDSignatureErased
import all ConsensusCoverage.HandReadersTrunkDSignatureTransport
import all ConsensusCoverage.HandReadersOtherFoldDirect
import all ConsensusCoverage.HandReadersOtherTransferSites
import all ConsensusCoverage.HandReadersTrunkALoopGate
import all ConsensusCoverage.HandReadersTrunkAFactor
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersTrunkDSignatureTransport

namespace ConsensusCoverage.HandReadersTrunkD.Record

open Consensus Model Model.Node Proofs Safety Direct Ledger SolvedWitnesses HandReadersOther HandReadersTrunkA
open Lean Meta Elab Command
set_option maxRecDepth 16384
set_option maxHeartbeats 3000000
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)

abbrev DirectCase (b : Bool) := ∃ m n, Fold.DirectSite c m n ∧ Pick b n m
abbrev Classes (b : Bool) := Loop.Live f t c ∨ DirectCase c b ∨ Leader.Working f t c (Pick b)
end

private theorem cut_at {b n m i} (hi : i = highestCommittableIndex m n) (g : ¬highestCommittableIndex m n ≤ m.commitIndex)
    (h : cut b n m i) : Pick b n m := ⟨Nat.lt_of_not_ge g,hi ▸ h⟩

meta section
private def ns := `ConsensusCoverage.HandReadersTrunkD.Record
private def sites := Leader.kids ``step_recordCommit_eq_retire_pos
private def plain (q : Name) (xs : Array Expr) : MetaM Expr := do
  let mut b := (←getConstInfo q).value!.beta xs
  while HandReadersBPaths.reaches b do b := (←unfoldDefinition? b).get!
  return b

private def orIff (as bs hs : List Expr) : MetaM Expr := do
  unless as.length==bs.length && bs.length==hs.length do throwError "different numbers of arms"
  let mut pf := hs.getLast!
  for h in hs.dropLast.reverse do pf ←mkAppM ``or_congr #[h,pf]
  return pf

private def rawName (r : Name) := (ns++`Raw).str r.getString!
private def fullName (r : Name) := (ns++`Full).str r.getString!

-- The final follower record and the induction caller use the same accepted
-- request. The full query additionally pins the working node (including a
-- possible conflict truncation); dropping the pin preserves loop entry.
private def full (r loop : Name) : MetaM Unit := do
  lambdaTelescope (←getConstInfo r).value! fun xs _=>do
    let ctx:=xs.extract 0 4
    let self:=xs[4]!
    let q:=xs[6]!
    let body ←plain r xs
    let p := if body.isAppOfArity ``And 2 && HandReadersBPaths.reaches (body.getArg! 0) then
      body.getArg! 0 else mkAppN (mkConst r) xs
    let expanded ←plain p.getAppFn.constName! p.getAppArgs
    let lim ←mkAppM ``min #[←mkAppM ``AppendEntriesRequest.primaryCommit #[q],←mkAppM ``HAdd.hAdd #[
      ←mkAppM ``AppendEntriesRequest.prevLogIndex #[q],←mkAppM ``List.length #[←mkAppM ``AppendEntriesRequest.entries #[q]]]]
    let tgt:=mkAppN (mkConst loop) (ctx++#[self,lim])
    let loopBody ←plain loop (ctx++#[self,lim])
    let inner := loopBody.appArg!.beta #[q]
    let root := inner.getArg! 0
    let targetArms := Signed.choices (←plain root.getAppFn.constName! root.getAppArgs)
    let sourceArms := Signed.choices expanded
    let hs ←sourceArms.mapM fun a=>withLocalDeclD `h a fun h=>do
      let out ←Transfer.unpack [] a h #[] fun ds=>do
        let fs ←Signed.asFields ds
        for (b,j) in targetArms.zipIdx do
          if let some pf ←Signed.pack b fs then
            let part ←HandReadersBFactor.into (Signed.disj targetArms) pf j targetArms.length
            let val := mkApp4 (mkConst ``And.intro) root inner.appArg! part (←mkEqRefl lim)
            return ←mkExpectedTypeHint (←mkAppOptM ``Exists.intro #[none,loopBody.appArg!,q,val]) tgt
        throwError "cannot project accepted follower at {r.getString!}"
      mkLambdaFVars #[h] out
    withLocalDeclD `h (mkAppN (mkConst r) xs) fun h=>do
      let arg:=if p == mkAppN (mkConst r) xs then h else mkProj ``And 0 h
      let pf ←mkLambdaFVars (xs.push h) (←HandReadersBFactor.outOf expanded arg tgt hs)
      addDecl (.thmDecl {name:=fullName r,levelParams:=[],type:=←inferType pf,value:=pf})

-- The direct highest-index sources duplicate an existing six-way family.
-- Their sole extra data are the selected index and its signature proof.
private def direct (r : Name) (which : Nat) : MetaM Unit := do
  let root:=``step_foldl_select_max_values_cons
  let selected:= (←Leader.kids (←Leader.kids (←Leader.kids root)[4+which]!)[0]!)[0]!
  lambdaTelescope (←getConstInfo r).value! fun xs body=>do
    let ctx:=xs.extract 0 4
    let n:=xs[4]!
    let m:=xs[5]!
    let i:=xs[6]!
    let args:=ctx++#[m,n]
    let left:=mkAppN (mkConst r) xs
    let bound ←mkEq i (←mkAppM ``highestCommittableIndex #[m,n])
    let term:=mkAppN (mkConst selected) args
    let rhs:=mkApp2 (mkConst ``And) term bound
    let s:=Signed.choices body
    let b:=Signed.choices ((←getConstInfo selected).value!.beta args)
    let project (forward : Bool) (as bs : List Expr) : MetaM (List Expr) := as.mapM fun a=>withLocalDeclD `leaf a fun h=>do
      let form:=if forward then a else a.getArg! 0
      let hv:=if forward then h else mkProj ``And 0 h
      let out ←Transfer.unpack [] form hv #[] fun ds=>do
        let fs ←Signed.asFields (if forward then ds else ds.push (mkProj ``And 1 h))
        let mut fs := fs
        if !forward then
          let some (v,_) := fs.find? (fun (_,p)=>p.isAppOf ``Not) | throwError "missing high frontier"
          let g ←mkAppM ``Nat.lt_of_not_ge #[v]
          let sg ←mkAppM ``highestCommittableIndex_signature #[m,n,←mkAppM ``Nat.zero_lt_of_lt #[g]]
          fs:=fs.push (sg,←inferType sg)
        for (part,j) in bs.zipIdx do
          if let some pf ←Signed.pack part fs then
            let inj ←HandReadersBFactor.into (Signed.disj bs) pf j bs.length
            if !forward then return ←mkExpectedTypeHint inj left
            let some pin ←Signed.pack bound fs | throwError "lost maximum pin"
            return mkApp4 (mkConst ``And.intro) term bound inj pin
        throwError "missing direct maximum route at {r.getString!}"
      mkLambdaFVars #[h] out
    let fw ←project true s b
    let bw ←project false (b.map fun a=>mkApp2 (mkConst ``And) a bound) s
    let mp ←withLocalDeclD `site left fun h=>do mkLambdaFVars #[h] (←HandReadersBFactor.outOf body h rhs fw)
    let mpr ←withLocalDeclD `h rhs fun h=>do
      let fs ←b.zipIdx.mapM fun (v,j)=>withLocalDeclD `s v fun s=>do
        mkLambdaFVars #[s] (mkApp bw[j]! (mkApp4 (mkConst ``And.intro) v bound s (mkProj ``And 1 h)))
      mkLambdaFVars #[h] (←HandReadersBFactor.outOf (Signed.disj b) (mkProj ``And 0 h) left fs)
    addDecl (.thmDecl {
      name:=rawName r,levelParams:=[],type:=←mkForallFVars xs (←mkAppM ``Iff #[left,rhs])
      value:=←mkLambdaFVars xs (←mkAppM ``Iff.intro #[mp,mpr])})

run_cmd liftTermElabM do
  let ss ←sites
  for (r,i) in ss.toList.zipIdx do
    let ds ←Leader.kids r
    if i < 2 then
      for d in ds.extract 0 2 do direct d i
    if i == 0 || (2 ≤ i && i ≤ 26) then full (if i == 0 then ds[2]! else ds[0]!) ds.back!
end

end ConsensusCoverage.HandReadersTrunkD.Record
