module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkDRecordRoute
import all ConsensusCoverage.HandReadersTrunkDRecordSites
import all ConsensusCoverage.HandReadersTrunkDRecordSample
import all ConsensusCoverage.HandReadersTrunkDLeaderQuery
import all ConsensusCoverage.HandReadersTrunkDSignatureTransport
import all ConsensusCoverage.HandReadersOtherFoldDirect
import all ConsensusCoverage.HandReadersTrunkALoopGate
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersTrunkDRecordRoute

namespace ConsensusCoverage.HandReadersTrunkD.Record

open Consensus Model Model.Node Proofs Safety SolvedWitnesses HandReadersOther HandReadersTrunkA
open Lean Meta Elab Command
set_option maxRecDepth 16384
set_option maxHeartbeats 3200000

private theorem leaderEmit (R : NodeID → NodeState → Prop) {n m} (h : R n m) (g : Leader.Growth n m)
    (ret : (m.recordCommit n (highestCommittableIndex m n)).isRetiredCommitted n) (pr : m.role = .primary) :
    ∃ mid, R n mid ∧ ¬highestCommittableIndex mid n ≤ mid.commitIndex ∧
      (mid.recordCommit n (highestCommittableIndex mid n)).isRetiredCommitted n ∧ mid.role = .primary ∧
      ∃ sent : List Model.Envelope, (mid.role = .primary ∧ ∀ e ∈ sent, e.source = n ∧
        e.payload = .proposeRequestVoteRequest mid.currentTerm) ∧ m = mid ∧
        highestCommittableIndex m n = highestCommittableIndex mid n :=
  ⟨m,h,Nat.not_le_of_gt g,ret,pr,[],⟨pr,by simp⟩,rfl,rfl⟩

meta section
private def insertAt (xs : Array Expr) (n m i : Expr) (make : Expr → MetaM (Option Expr)) : MetaM Expr := do
  let ctx:=xs.extract 0 4
  let rs ←sites
  let ts ←tickets xs[4]! (rs.map fun r=>mkAppN (mkConst r) ctx)
  for (r,j) in rs.toList.zipIdx do
    let raw:=mkAppN (mkConst r) (ctx++#[n,m,i])
    let body ←expand raw
    let as:=Signed.choices body
    for (a,k) in as.zipIdx do
      if let some p ←make a then
        let proof ←HandReadersBFactor.into body p k as.length
        let b:=ts[j]!.appArg!.beta #[n] |>.appArg!.beta #[m] |>.appArg!.beta #[i]
        let pred ←mkLambdaFVars #[] b.appArg!
        return ←withLocalDeclD `cut pred fun cut=>do
          let out ←pack3 ts[j]! n m i proof cut
          mkLambdaFVars #[cut] (←HandReadersBFactor.into (Signed.disj ts.toList) out j ts.size)
  throwError "no normalized witness at selected site"

private def supplyLoop (xs : Array Expr) (loop : Expr) : MetaM Expr := do
  let b:=xs[4]!
  let dest:=mkAppN (mkConst ``Tickets) xs
  let clauses:=Signed.choices (←expand loop)
  let hs ←clauses.mapM fun a=>withLocalDeclD `site a fun h=>do
    let out ←Transfer.unpack [] a h #[] fun data=>do
      let #[n,k,origin] := data | throwError "unexpected loop origin"
      let src ←inferType origin
      let someVal ←mkAppM ``follower #[n,k,b]
      let p ←inferType someVal
      Transfer.unpack [] p someVal #[] fun ds=>do
        let #[m,i,call,cut] := ds | throwError "unexpected synthetic follower"
        let pkg ←insertAt xs n m i fun a=>do
          unless a.isAppOfArity ``Exists 2 && (Signed.deps a).contains src.getAppFn.constName! do return none
          let ty:=a.appArg!.beta #[k]
          let pair:=mkApp4 (mkConst ``And.intro) (ty.getArg! 0) ty.appArg! origin call
          return some (←mkAppOptM ``Exists.intro #[none,a.appArg!,k,pair])
        mkExpectedTypeHint (mkApp pkg cut) dest
    mkLambdaFVars #[h] out
  withLocalDeclD `loop loop fun h=>do
    mkLambdaFVars #[h] (←HandReadersBFactor.outOf (Signed.disj clauses) h dest hs)

private def supplyDirect (xs : Array Expr) (direct : Expr) : MetaM Expr := do
  let ctx:=xs.extract 0 4
  let dest:=mkAppN (mkConst ``Tickets) xs
  withLocalDeclD `d direct fun h=>do
    let body ←expand direct
    let out ←Transfer.unpack [] body h #[] fun ds=>do
      let #[m,n,co,guard] := ds | throwError "unexpected direct evidence"
      let high ←mkAppM ``highestCommittableIndex #[m,n]
      let cut ←mkAppM ``And.right #[guard]
      let split ←expand (←inferType co)
      let lhs:=Signed.choices split
      let fs ←lhs.mapM fun q=>withLocalDeclD `s q fun s=>do
        let pkg ←insertAt xs n m high fun a=>do
          let some r:=a.getAppFn.constName? | return none
          unless (←getEnv).contains (rawName r) do return none
          let eq:=mkAppN (mkConst (rawName r)) (ctx++#[n,m,high])
          let rhs := (←inferType eq).appArg!
          unless (rhs.getArg! 0).getAppFn == q.getAppFn do return none
          let both:=mkApp4 (mkConst ``And.intro) (rhs.getArg! 0) rhs.appArg! s (←mkEqRefl high)
          return some (←mkAppM ``Iff.mpr #[eq,both])
        mkLambdaFVars #[s] (mkApp pkg cut)
      HandReadersBFactor.outOf split co dest fs
    mkLambdaFVars #[h] out

private def supplyLeader (xs : Array Expr) (leader : Expr) : MetaM Expr := do
  let dest:=mkAppN (mkConst ``Tickets) xs
  let rhs ←expand leader
  let clauses:=Signed.choices rhs
  let fs ←clauses.mapM fun q=>withLocalDeclD `q q fun origin=>do
    let p ←Transfer.unpack [] q origin #[] fun ds=>do
      let #[n,m,site,pick] :=ds | throwError "unexpected leader evidence"
      let high ←mkAppM ``highestCommittableIndex #[m,n]
      let g ←mkAppM ``And.left #[pick]
      let cut ←mkAppM ``And.right #[pick]
      let h ←mkAppM ``lowerRetire #[n,m,g]
      let choices ←inferType h
      let ps:=Signed.choices choices
      let hs ←ps.mapM fun leaf=>withLocalDeclD `leaf leaf fun l=>do
        let pr ←Transfer.unpack [] leaf l #[n,m,site] fun args=>do
          let ff ←Signed.asFields args
          let sr ←inferType site
          let fn := mkAppN sr.getAppFn (xs.extract 0 4)
          let pkg ←insertAt xs n m high fun a=>do
            unless (Signed.deps a).contains sr.getAppFn.constName! do return none
            if leaf == ps[0]! then
              let pr ←mkAppM ``leaderEmit #[fn,site,g,mkProj ``And 0 (mkProj ``And 1 l),
                mkProj ``And 0 (mkProj ``And 1 (mkProj ``And 1 l))]
              if ←isDefEq (←inferType pr) a then return some pr
            Signed.pack a ff
          mkExpectedTypeHint (mkApp pkg cut) dest
        mkLambdaFVars #[l] pr
      HandReadersBFactor.outOf choices h dest hs
    mkLambdaFVars #[origin] p
  withLocalDeclD `site leader fun h=>do mkLambdaFVars #[h] (←HandReadersBFactor.outOf rhs h dest fs)

run_cmd liftTermElabM do
  lambdaTelescope (←getConstInfo ``Classes).value! fun xs cs=>do
    let (as,_,_) ←pieces xs
    let fs := [←supplyLoop xs as[0]!,←supplyDirect xs as[1]!,←supplyLeader xs as[2]!]
    let dest:=mkAppN (mkConst ``Tickets) xs
    let pf ←withLocalDeclD `h (mkAppN (mkConst ``Classes) xs) fun h=>do
      mkLambdaFVars (xs.push h) (←HandReadersBFactor.outOf cs h dest fs)
    addDecl (.thmDecl {name:=ns++`sufficient,levelParams:=[],type:=←inferType pf,value:=pf})
end

end ConsensusCoverage.HandReadersTrunkD.Record
