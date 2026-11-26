module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkDRecordSites
import all ConsensusCoverage.HandReadersTrunkDRecordSample
import all ConsensusCoverage.HandReadersTrunkDLeaderQuery
import all ConsensusCoverage.HandReadersTrunkDLeader
import all ConsensusCoverage.HandReadersTrunkDSignatureTransport
import all ConsensusCoverage.HandReadersOtherFoldDirect
import all ConsensusCoverage.HandReadersOtherTransferSites
import all ConsensusCoverage.HandReadersTrunkALoopGate
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersTrunkDRecordSites

namespace ConsensusCoverage.HandReadersTrunkD.Record

open Consensus Model Model.Node Proofs Safety Direct Ledger SolvedWitnesses HandReadersOther HandReadersTrunkA
open Lean Meta Elab Command
set_option maxRecDepth 16384
set_option maxHeartbeats 3000000
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private def column (b : Bool) : ConsensusCoverage.Classes.StepBranch :=
  if b then .recordCommit_eq_retire_pos else .recordCommit_eq_retire_neg

private theorem positives {R : NodeID → NodeState → Nat → Prop} :
    (∃ n m i, R n m i ∧ (!m.retiredCommittedIndex.isSome) = true ∧ (latched n m i).isRetiredCommitted n) ↔
    ∃ n m i, R n m i ∧ cut true n m i := by simp only [cut,beq_iff_eq,decide_eq_true_eq]; rfl
private theorem negatives {R : NodeID → NodeState → Nat → Prop} :
    (∃ n m i, R n m i ∧ ¬((!m.retiredCommittedIndex.isSome) = true ∧ (latched n m i).isRetiredCommitted n)) ↔
    ∃ n m i, R n m i ∧ cut false n m i := by simp only [cut,beq_iff_eq,decide_eq_false_iff_not]; rfl

private theorem leaderUpper {R : NodeID → NodeState → Prop} {n s i b} (cut' : cut b n s i)
    {m} (h : R n m) (g : ¬highestCommittableIndex m n ≤ m.commitIndex)
    (meq : s = m) (idx : i = highestCommittableIndex m n) : ∃ n m, R n m ∧ Pick b n m := by
  subst s; exact ⟨n,m,h,cut_at idx g cut'⟩

private theorem directUpper [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)
    {n s i b} (cut' : cut b n s i) (co : Fold.DirectSite c s n) (pin : i = highestCommittableIndex s n) :
    DirectCase c b := by
  have g : Leader.Growth n s := by
    repeat' (change _ ∨ _ at co; rcases co with co | co)
    all_goals exact Nat.lt_of_not_ge co.2.1
  exact ⟨s,n,co,g,pin ▸ cut'⟩

private theorem lowerRetire (n : NodeID) (m : NodeState) (g : Leader.Growth n m) :
    (¬ highestCommittableIndex m n ≤ m.commitIndex ∧ (m.recordCommit n (highestCommittableIndex m n)).isRetiredCommitted n ∧
      m.role = .primary ∧ ∃ sent : List Model.Envelope, m.role = .primary ∧
        ∀ e ∈ sent, e.source = n ∧ e.payload = .proposeRequestVoteRequest m.currentTerm) ∨
    (¬highestCommittableIndex m n ≤ m.commitIndex ∧ (m.recordCommit n (highestCommittableIndex m n)).isRetiredCommitted n ∧
      ¬m.role = .primary) ∨
    (¬highestCommittableIndex m n ≤ m.commitIndex ∧ ¬(m.recordCommit n (highestCommittableIndex m n)).isRetiredCommitted n) := by
  by_cases ret : (m.recordCommit n (highestCommittableIndex m n)).isRetiredCommitted n
  · by_cases pr : m.role = .primary
    · exact .inl ⟨Nat.not_le_of_gt g,ret,pr,[],pr,by simp⟩
    · exact .inr (.inl ⟨Nat.not_le_of_gt g,ret,pr⟩)
  · exact .inr (.inr ⟨Nat.not_le_of_gt g,ret⟩)

meta section
private def tickets (b : Expr) (rs : Array Expr) : MetaM (Array Expr) := rs.mapM fun r=>do
  let ty ←inferType r
  forallTelescope ty fun vs _=>do
    unless vs.size == 3 do throwError "expected three record fields"
    let v:=mkApp2 (mkConst ``And) (mkAppN r vs) (←mkEq (mkAppN (mkConst ``cut) (#[b]++vs)) (toExpr true))
    vs.foldrM (fun x p=>mkLambdaFVars #[x] p >>= fun f=>mkAppM ``Exists #[f]) v

private def join (ps : List Expr) (a h : Expr) : MetaM Expr := do
  let some j := ps.findIdx? (· == a) | throwError "missing phase alternative"
  HandReadersBFactor.into (Signed.disj ps) h j ps.length

private def pack3 (p n s i site cut : Expr) : MetaM Expr := do
  let p1 := p.appArg!.beta #[n]
  let p2 := p1.appArg!.beta #[s]
  let prod ←mkAppM ``And.intro #[site,cut]
  let x ←mkAppOptM ``Exists.intro #[none,p2.appArg!,i,prod]
  let y ←mkAppOptM ``Exists.intro #[none,p1.appArg!,s,x]
  mkAppOptM ``Exists.intro #[none,p.appArg!,n,y]

private def expand (p : Expr) : MetaM Expr := do return (←getConstInfo p.getAppFn.constName!).value!.beta p.getAppArgs

private def pieces (xs : Array Expr) : MetaM (Array Expr × List Expr × List Expr) := do
  let ctx:=xs.extract 0 4
  let b:=xs[4]!
  let c:=xs[3]!
  let direct ←mkAppM ``DirectCase #[c,b]
  let top:=[mkAppN (mkConst ``Loop.Live) ctx,direct,mkAppN (mkConst ``Leader.Working) (ctx.push (mkApp (mkConst ``Pick) b))]
  let loops:=Signed.choices (←expand top[0]!)
  let leaders:=Signed.choices (←expand top[2]!)
  return (top.toArray,loops,leaders)

private def findRoot (ps : List Expr) (r : Name) : Nat := ps.findIdx fun p=>p.getUsedConstants.contains r

private def upper (q : Name) (xs : Array Expr) (p : Expr) : MetaM Expr := do
  let ctx:=xs.extract 0 4
  let c:=xs[3]!
  let b:=xs[4]!
  let (top,lps,sps) ← pieces xs
  let dest := Signed.disj top.toList
  let rts ←Leader.sources
  let lts ←Leader.kids ``step_fromLeader_loop_entries_cons
  let pred:=mkAppN (mkConst q) ctx
  let ty ←inferType pred
  forallTelescope ty fun args _=>do
    let n:=args[0]!
    let m:=args[1]!
    let i:=args[2]!
    let raw:=mkAppN pred args
    let body ←expand raw
    let cut ←mkEq (mkAppN (mkConst ``cut) (#[b]++args)) (toExpr true)
    withLocalDeclD `chosen cut fun cut'=>do
      let leaves:=Signed.choices body
      let fs ←leaves.mapM fun a=>withLocalDeclD `origin a fun h=>do
        let g ←Transfer.unpack [] a h #[] fun data=>do
          let facts ←Signed.asFields data
          let some (co,t) := facts.find? (fun (_,p)=>HandReadersBPaths.reaches p) | throwError "untagged record origin"
          let r:=t.getAppFn.constName!
          let idx:=t.getAppArgs
          if (←getEnv).contains (rawName r) then
            let split ←mkAppM ``Iff.mp #[mkAppN (mkConst (rawName r)) idx,co]
            let s ←mkAppM ``And.left #[split]
            let d ←mkAppM ``And.right #[split]
            let dt ←mkAppM ``Fold.DirectSite #[c,m,n] >>= expand
            let branches := [dt.getArg! 0,dt.appArg!]
            let which := if (←inferType s).getAppFn == branches[0]!.getAppFn then 0 else 1
            let both ← HandReadersBFactor.into dt s which 2
            let dr ←mkAppM ``directUpper #[c,cut',both,d]
            return ←HandReadersBFactor.into dest dr 1 3
          if lts.contains r || (←getEnv).contains (fullName r) then
            let call:=if lts.contains r then co else mkAppN (mkConst (fullName r)) (idx.push co)
            let t ←inferType call
            let j:=findRoot lps t.getAppFn.constName!
            let a:=lps[j]!
            let vals:=t.getAppArgs
            let h ←mkAppOptM ``Exists.intro #[none,(a.appArg!.beta #[vals[4]!]).appArg!,vals[5]!,call]
            let h ←mkAppOptM ``Exists.intro #[none,a.appArg!,vals[4]!,h]
            let live ←HandReadersBFactor.into (Signed.disj lps) h j lps.length
            return ←HandReadersBFactor.into dest live 0 3
          unless rts.contains r do throwError "unexpected leader source {r}"
          let mid:=idx[5]!
          let neg:=mkNot (←mkAppM ``LE.le #[←mkAppM ``highestCommittableIndex #[mid,n],←mkAppM ``NodeState.commitIndex #[mid]])
          let args:=#[t,neg,←mkEq m mid,←mkEq i (←mkAppM ``highestCommittableIndex #[mid,n])]
          let #[site,gt,eq,index] ←args.mapM (fun g=>do
            let some h ←Signed.pack g facts | throwError "missing leader field {g.getAppFn}"
            return h) | throwError "bad arity"
          let fn:=mkAppN (mkConst r) ctx
          let collect ←mkAppOptM ``leaderUpper #[fn,n,m,i,b,cut',mid,site,gt,eq,index]
          let working ←HandReadersBFactor.into (Signed.disj sps) collect (findRoot sps r) sps.length
          return ←HandReadersBFactor.into dest working 2 3
        mkLambdaFVars #[h] g
      let mp ←withLocalDeclD `site raw fun h=>do mkLambdaFVars #[h,cut'] (←HandReadersBFactor.outOf body h dest fs)
      let fn ←mkLambdaFVars args mp
      withLocalDeclD `u p fun u=>do
        let rec intro (p h : Expr) (args : Array Expr) (depth : Nat) : MetaM Expr := do
          if depth > 0 then return ←withLocalDeclD `w (p.getArg! 0) fun w=>do
            let a:=p.appArg!.beta #[w]
            withLocalDeclD `v a fun v=>do return ProofWalk.casesExists p h dest (←mkLambdaFVars #[w,v] (←intro a v (args.push w) (depth-1)))
          return mkAppN fn (args ++ #[mkProj ``And 0 h,mkProj ``And 1 h])
        mkLambdaFVars #[u] (←intro p u #[] 3)

run_cmd liftTermElabM do
  lambdaTelescope (←getConstInfo ``Classes).value! fun xs _=>do
    let ctx:=xs.extract 0 4
    let cs ←sites
    let es ←tickets xs[4]! (cs.map fun r=>mkAppN (mkConst r) ctx)
    let ty:=Signed.disj es.toList
    let name:=ns++`Tickets
    addDecl (.defnDecl {name,levelParams:=[],type:=←mkForallFVars xs (mkSort .zero),value:=←mkLambdaFVars xs ty,hints:=.abbrev,safety:=.safe})
    let fs ←(cs.zip es).mapM fun (r,p)=>upper r xs p
    let t:=mkAppN (mkConst ``Classes) xs
    withLocalDeclD `h (mkAppN (mkConst name) xs) fun h=>do
      let v ←mkLambdaFVars (xs.push h) (←HandReadersBFactor.outOf ty h t fs.toList)
      addDecl (.thmDecl {name:=ns++`necessary,levelParams:=[],type:=←inferType v,value:=v})

  for (b,q,r) in [(true,``step_recordCommit_eq_retire_pos,``positives),(false,``step_recordCommit_eq_retire_neg,``negatives)] do
    lambdaTelescope (←getConstInfo q).value! fun xs body=>do
      let cs ←sites
      let es:=Signed.choices body
      let ts ←tickets (toExpr b) (cs.map fun n=>mkAppN (mkConst n) xs)
      let pf ←orIff es ts.toList (cs.toList.map fun n=>mkApp (mkConst r) (mkAppN (mkConst n) xs))
      addDecl (.thmDecl {
        name:=ns++(if b then `positive_iff else `negative_iff),levelParams:=[]
        type:=←mkForallFVars xs (←mkAppM ``Iff #[mkAppN (mkConst q) xs,mkAppN (mkConst (ns++`Tickets)) (xs.push (toExpr b))])
        value:=←mkLambdaFVars xs pf})
end

end ConsensusCoverage.HandReadersTrunkD.Record
