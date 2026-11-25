module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkDSignatureData
import all ConsensusCoverage.HandReadersTrunkDTermSites
import all ConsensusCoverage.HandReadersOtherTransferSites
import all ConsensusCoverage.HandReadersOtherFactsSites
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersTrunkDSignatureData
public meta import ConsensusCoverage.HandReadersTrunkDTermSites

namespace ConsensusCoverage.HandReadersTrunkD.Signed

open Consensus Model Model.Node Proofs Safety Ledger SolvedWitnesses Lean Meta Elab Command
open HandReadersOther
set_option maxRecDepth 16384
set_option maxHeartbeats 3000000

private theorem lengthTaken {l i} (sg : isSignatureAt l i = true) : i ≤ (l.take i).length :=
  Nat.le_of_eq (List.length_take_of_le (signature_bound sg)).symm
private theorem kept {l i st} (sg : isSignatureAt l i = true) (sub : l.take i <+: st) :
    isSignatureAt st i = true := isSignatureAt_of_prefix sub (isSignatureAt_take_of_le Nat.le.refl sg)

meta section
private def extras (xs : Array (Expr × Expr)) : MetaM (Array (Expr × Expr)) := do
  let mut more := #[]
  for (h,p) in xs do
    if p.isAppOfArity ``Ne 3 || p.isAppOfArity ``Not 1 then
      if let some hi ← observing? (mkAppM ``Nat.pos_of_ne_zero #[h]) then more := more.push hi
    if p.isAppOfArity ``Eq 3 && (p.getArg! 1).isAppOf ``isSignatureAt then
      more := more.push (←mkAppM ``lengthTaken #[h])
      for (sub,q) in xs do
        if q.isAppOf ``List.IsPrefix then
          if let some out ←observing? (mkAppM ``kept #[h,sub]) then more := more.push out
  return xs ++ (←more.mapM fun v=>do return (v,←inferType v))

-- Match common witness binders before projecting a different right spine.
-- No search bounds are used in either direction.
private partial def align (p h q : Expr) (known : Array Expr) : MetaM Expr := do
  if p == q then return h
  if p.isAppOfArity ``Exists 2 && q.isAppOfArity ``Exists 2 && (←isDefEq (p.getArg! 0) (q.getArg! 0)) then
    return ←withLocalDeclD `w (p.getArg! 0) fun w=>do
      let a := p.appArg!.beta #[w]
      withLocalDeclD `hw a fun hw=>do
        let b ←align a hw (q.appArg!.beta #[w]) (known.push w)
        let sub ←mkAppOptM ``Exists.intro #[none,q.appArg!,w,b]
        return ProofWalk.casesExists p h q (←mkLambdaFVars #[w,hw] sub)
  if p.isAppOfArity ``And 2 && q.isAppOfArity ``And 2 && p.getArg! 0 == q.getArg! 0 then
    let h0 := mkProj ``And 0 h
    let b ←align p.appArg! (mkProj ``And 1 h) q.appArg! (known.push h0)
    return mkApp4 (mkConst ``And.intro) (q.getArg! 0) q.appArg! h0 b
  Transfer.unpack [] p h known fun xs=>do
    let fs ←extras (←xs.mapM fun x=>do return (x,←inferType x))
    let some proof ←HandReadersTrunkD.Term.fields q fs | throwError "unmatched signed-index premise {q.getAppFn}"
    mkExpectedTypeHint proof q

private def choices (p : Expr) := HandReadersBFactor.disjuncts p
private def deps (p : Expr) := ReachPath.children `ConsensusCoverage.SolvedWitnesses p

run_cmd liftTermElabM do
  let ci ←getConstInfo ``Erased
  lambdaTelescope ci.value! fun xs es => do
    let es' := choices es
    let qs := [``NonRanking,``step_maxCommittableIndex_le_of_prefix_zero_neg,``step_rankAtGrant_persist_inl]
    let ts := qs.map fun q=>mkAppN (mkConst q) xs
    let target := disj ts
    let bodies ←qs.mapM fun q=>do return (←getConstInfo q).value!.beta xs
    let rows := bodies.map choices
    let fw ←es'.mapM fun e=>withLocalDeclD `e e fun he=>do
      let b := (←getConstInfo e.getAppFn.constName!).value!.beta xs
      let leaves := choices b
      let hs ←leaves.mapM fun p=>withLocalDeclD `h p fun h=>do
        for (ls,i) in rows.zipIdx do
          for (v,j) in ls.zipIdx do
            if deps p != deps v then continue
            if let some val ←observing? (align p h v #[]) then
              let arm ← HandReadersBFactor.into bodies[i]! val j ls.length
              return ←mkLambdaFVars #[h] (←HandReadersBFactor.into target arm i ts.length)
        throwError "no destination for {e.getAppFn}.{leaves.idxOf p}"
      mkLambdaFVars #[he] (←HandReadersBFactor.outOf b he target hs)
    let bw ←ts.zipIdx.mapM fun (t,i)=>withLocalDeclD `t t fun ht=>do
      let ls := rows[i]!
      let sub ←ls.mapM fun p=>withLocalDeclD `h p fun h=>do
        for (e,j) in es'.zipIdx do
          let b := (←getConstInfo e.getAppFn.constName!).value!.beta xs
          let bs := choices b
          for (a,k) in bs.zipIdx do
            if deps a != deps p then continue
            if let some val ←observing? (align p h a #[]) then
              let arm ←HandReadersBFactor.into b val k bs.length
              return ←mkLambdaFVars #[h] (←HandReadersBFactor.into es arm j es'.length)
        throwError "missing erased source for {qs[i]!}.{ls.idxOf p}"
      mkLambdaFVars #[ht] (←HandReadersBFactor.outOf bodies[i]! ht es sub)
    let lhs := mkAppN (mkConst ``Erased) xs
    let f ←withLocalDeclD `h lhs fun h=>do mkLambdaFVars #[h] (←HandReadersBFactor.outOf es h target fw)
    let b ←withLocalDeclD `h target fun h=>do mkLambdaFVars #[h] (←HandReadersBFactor.outOf target h lhs bw)
    addDecl (.thmDecl {
      name:=ns++`erased_iff,levelParams:=[],type:=←mkForallFVars xs (←mkAppM ``Iff #[lhs,target])
      value:=←mkLambdaFVars xs (←mkAppM ``Iff.intro #[f,b])})
end

end ConsensusCoverage.HandReadersTrunkD.Signed
