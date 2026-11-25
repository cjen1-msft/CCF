module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkDSignatureData
import all ConsensusCoverage.HandReadersTrunkDSignatureTransport
import all ConsensusCoverage.HandReadersOtherTransferSites
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.ProofWalk
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersTrunkDSignatureTransport

namespace ConsensusCoverage.HandReadersTrunkD.Signed

open Consensus Model Model.Node Proofs Safety Ledger SolvedWitnesses Lean Meta Elab Command
set_option maxRecDepth 8192
set_option maxHeartbeats 3000000

private theorem signedValid {l i} (sg : isSignatureAt l i = true) : Valid l i := ⟨sg,signature_bound sg⟩
private theorem partEquiv {R : List Entry → List Entry → Prop} {E : Prop}
    (eq : (∃ p l, R p l ∧ Part p l) ↔ E) :
    (∃ l i, (∃ p, R p l ∧ p <+: l ∧ isSignatureAt p p.length = true ∧ i = p.length) ∧ Valid l i) ↔ E := by
  apply Iff.trans _ eq
  exact ⟨fun ⟨l,_,⟨p,r,sub,sg,_⟩,_⟩ => ⟨p,l,r,sub,sg⟩,
    fun ⟨p,l,r,g⟩ => ⟨l,p.length,⟨p,r,g.1,g.2,rfl⟩,partValid g⟩⟩

private theorem mapValid {R S : List Entry → Nat → Prop} :
    (∃ l i, (R l i ∨ S l i) ∧ Valid l i) ↔ (∃ l i, R l i ∧ Valid l i) ∨ (∃ l i, S l i ∧ Valid l i) := by
  constructor
  · rintro ⟨l,i,h | h,v⟩ <;> first | exact .inl ⟨l,i,h,v⟩ | exact .inr ⟨l,i,h,v⟩
  · rintro (⟨l,i,h,v⟩ | ⟨l,i,h,v⟩) <;> first | exact ⟨l,i,.inl h,v⟩ | exact ⟨l,i,.inr h,v⟩

meta section
private def validPred (l i b : Expr) := mkLambdaFVars #[l,i] b

private def liftValid (R : Expr) : MetaM Expr := do
  let ty ←inferType R
  withLocalDeclD `l ty.bindingDomain! fun l=>withLocalDeclD `i (mkConst ``Nat) fun i=>do
    let cell := mkApp2 (mkConst ``And) (mkApp2 R l i).headBeta (mkApp2 (mkConst ``Valid) l i)
    mkLambdaFVars #[i] cell >>= fun b=>mkAppM ``Exists #[b] >>= fun b=>mkLambdaFVars #[l] b >>= fun b=>mkAppM ``Exists #[b]

private def siteIff (r : Name) := (ns++`Indexed).str (r.getString! ++ "_iff")

private def certifySite (r e : Name) : MetaM Unit := do
  let ci ←getConstInfo r
  lambdaTelescope ci.value! fun xs indexed => do
    let ctx := xs.extract 0 4
    let l := xs[4]!
    let i := xs[5]!
    let erased := (←getConstInfo e).value!.beta ctx
    let mut alts := #[]
    let mut eqs := #[]
    let is := choices indexed
    let es := choices erased
    unless is.length == es.length do throwError "indexed/erased alternatives disagree"
    for (a,b) in is.zip es do
      let source ←validPred l i a
      let left ←instantiateMVars (←liftValid source)
      let #[d] := deps a | throwError "expected one indexed origin"
      let de := deepIff d
      let proof ← if (←getEnv).contains de then
        mkAppM ``partEquiv #[mkAppN (mkConst de) ctx]
      else do
        let fw ←withLocalDeclD `h left fun h=>do
          let rec peel (v pr : Expr) (depth : Nat) (ys : Array Expr) : MetaM Expr := do
            if depth > 0 then return ← withLocalDeclD `w (v.getArg! 0) fun w=>do
              let ty := v.appArg!.beta #[w]
              withLocalDeclD `h ty fun hw=>do
                let pf ←peel ty hw (depth-1) (ys.push w)
                return ProofWalk.casesExists v pr b (←mkLambdaFVars #[w,hw] pf)
            HandReadersOther.Transfer.unpack [] (v.getArg! 0) (mkProj ``And 0 pr) ys fun data=>do
              let some pf ←pack b (←asFields data) | throwError "cannot forget index at {r.getString!}.{is.idxOf a}"
              mkExpectedTypeHint pf b
          mkLambdaFVars #[h] (←peel left h 2 #[])
        let bw ←withLocalDeclD `h b fun h=>do
          let out ←HandReadersOther.Transfer.unpack [] b h #[] fun data=>do
            let fs ←asFields data
            let mut good := #[]
            for (v,ty) in fs do
              if ty.isAppOfArity ``Eq 3 && (ty.getArg! 1).isAppOf ``isSignatureAt then
                good := good.push (←mkAppM ``signedValid #[v])
              if ty.isAppOf ``LT.lt || ty.isAppOf ``GT.gt then
                if let some pf ←observing? (mkAppM ``electionValid #[ctx[3]!,v]) then good := good.push pf
                for (s,qt) in fs do
                  if qt.isAppOf ``List.IsPrefix then
                    if let some pf ←observing? (mkAppM ``prefixValid #[s,v]) then good := good.push pf
            for cut in good do
              let ty ←instantiateMVars (←inferType cut)
              let args := ty.getAppArgs
              let u := args[args.size-2]!
              let j := args.back!
              if let some pf ←pack (a.replaceFVars #[l,i] #[u,j]) fs then
                let prod ←mkAppM ``And.intro #[pf,cut]
                let inner := left.appArg!.beta #[u]
                let ex ←mkAppOptM ``Exists.intro #[none,inner.appArg!,j,prod]
                return ←mkAppOptM ``Exists.intro #[none,left.appArg!,u,ex]
            throwError "cannot recover signed index {r.getString!}.{is.idxOf a}"
          mkLambdaFVars #[h] out
        mkAppM ``Iff.intro #[fw,bw]
      alts:=alts.push a; eqs:=eqs.push proof
    let mut rest := alts.back!
    let mut pf := eqs.back!
    for (a,h) in alts.pop.zip eqs.pop |>.toList.reverse do
      let split ←mkAppOptM ``mapValid #[←validPred l i a,←validPred l i rest]
      pf ←mkAppM ``Iff.trans #[split,←mkAppM ``or_congr #[h,pf]]
      rest := mkApp2 (mkConst ``Or) a rest
    let lhs ←liftValid (mkAppN (mkConst r) ctx)
    addDecl (.thmDecl {
      name:=siteIff r,levelParams:=[],type:=←mkForallFVars ctx (←mkAppM ``Iff #[lhs,mkAppN (mkConst e) ctx])
      value:=←mkLambdaFVars ctx pf})

run_cmd liftTermElabM do
  for (r,e) in (←indexedSites).zip (←erasedSites) do certifySite r e
end

end ConsensusCoverage.HandReadersTrunkD.Signed
