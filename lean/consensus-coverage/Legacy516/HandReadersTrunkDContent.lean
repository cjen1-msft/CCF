module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkDSignature
import all ConsensusCoverage.HandReadersTrunkDSignatureData
import all ConsensusCoverage.HandReadersTrunkDSignatureErased
import all ConsensusCoverage.HandReadersTrunkDSignatureSites
import all ConsensusCoverage.HandReadersTrunkDSignatureTransport
import all ConsensusCoverage.HandReadersTrunkAFactor
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.PromotionImpossibleB
import all ConsensusCoverage.DeepSignedCases
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersTrunkDSignatureSites
public meta import ConsensusCoverage.PromotionImpossibleB

namespace ConsensusCoverage.HandReadersTrunkD.Content

open Consensus Model Model.Node Proofs Safety Ledger SolvedWitnesses Lean Meta Elab Command
set_option maxRecDepth 16384
set_option maxHeartbeats 3500000

private abbrev Input := List Entry → Nat → Prop
private abbrev Called (R : Input) := ∃ l i, R l i

private theorem strict {st self l i} (lt : st.commitIndex < highestCommittableIndex st self)
    (log : l = st.log) (idx : i = highestCommittableIndex st self) : isSignatureAt l i = true :=
  log ▸ idx ▸ (highestCommittableIndex_spec st self lt).2.1

private theorem forgetLookup (R : Input) (found : ∀ l i, R l i → isSignatureAt l i = true) :
    (∃ l i, R l i ∧ ∃ v, entryAt? l i = some v ∧ entryAt? l i = some v ∧ isSignatureAt l i = true) ↔ Called R := by
  constructor
  · rintro ⟨l,i,h,_⟩; exact ⟨l,i,h⟩
  · rintro ⟨l,i,h⟩
    have sg := found l i h
    obtain ⟨e,mem,_⟩ := isSignatureAtTrue sg
    exact ⟨l,i,h,e,mem,mem,sg⟩

private theorem calledOr (R S : Input) : Called (fun l i=>R l i ∨ S l i) ↔ Called R ∨ Called S :=
  ⟨fun ⟨l,i,h⟩ => h.elim (fun r=>.inl ⟨l,i,r⟩) (fun s=>.inr ⟨l,i,s⟩),
    fun h=>h.elim (fun ⟨l,i,r⟩=>⟨l,i,.inl r⟩) (fun ⟨l,i,s⟩=>⟨l,i,.inr s⟩)⟩

private theorem foldCalled (R : Input) :
    Called (fun l i=>R l i ∧ isSignatureAt l i = true ∧
      ∀ (values : List Nat) best, best ≤ values.foldl
        (fun b j=>if isSignatureAt l j then max b j else b) best) ↔ ∃ l i, R l i ∧ Signed.Valid l i :=
  ⟨fun ⟨l,i,h,sg,_⟩=>⟨l,i,h,sg,signature_bound sg⟩,
    fun ⟨l,i,h,sg,_⟩=>⟨l,i,h,sg,DeepSignedCases.above l⟩⟩

meta section
private def ns := `ConsensusCoverage.HandReadersTrunkD.Content
private def children (q : Name) : MetaM (Array Name) := do
  return ReachPath.children q.getPrefix (←getConstInfo q).value!

private def signedAt (l i : Expr) (fs : PromotionImpossibleB.Fields) : MetaM Expr := do
  let wanted ←mkEq (←mkAppM ``isSignatureAt #[l,i]) (toExpr true)
  for (p,h) in fs do if p == wanted then return h
  let some (_,a):=fs.find? (fun (p,_)=>p.isAppOfArity ``Eq 3 && p.getArg! 1 == l) | throwError "unbound signature log"
  let some (_,b):=fs.find? (fun (p,_)=>p.isAppOfArity ``Eq 3 && p.getArg! 1 == i) | throwError "unbound signature index"
  for (p,h) in fs do
    if p.isAppOf ``LT.lt then
      if let some pf ←observing? (mkAppM ``strict #[h,a,b]) then return pf
  throwError "missing signature evidence"

private partial def splitSites (xyz : Array Expr) (body : Expr) : MetaM (List Expr × Expr) := do
  let wrap := fun t=>mkLambdaFVars xyz t
  if body.isAppOfArity ``Or 2 then
    let l:=body.getArg! 0
    let r:=body.appArg!
    let (bs,recEq) ←splitSites xyz r
    let call ←mkAppM ``Called #[←wrap l]
    let eq ←mkAppM ``calledOr #[←wrap l,←wrap r]
    return (call::bs,←mkAppM ``Iff.trans #[eq,←mkAppM ``or_congr #[mkApp (mkConst ``Iff.rfl) call,recEq]])
  let p←mkAppM ``Called #[←wrap body]
  return ([p],mkApp (mkConst ``Iff.rfl) p)

-- Partition the content question by actual caller, not by content constructor.
-- The whole follower-loop and signed-fold questions are known subsets; keep
-- the other alternatives intact instead of treating them as false.
run_cmd liftTermElabM do
  let q:=``step_isSignature_eq_true_content_transaction
  let rs←children q
  let follower := ``step_fromLeader_loop_entries_nil
  let follows←children follower
  let indexed←Signed.indexedSites
  let erased←Signed.erasedSites
  lambdaTelescope (←getConstInfo q).value! fun xs outer=>do
    let mut rest := []
    let mut sets := #[]
    for (r,j) in rs.zipIdx do
      let union:=(←children r)[0]!
      let cs←children union
      let index:=cs[0]!
      let bound ←lambdaTelescope (←getConstInfo index).value! fun vs p=>do
        withLocalDeclD `site (mkAppN (mkConst index) vs) fun h=>do
          let signed ←PromotionImpossibleB.withFields p h #[] (signedAt vs[4]! vs[5]!)
          mkLambdaFVars (vs.push h) signed
      let fn:= (ns++`Lookup).str index.getString!
      addDecl (.thmDecl {name:=fn,levelParams:=[],type:=←inferType bound,value:=bound})
      let (as,spread) ←forallTelescope (←inferType (mkAppN (mkConst index) xs)) fun yz _=>do
        let p := (←getConstInfo index).value!.beta (xs++yz)
        splitSites yz p
      let erase ←mkAppM ``forgetLookup #[mkAppN (mkConst index) xs,mkAppN (mkConst fn) xs]
      let p := (←getConstInfo union).value!.beta xs
      let zs:=HandReadersBFactor.disjuncts p
      let mut eq ←mkAppM ``Iff.trans #[erase,spread]
      let mut alternatives:=as
      if zs.length>1 then
        let tail := p.appArg!
        eq←mkAppM ``or_congr #[eq,mkApp (mkConst ``Iff.rfl) tail]
        eq←mkAppM ``Iff.trans #[eq,←HandReadersTrunkA.Factor.join as zs.tail!]
        alternatives:=as++zs.tail!
      let mut rows:=#[]
      for (a,offset) in alternatives.zipIdx do
        let deps:=ReachPath.children q.getPrefix a
        let some d:=deps[0]? | throwError "no content origin"
        if indexed.contains d then
          let where_ := indexed.idxOf d
          let h ←mkAppM ``Iff.trans #[mkApp (mkConst ``foldCalled) (mkAppN (mkConst d) xs),
            mkAppN (mkConst (Signed.siteIff d)) xs]
          rows:=rows.push (1,where_,h)
        else if follows.contains d then
          let h:=mkApp (mkConst ``Iff.rfl) a
          rows:=rows.push (0,follows.idxOf d,h)
        else
          let k:=rest.length
          let name:=(ns++`Remainder).str s!"site{j}arm{offset}"
          let v←mkLambdaFVars xs a
          addDecl (.defnDecl {name,levelParams:=[],type:=←inferType v,value:=v,hints:=.abbrev,safety:=.safe})
          rest:=rest++[mkAppN (mkConst name) xs]
          rows:=rows.push (2,k,mkApp (mkConst ``Iff.rfl) a)
      sets:=sets.push (r,alternatives,eq,rows)
    let followProp:=mkAppN (mkConst follower) xs
    let foldProp:=mkAppN (mkConst ``Signed.Erased) xs
    let restProp:=HandReadersTrunkA.Factor.disj rest
    let name:=ns++`Residual
    let rv←mkLambdaFVars xs restProp
    addDecl (.defnDecl {name,levelParams:=[],type:=←inferType rv,value:=rv,hints:=.abbrev,safety:=.safe})
    let target:=HandReadersTrunkA.Factor.disj [followProp,foldProp,mkAppN (mkConst name) xs]
    let parts:=#[(←getConstInfo follower).value!.beta xs,(←getConstInfo ``Signed.Erased).value!.beta xs,restProp]
    let widths:=#[follows.size,erased.size,rest.length]
    let mut fw:=[]
    let mut backs : Std.HashMap (Nat×Nat) Expr := {}
    for ((r,as,eq,rows),j) in sets.zipIdx do
      let all:=HandReadersTrunkA.Factor.disj as
      let mut forward := []
      for ((part,k,h),i) in rows.zipIdx do
        let ty:=as[i]!
        let out ←withLocalDeclD `a ty fun a=>do
          let v ←HandReadersBFactor.into parts[part]! (←mkAppM ``Iff.mp #[h,a]) k widths[part]!
          mkLambdaFVars #[a] (←HandReadersBFactor.into target v part 3)
        forward:=forward++[out]
        let back ←withLocalDeclD `a (HandReadersBFactor.disjuncts parts[part]!)[k]! fun a=>do
          let v←HandReadersBFactor.into all (←mkAppM ``Iff.mpr #[h,a]) i as.length
          mkLambdaFVars #[a] (←HandReadersBFactor.into outer (←mkAppM ``Iff.mpr #[eq,v]) j rs.size)
        backs:=backs.insert (part,k) back
      let h ←withLocalDeclD `a (mkAppN (mkConst r) xs) fun a=>do
        mkLambdaFVars #[a] (←HandReadersBFactor.outOf all (←mkAppM ``Iff.mp #[eq,a]) target forward)
      fw:=fw++[h]
    let mut rev := []
    for (p,i) in parts.zipIdx do
      let mut arms := []
      for j in [:widths[i]!] do
        let some h:=backs[(i,j)]? | throwError "missing direction for known class {i}.{j}"
        arms:=arms++[h]
      rev:=rev++[←withLocalDeclD `a p fun a=>do mkLambdaFVars #[a] (←HandReadersBFactor.outOf p a (mkAppN (mkConst q) xs) arms)]
    let mp ←withLocalDeclD `h (mkAppN (mkConst q) xs) fun h=>do mkLambdaFVars #[h] (←HandReadersBFactor.outOf outer h target fw)
    let mpr ←withLocalDeclD `h target fun h=>do mkLambdaFVars #[h] (←HandReadersBFactor.outOf target h (mkAppN (mkConst q) xs) rev)
    let v←mkLambdaFVars xs (←mkAppM ``Iff.intro #[mp,mpr])
    addDecl (.thmDecl {name:=ns++`content_iff,levelParams:=[],type:=←inferType v,value:=v})
end

end ConsensusCoverage.HandReadersTrunkD.Content
