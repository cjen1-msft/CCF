module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkDSignatureErased
import all ConsensusCoverage.HandReadersTrunkDSignatureData
import all ConsensusCoverage.HandReadersOtherTransferSites
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.ProofWalk
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersTrunkDSignatureErased
public meta import ConsensusCoverage.HandReadersOtherTransferSites

namespace ConsensusCoverage.HandReadersTrunkD.Signed

open Consensus Model Model.Node Proofs Safety Ledger SolvedWitnesses Lean Meta Elab Command
set_option maxRecDepth 16384
set_option maxHeartbeats 4800000

private abbrev Part (p l : List Entry) := p <+: l ∧ isSignatureAt p p.length = true
private abbrev Valid (l : List Entry) (i : Nat) := isSignatureAt l i = true ∧ i ≤ l.length

private theorem committedPart [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)
    {e p n k l i} (key : f.logs.committed e p) (win : (f.advance t).logs.elected n k l i) (lt : e < k) :
    Part p l := ⟨c.old_complete key win lt,(c.inv.commitChains _ _ key).signed.2⟩

private theorem advancedPart [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)
    {a st k b i n e l j} (step : CommitStep (f.advance t) a st k b i) (back : Backed f st.log b k)
    (win : (f.advance t).logs.elected n e l j) (lt : k < e) : Part (st.log.take i) l :=
  ⟨c.completeness _ _ _ _ _ _ (.inr ⟨a,st,b,i,step,rfl,back⟩) win lt,take_signature step.2.2.2.1⟩

private theorem anyPart : Part [⟨0,.signature⟩] [⟨0,.signature⟩] := ⟨List.prefix_refl _,rfl⟩
private theorem oldPart {a l : List Entry} (sub : a <+: l) (sg : isSignatureAt a a.length = true) :
    Part a l := ⟨sub,sg⟩

private theorem electionValid [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)
    (pos : 0 < c.pre.commitIndex) : Valid c.pre.log c.pre.commitIndex :=
  ⟨(c.inv.frontier _ _ c.pre_now).2 pos,c.frontier_pre⟩
private theorem prefixValid {l r : List Entry} (sub : l <+: r) (pos : 0 < maxCommittableIndex l) :
    Valid r (maxCommittableIndex l) := by
  have sg := isSignatureAt_of_prefix sub (maxCommittableIndexPositiveIsSignature pos)
  exact ⟨sg,signature_bound sg⟩
private theorem partValid {l r : List Entry} (h : Part l r) : Valid r l.length :=
  let sg := isSignatureAt_of_prefix h.1 h.2
  ⟨sg,signature_bound sg⟩

meta section

private abbrev Known := Array (Expr × Expr)

-- Delay existential choices until the actual caller premises determine them.
-- In particular, do not enumerate the Nat witnesses of an induction on runtime data.
private partial def sketch (p : Expr) : StateRefT (Array (Expr × Expr)) MetaM Expr := do
  if p.isAppOfArity ``Exists 2 then
    let w ←mkFreshExprMVar (p.getArg! 0)
    let body ←sketch (p.appArg!.beta #[w])
    modify (·.push (p.getArg! 0,w))
    return ←mkAppOptM ``Exists.intro #[none,p.appArg!,w,body]
  if p.isAppOfArity ``And 2 then
    let l ← mkFreshExprMVar (p.getArg! 0)
    modify (·.push (p.getArg! 0,l))
    return mkApp4 (mkConst ``And.intro) (p.getArg! 0) p.appArg! l (←sketch p.appArg!)
  let leaf ←mkFreshExprMVar p
  modify (·.push (p,leaf))
  return leaf

private partial def matchFields (xs : Known) : List (Expr × Expr) → MetaM Bool
  | [] => pure true
  | (p,g)::rest => do
    if ←g.mvarId!.isAssigned then return ←matchFields xs rest
    let p ←instantiateMVars p
    let saved ←saveState
    for (h,t) in xs do
      if p.getAppFn == t.getAppFn || (p.isForall && t.isForall) then
        if ←withReducible (isDefEq p t) then
          g.mvarId!.assign h
          if ←matchFields xs rest then return true
        saved.restore
    if p.isAppOfArity ``Eq 3 && (←isDefEq (p.getArg! 1) p.appArg!) then
      g.mvarId!.assign (←mkEqRefl p.appArg!)
      if ←matchFields xs rest then return true
    saved.restore
    return false

private def pack (p : Expr) (xs : Known) : MetaM (Option Expr) := do
  let p ←instantiateMVars p
  let (v,goals) ←(sketch p).run #[]
  if ←matchFields xs goals.toList then
    let v ← instantiateMVars v
    unless v.hasMVar do return some v
  return none

private def asFields (xs : Array Expr) : MetaM Known := xs.mapM fun h=>do return (h,←inferType h)
private def addPair (p : Expr) : MetaM (Array Expr) := do
  return #[p,←mkAppM ``And.left #[p],←mkAppM ``And.right #[p]]

private def moreParts (c : Expr) (fs : Known) : MetaM (Array Expr) := do
  let mut out := #[]
  for (h,p) in fs do
    if p.isAppOf ``List.IsPrefix then
      for (s,q) in fs do
        if q.isAppOfArity ``Eq 3 && (q.getArg! 1).isAppOf ``isSignatureAt then
          if let some pr ←observing? (mkAppM ``oldPart #[h,s]) then out := out.push pr
    if p.isAppOf ``LogFacts.Ghost.elected then
      for (key,q) in fs do
        if q.isAppOf ``LogFacts.Ghost.committed then
          for (lt,r) in fs do
            if r.isAppOf ``LT.lt then
              if let some pr ← observing? (mkAppM ``committedPart #[c,key,h,lt]) then out :=out.push pr
        if q.isAppOf ``CommitStep then
          for (b,r) in fs do
            if r.isAppOf ``Or || r.isAppOf ``Backed then
              for (lt,s) in fs do
                if s.isAppOf ``LT.lt then
                  if let some pr ←observing? (mkAppM ``advancedPart #[c,key,b,h,lt]) then out :=out.push pr
  return out.push (mkConst ``anyPart)

private def deepIff (r : Name) := (ns++`Parts).str (r.getString! ++ "_iff")

private def deep (r e : Name) : MetaM Unit := do
  let ci ←getConstInfo r
  lambdaTelescope ci.value! fun xs body=>do
    let ctx := xs.extract 0 4
    let p := xs[4]!
    let l := xs[5]!
    let term := mkAppN (mkConst r) xs
    let guard := mkApp2 (mkConst ``Part) p l
    let inner ←mkLambdaFVars #[l] (mkApp2 (mkConst ``And) term guard) >>= fun a=>mkAppM ``Exists #[a]
    let pred ←instantiateMVars (←mkLambdaFVars #[p] inner)
    let lhs ←instantiateMVars (←mkAppM ``Exists #[pred])
    let rhs := mkAppN (mkConst e) ctx
    let a := choices body
    let eb := (←getConstInfo e).value!.beta ctx
    let b := choices eb
    unless a.length == b.length do throwError "different signed-prefix caller alternatives {r}"
    let mp ←withLocalDeclD `site term fun site=>withLocalDeclD `ok guard fun ok=>do
      let hs ←a.zipIdx.mapM fun (v,i)=>withLocalDeclD `s v fun s=>do
        let target := b[i]!
        let proof ←HandReadersOther.Transfer.unpack [] v s #[p,l] fun data=>do
          let some k ←pack target (←asFields data) | throwError "cannot erase prefix {r.getString!}.{i}"
          return ←mkExpectedTypeHint k target
        mkLambdaFVars #[s] (←HandReadersBFactor.into eb proof i b.length)
      mkLambdaFVars #[p,l,site,ok] (←HandReadersBFactor.outOf body site rhs hs)
    let mp ←withLocalDeclD `h lhs fun h=>do
      let lam ←withLocalDeclD `p (←inferType p) fun u=>withLocalDeclD `s (pred.beta #[u]) fun s=>do
        let inner ←instantiateMVars (pred.beta #[u])
        let lam ←withLocalDeclD `log (←inferType l) fun y=>do
          let a := inner.appArg!.beta #[y]
          withLocalDeclD `z a fun z=>do
            mkLambdaFVars #[y,z] (mkAppN mp #[u,y,mkProj ``And 0 z,mkProj ``And 1 z])
        mkLambdaFVars #[u,s] (ProofWalk.casesExists inner s rhs lam)
      mkLambdaFVars #[h] (ProofWalk.casesExists lhs h rhs lam)
    let back ←b.zipIdx.mapM fun (v,i)=>withLocalDeclD `s v fun s=>do
      let proof ←HandReadersOther.Transfer.unpack [] v s #[] fun data=>do
        let fs ←asFields data
        for cut in ←moreParts xs[3]! fs do
          let ty ←instantiateMVars (←inferType cut)
          let args := ty.getAppArgs
          let u := args[args.size-2]!
          let y := args.back!
          let concrete := body.replaceFVars #[p,l] #[u,y]
          let localArms := choices concrete
          if let some proof ←pack localArms[i]! fs then
            let site ←HandReadersBFactor.into concrete proof i localArms.length
            let prod ←mkAppM ``And.intro #[site,cut]
            let inr ←mkAppOptM ``Exists.intro #[none,(pred.beta #[u]).appArg!,y,prod]
            return ←mkAppOptM ``Exists.intro #[none,pred,u,inr]
        throwError "cannot reconstruct prefix {r.getString!}.{i}"
      mkLambdaFVars #[s] proof
    let mpr ←withLocalDeclD `h rhs fun h=>do mkLambdaFVars #[h] (←HandReadersBFactor.outOf eb h lhs back)
    addDecl (.thmDecl {
      name:=deepIff r,levelParams:=[],type:=←mkForallFVars ctx (←mkAppM ``Iff #[lhs,rhs])
      value:=←mkLambdaFVars ctx (←mkAppM ``Iff.intro #[mp,mpr])})

private def subparts : MetaM (Array (Name × Name)) := do
  let mut parts := #[]
  let es ←erasedSites
  for (r,i) in (←indexedSites).toList.zipIdx do
    let ds ←kids r
    let ez ←kids es[i]!
    unless ds.size == ez.size do throwError "non-parallel signed call roots"
    for (d,e) in ds.zip ez do
      if ←forallTelescope (←getConstInfo d).type fun xs _=>do
        return xs.size == 6 && (←inferType xs[4]!).isAppOf ``List && (←inferType xs[5]!).isAppOf ``List && d != e then
        unless parts.contains (d,e) do parts:=parts.push (d,e)
  return parts

run_cmd liftTermElabM do
  for (r,e) in ←subparts do deep r e
end

end ConsensusCoverage.HandReadersTrunkD.Signed
