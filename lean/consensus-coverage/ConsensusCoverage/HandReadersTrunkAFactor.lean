module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.HandReadersBPaths
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
public meta import ConsensusCoverage.HandReadersBFactor

namespace ConsensusCoverage.HandReadersTrunkA.Factor

open Lean Meta

private theorem ex_or {α : Sort u} {p q : α → Prop} :
    (∃ x, p x ∨ q x) ↔ (∃ x, p x) ∨ (∃ x, q x) := by grind

meta section

private abbrev Gen := StateRefT (Std.HashMap Name (List Name)) MetaM

private partial def origins (rs : Array Name) (n : Name) : Gen (List Name) := do
  if rs.contains n then return [n]
  if let some s := (← get)[n]? then return s
  let mut out := []
  for ch in ReachPath.children n.getPrefix (← getConstInfo n).value! do
    out := (out ++ (← origins rs ch)).eraseDups
  modify (·.insert n out)
  return out

private partial def sources (rs : Array Name) (p : Expr) : Gen (List Name) := do
  let mut out := []
  for ch in ReachPath.children `ConsensusCoverage.SolvedWitnesses p do
    out := (out ++ (← origins rs ch)).eraseDups
  return out

private def disj (ps : List Expr) : Expr :=
  ps.dropLast.foldr (fun a b => mkApp2 (mkConst ``Or) a b) ps.getLast!

private def refl (p : Expr) := mkApp (mkConst ``Iff.refl) p

private abbrev Result := List Expr × Expr

private partial def join (left right : List Expr) : MetaM Expr := do
  let a :: b :: as := left | return refl (disj (left ++ right))
  let lhs := disj (b :: as)
  let rhs := disj right
  let assoc ← mkAppOptM ``or_assoc #[a,lhs,rhs]
  let recEq ← join (b :: as) right
  mkAppM ``Iff.trans #[assoc,←mkAppM ``or_congr #[refl a,recEq]]

private partial def liftAnd (p : Expr) (left : Bool) (as : List Expr) : MetaM Result := do
  let conj (a : Expr) := if left then mkApp2 (mkConst ``And) a p else mkApp2 (mkConst ``And) p a
  let a :: b :: rest := as | return ([conj as.getLast!],refl (conj as.getLast!))
  let (tail,recEq) ← liftAnd p left (b :: rest)
  let distrib ← if left then mkAppOptM ``or_and_right #[a,disj (b :: rest),p]
    else mkAppOptM ``and_or_left #[p,a,disj (b :: rest)]
  return (conj a :: tail,←mkAppM ``Iff.trans #[distrib,←mkAppM ``or_congr #[refl (conj a),recEq]])

private partial def liftEx (x : Expr) (as : List Expr) : MetaM Result := do
  let ex (p : Expr) := mkLambdaFVars #[x] p >>= fun f => mkAppM ``Exists #[f]
  let a :: b :: rest := as | let p ← ex as.getLast!; return ([p],refl p)
  let (tail,recEq) ← liftEx x (b :: rest)
  let distrib ← mkAppOptM ``ex_or #[←inferType x,←mkLambdaFVars #[x] a,←mkLambdaFVars #[x] (disj (b :: rest))]
  let first ← ex a
  return (first :: tail,←mkAppM ``Iff.trans #[distrib,←mkAppM ``or_congr #[refl first,recEq]])

/-- Distribute alternatives on the dispatch spine, leaving other tests
    untouched. Keep unsplit sub-DAGs as calls, not expanded terms. -/
private partial def split (rs : Array Name) (p : Expr) : Gen Result := do
  if (← sources rs p).isEmpty then return ([p],refl p)
  if HandReadersBPaths.reaches p then
    if rs.contains p.getAppFn.constName! then return ([p],refl p)
    let some body ← unfoldDefinition? p | throwError "opaque mixed caller"
    let (as,h) ← split rs body
    return if as.length == 1 then ([p],refl p) else (as,h)
  if p.isAppOf ``Or then
    let (a,ha) ← split rs (p.getArg! 0)
    let (b,hb) ← split rs p.appArg!
    return (a ++ b,←mkAppM ``Iff.trans #[←mkAppM ``or_congr #[ha,hb],←join a b])
  if p.isAppOf ``And then
    let a := p.getArg! 0
    let b := p.appArg!
    let left := (← sources rs b).isEmpty
    let (parts,h) ← split rs (if left then a else b)
    if parts.length == 1 then return ([p],refl p)
    let eq ← if left then mkAppM ``and_congr #[h,refl b] else mkAppM ``and_congr #[refl a,h]
    let (out,dist) ← liftAnd (if left then b else a) left parts
    return (out,←mkAppM ``Iff.trans #[eq,dist])
  if p.isAppOf ``Exists then
    return ← withLocalDeclD `x (p.getArg! 0) fun x => do
      let (parts,h) ← split rs (p.appArg!.beta #[x])
      if parts.length == 1 then return ([p],refl p)
      let (out,dist) ← liftEx x parts
      return (out,←mkAppM ``Iff.trans #[←mkAppM ``exists_congr #[←mkLambdaFVars #[x] h],dist])
  throwError "unsupported mixed dispatch at {p.getAppFn}"

def normalized (n : Name) := (`ConsensusCoverage.HandReadersTrunkA.Factor.Split).str n.getString!
def iffName (n : Name) := (normalized n).appendAfter "_iff"

def compile (n : Name) : MetaM Unit := do
  let rs ← HandReadersBFactor.roots
  lambdaTelescope (←getConstInfo n).value! fun xs p => do
    let mut cache := {}
    let mut parts := []
    let mut proofs := []
    for arm in HandReadersBFactor.disjuncts p do
      let ((as,h),cache') ← (split rs arm).run cache
      cache := cache'
      parts := as :: parts
      proofs := h :: proofs
    let mut out := parts.head!
    let mut eq := proofs.head!
    for (as,h) in parts.tail!.zip proofs.tail! do
      eq ← mkAppM ``Iff.trans #[←mkAppM ``or_congr #[h,eq],←join as out]
      out := as ++ out
    let name := normalized n
    addDecl (.defnDecl {
      name, levelParams := [], type := ← mkForallFVars xs (mkSort .zero)
      value := ← mkLambdaFVars xs (disj out), hints := .abbrev, safety := .safe })
    addDecl (.thmDecl {
      name := iffName n, levelParams := []
      type := ← mkForallFVars xs (←mkAppM ``Iff #[mkAppN (mkConst n) xs,mkAppN (mkConst name) xs])
      value := ← mkLambdaFVars xs eq })
    HandReadersBFactor.compile name

end

end ConsensusCoverage.HandReadersTrunkA.Factor
