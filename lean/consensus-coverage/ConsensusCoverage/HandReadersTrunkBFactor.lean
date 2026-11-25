module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.HandReadersBPaths
import all ConsensusCoverage.HandReadersBGate
import all ConsensusCoverage.ProofWalk
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersBFactor

/-! A dispatch origin may be shared by several handlers; conversely, the
normalizer may merge several different origins *inside* one handler. Move
only the origin-bearing disjunctions out through existentials/conjunctions.
The remaining handler guard stays intact. -/
namespace ConsensusCoverage.HandReadersTrunkBFactor

open Lean Meta Elab Command
open Consensus Consensus.Model Consensus.Proofs Safety HandReadersBGate

private theorem someOr {α : Sort u} (a b : α → Prop) :
    (∃ x, a x ∨ b x) ↔ (∃ x, a x) ∨ ∃ x, b x := exists_or

private theorem underEx {α : Sort u} {a b : α → Prop} (h : ∀ x, a x ↔ b x) :
    (∃ x, a x) ↔ ∃ x, b x := exists_congr h

meta section

private inductive Tree where
  | leaf (root : Name) (tail : Expr)
  | fork (l r : Tree)
  deriving Inhabited

private def Tree.prop (xs : Array Expr) : Tree → Expr
  | .leaf r t => mkApp2 (mkConst ``And) (mkAppN (mkConst r) xs) t
  | .fork l r => mkApp2 (mkConst ``Or) (l.prop xs) (r.prop xs)

private structure Split where
  tree : Tree
  proof : Expr
  deriving Inhabited

private def liftAnd (stem : Array Expr) (suffix : Expr) (onLeft : Bool) : Tree → MetaM Split
  | .leaf r t => do
    let rp := mkAppN (mkConst r) stem
    let eq := mkApp (mkConst ``Iff.rfl) (mkApp2 (mkConst ``And) rp t)
    let tail := if onLeft then mkApp2 (mkConst ``And) t suffix else mkApp2 (mkConst ``And) suffix t
    return ⟨.leaf r tail, ←mkAppM (if onLeft then ``HandReadersBFactor.left else ``HandReadersBFactor.right) #[suffix,eq]⟩
  | .fork l r => do
    let a ← liftAnd stem suffix onLeft l
    let b ← liftAnd stem suffix onLeft r
    let p := if onLeft then mkApp3 (mkConst ``or_and_right) (l.prop stem) (r.prop stem) suffix
      else mkApp3 (mkConst ``and_or_left) suffix (l.prop stem) (r.prop stem)
    return ⟨.fork a.tree b.tree, ←mkAppM ``Iff.trans #[p, ←mkAppM ``or_congr #[a.proof,b.proof]]⟩

private def liftEx (stem : Array Expr) (x : Expr) : Tree → MetaM Split
  | .leaf r t => do
    let fn ← mkLambdaFVars #[x] t
    let eq ← mkLambdaFVars #[x] (mkApp (mkConst ``Iff.rfl) (Tree.prop stem (.leaf r t)))
    return ⟨.leaf r (←mkAppM ``Exists #[fn]), ←mkAppM ``HandReadersBFactor.ex #[eq]⟩
  | .fork l r => do
    let a ← liftEx stem x l
    let b ← liftEx stem x r
    let p ← mkAppM ``someOr #[←mkLambdaFVars #[x] (l.prop stem),←mkLambdaFVars #[x] (r.prop stem)]
    return ⟨.fork a.tree b.tree, ←mkAppM ``Iff.trans #[p,←mkAppM ``or_congr #[a.proof,b.proof]]⟩

private partial def split (rs : Array Name) (xs stem : Array Expr) (p : Expr) : MetaM Split := do
  if p.isAppOf ``Or then
    let a ← split rs xs stem (p.getArg! 0)
    let b ← split rs xs stem p.appArg!
    return ⟨.fork a.tree b.tree, ←mkAppM ``or_congr #[a.proof,b.proof]⟩
  if p.isAppOf ``Exists then
    return ←withLocalDeclD `x (p.getArg! 0) fun x => do
      let b := p.appArg!.beta #[x]
      if b.isAppOf ``Exists then
        let terminal ← withLocalDeclD `y (b.getArg! 0) fun y => do
          let pair := b.appArg!.beta #[y]
          return pair.isAppOf ``And && (pair.getArg! 0).getAppFn.constName?.any rs.contains
        if terminal then
          let found ← HandReadersBFactor.splitAt rs xs p
          return ⟨.leaf found.root found.tail,found.proof⟩
      let inner ← split rs xs stem b
      let lifted ← liftEx stem x inner.tree
      let intro ← mkAppM ``underEx #[←mkLambdaFVars #[x] inner.proof]
      return { lifted with proof := ←mkAppM ``Iff.trans #[intro,lifted.proof] }
  if p.isAppOf ``And then
    let a := p.getArg! 0
    let b := p.appArg!
    let left := HandReadersBFactor.rooted a
    if left != HandReadersBFactor.rooted b then
      let side := if left then b else a
      let inner ← split rs xs stem (if left then a else b)
      let lifted ← liftAnd stem side left inner.tree
      let refl := mkApp (mkConst ``Iff.rfl) side
      let eq ← mkAppM ``and_congr (if left then #[inner.proof,refl] else #[refl,inner.proof])
      return {lifted with proof := ←mkAppM ``Iff.trans #[eq,lifted.proof]}
  if HandReadersBPaths.reaches p then
    let some q ← unfoldDefinition? p | throwError "opaque reach predicate"
    return ← split rs xs stem q
  throwError "caller is not a single positive dispatch occurrence: {p.getAppFn}"

private def Tree.leaves : Tree → List (Name × Expr)
  | .leaf n t => [(n,t)]
  | .fork a b => a.leaves ++ b.leaves

private partial def Tree.elim (stem : Array Expr) (tgt : Expr) (atLeaf : Name → Expr → MetaM Expr)
    (tree : Tree) (h : Expr) : MetaM Expr := do
  match tree with
  | .leaf n t => return mkApp (←atLeaf n t) h
  | .fork a b =>
    let arm (s : Tree) := withLocalDeclD `alt (s.prop stem) fun p => do
      mkLambdaFVars #[p] (←s.elim stem tgt atLeaf p)
    return ProofWalk.casesOr (tree.prop stem) h tgt (←arm a) (←arm b)

private def Tree.injected (stem : Array Expr) (root : Name) (tail r h : Expr) :
    Tree → MetaM (Option Expr)
  | .leaf n t => do
    if n == root && (←isDefEq t tail) then return some (←mkAppM ``And.intro #[r,h])
    return none
  | .fork a b => do
    if let some v ← a.injected stem root tail r h then
      return some (←mkAppOptM ``Or.inl #[none,some (b.prop stem),some v])
    if let some v ← b.injected stem root tail r h then
      return some (←mkAppOptM ``Or.inr #[some (a.prop stem),none,some v])
    return none

def compile (n : Name) : MetaM Unit := do
  let rs ← HandReadersBFactor.roots
  lambdaTelescope (←getConstInfo n).value! fun xs body => do
    let ctx := xs.extract 0 4
    let stem := ctx ++ #[xs[2]!,←mkAppM ``Ctx.tr #[xs[3]!]]
    let proof ← split rs ctx stem body
    let mut ts := #[]
    for (_,t) in proof.tree.leaves do
      unless ← ts.anyM (isDefEq t) do ts := ts.push t
    let tails := ts
    let clean := tails.toList.dropLast.foldr (fun a b => mkApp2 (mkConst ``Or) a b) tails.back!
    let tn := (`ConsensusCoverage.HandReadersTrunkBFactor.Tail).str n.getString!
    let en := (`ConsensusCoverage.HandReadersTrunkBFactor.Exact).str n.getString!
    addDecl (.defnDecl {
      name := tn, levelParams := [], type := ←mkForallFVars xs (mkSort .zero)
      value := ←mkLambdaFVars xs clean, hints := .abbrev, safety := .safe})
    let src ← mkAppM ``Source #[xs[3]!]
    let q := mkAppN (mkConst ``Quiet) (xs.extract 0 3)
    withLocalDeclD `absent (←mkArrow (mkNot src) q) fun absent => do
      let tgt := mkApp2 (mkConst ``And) src (mkAppN (mkConst tn) xs)
      let atLeaf := fun root tail => do
        let some i ← tails.findIdxM? (isDefEq tail) | throwError "lost handler guard"
        let leaf := Tree.prop stem (.leaf root tail)
        let f ← mkAppM ``HandReadersBFactor.forward #[mkApp (mkConst ``Iff.rfl) leaf,absent,
          mkAppN (mkConst (HandReadersBPaths.quietName root)) stem]
        withLocalDeclD `h leaf fun h => do
          let a ← mkAppM ``And.left #[mkApp f h]
          let b ← mkAppM ``And.right #[mkApp f h]
          mkLambdaFVars #[h] (←mkAppM ``And.intro #[a,←HandReadersBFactor.into clean b i tails.size])
      let lhs := mkAppN (mkConst n) xs
      let fw ← withLocalDeclD `h lhs fun h => do
        mkLambdaFVars #[h] (←proof.tree.elim stem tgt atLeaf (←mkAppM ``Iff.mp #[proof.proof,h]))
      let arms ← (#[15,16,9] : Array Nat).mapM fun idx =>
        withLocalDeclD `root (mkAppN (mkConst rs[idx]!) stem) fun r => withLocalDeclD `yes clean fun h => do
          let fs ← tails.mapIdxM fun j t => withLocalDeclD `guard t fun g => do
            let some val ← proof.tree.injected stem rs[idx]! t r g |
              throwError "{n.getString!}: guard {j} of {tails.size} lacks dispatch origin {idx}"
            mkLambdaFVars #[g] (←mkAppM ``Iff.mpr #[proof.proof,val])
          mkLambdaFVars #[r,h] (←HandReadersBFactor.outOf clean h lhs fs.toList)
      let back ← mkAppM ``HandReadersBFactor.backwards arms
      let vars := xs.push absent
      addDecl (.thmDecl {
        name := en,levelParams := [],type := ←mkForallFVars vars (←mkAppM ``Iff #[lhs,tgt])
        value := ←mkLambdaFVars vars (←mkAppM ``Iff.intro #[fw,back])})

private partial def template (p : Expr) (args : Array Expr) (pred : Option Expr) : MetaM Expr := do
  if p.isAppOf ``Or then
    return mkApp2 (mkConst ``Or) (←template (p.getArg! 0) args pred) (←template p.appArg! args pred)
  if p.isAppOf ``Exists then
    return ←withLocalDeclD `x (p.getArg! 0) fun x => do
      let inner ← template (p.appArg!.beta #[x]) (args.push x) pred
      if pred.isNone then return inner
      return mkApp2 p.getAppFn (p.getArg! 0) (←mkLambdaFVars #[x] inner)
  unless p.isAppOf ``And && HandReadersBPaths.reaches (p.getArg! 0) do
    throwError "expected guarded call: {p.getAppFn}"
  match pred with
  | none => mkLambdaFVars args p.appArg!
  | some k => return mkApp2 (mkConst ``And) (p.getArg! 0) (mkAppN k args)

/-- Abstract only the local branch test; every caller, including any merged
origin, remains in the kernel-checked dispatch equivalence. -/
def query (n out : Name) : MetaM Unit := do
  lambdaTelescope (←getConstInfo n).value! fun xs b => do
    let first ← template (b.getArg! 0) #[] none
    withLocalDeclD `pred (←inferType first) fun k => do
      let body ← template b #[] (some k)
      let vars := xs.push k
      addDecl (.defnDecl {
        name := out, levelParams := [], type := ←mkForallFVars vars (mkSort .zero)
        value := ←mkLambdaFVars vars body, hints := .abbrev, safety := .safe})
  compile out

def guardOf (n : Name) : MetaM Expr := do
  lambdaTelescope (←getConstInfo n).value! fun _ b => template (b.getArg! 0) #[] none

end
end ConsensusCoverage.HandReadersTrunkBFactor
