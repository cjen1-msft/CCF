module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersBGate
import all ConsensusCoverage.HandReadersBPaths
import all ConsensusCoverage.ProofWalk
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import Lean

/-! Factor a normalized handler branch into its dispatch trigger and its local
test. Existentials above the proof-entry transition are retained; the event,
actor and pre-state of the transition itself are pinned to the recorded step.
The generated equivalence checks every disjunct, not only the changed-node path. -/

namespace ConsensusCoverage.HandReadersBFactor

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open SolvedWitnesses HandReadersBGate
open Lean Meta Elab Term Command

set_option maxRecDepth 8192

private theorem ex {α : Sort u} {s : Prop} {p q : α → Prop} (h : ∀ a, p a ↔ s ∧ q a) :
    (∃ a, p a) ↔ s ∧ ∃ a, q a := ⟨fun ⟨a,hp⟩ => ⟨(h a |>.mp hp).1,a,(h a |>.mp hp).2⟩,
  fun ⟨hs,a,hq⟩ => ⟨a,(h a).mpr ⟨hs,hq⟩⟩⟩
private theorem left {a s b : Prop} (p : Prop) (h : a ↔ s ∧ b) :
    (a ∧ p) ↔ s ∧ (b ∧ p) := by rw [h,and_assoc]
private theorem right {a s b : Prop} (p : Prop) (h : a ↔ s ∧ b) :
    (p ∧ a) ↔ s ∧ (p ∧ b) := by rw [h,and_left_comm]
private theorem either {a b s x y : Prop} (ha : a ↔ s ∧ x) (hb : b ↔ s ∧ y) :
    (a ∨ b) ↔ s ∧ (x ∨ y) := by rw [ha,hb,and_or_left]

variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}

private theorem bindTransition (R : (u : Model.State) → LocalTransition f.current u → Prop)
    (F : (u : Model.State) → LocalTransition f.current u → Prop)
    (pinned : ∀ u tr, R u tr → u = t ∧ HEq tr c.tr) :
    (∃ u tr, R u tr ∧ F u tr) ↔ R t c.tr ∧ F t c.tr := by
  refine ⟨?_, fun ⟨r,h⟩ => ⟨t,c.tr,r,h⟩⟩
  rintro ⟨u,tr,r,h⟩
  obtain ⟨rfl,eq⟩ := pinned u tr r
  cases eq_of_heq eq
  exact ⟨r,h⟩

private theorem pinned {u : Model.State} {tr : LocalTransition f.current u}
    (h : u = t) (he : HEq tr c.tr) : u = t ∧ HEq tr c.tr := ⟨h,he⟩

private theorem forward {p r a : Prop} (h : p ↔ r ∧ a)
    (no : ¬ Source c → Quiet f t) (refute : Quiet f t → r → False) : p → Source c ∧ a :=
  fun hp => ⟨Classical.byContradiction (fun n => refute (no n) (h.mp hp).1),(h.mp hp).2⟩

omit [Config.InitialConfiguration] in
private theorem inject {p r a : Prop} (h : p ↔ r ∧ a) : r → a → p := fun hr ha => h.mpr ⟨hr,ha⟩

private theorem backwards {p a : Prop}
    (n : (reach% step_summary_event_receive[15,0]) f t c t c.tr → a → p)
    (e : (reach% step_summary_event_receive[16,0]) f t c t c.tr → a → p)
    (k : (reach% step_summary_event_receive[9,0]) f t c t c.tr → a → p) :
    Source c ∧ a → p := fun ⟨src,ha⟩ => match site src with
    | .node h => n h ha | .packet h => e h ha | .key h => k h ha

meta section

private def pairName (r : Name) := (`ConsensusCoverage.HandReadersBFactor.Pin).str r.getString!

private partial def pinProof (p h tgt : Expr) : MetaM Expr := do
  if p.isAppOf ``Or then
    let a ← #[p.getArg! 0,p.appArg!].mapM fun q => withLocalDeclD `h q fun h' =>
      do mkLambdaFVars #[h'] (←pinProof q h' tgt)
    return ProofWalk.casesOr p h tgt a[0]! a[1]!
  let mut body := p
  let mut pr := h
  let mut facts := #[]
  while body.isAppOf ``And do
    let (a,b) := ProofWalk.conjuncts body pr
    facts := facts.push a.2
    body := b.1
    pr := b.2
  facts := facts.push pr
  for a in facts do
    for b in facts do
      if let some proof ← observing? (mkAppM ``pinned #[a,b]) then
        if ← isDefEq (← inferType proof) tgt then return proof
  throwError "unpinned transition: {tgt}"

private def roots : MetaM (Array Name) := do
  let summary := ``step_summary_event_receive
  (ReachPath.children summary.getPrefix (←getConstInfo summary).value!).mapM fun e => do
    let #[r] := ReachPath.children summary.getPrefix (←getConstInfo e).value! | throwError "transition origin"
    return r

private def makePins : MetaM Unit := do
  for r in ←roots do
    lambdaTelescope (←getConstInfo r).value! fun xs body => do
      let tr ← mkAppM ``Ctx.tr #[xs[3]!]
      let tgt := mkApp2 (mkConst ``And) (←mkEq xs[4]! xs[2]!) (←mkHEq xs[5]! tr)
      withLocalDeclD `h (mkAppN (mkConst r) xs) fun h => do
        let vars := xs.push h
        addDecl (.thmDecl {
          name := pairName r, levelParams := []
          type := ←mkForallFVars vars tgt, value := ←mkLambdaFVars vars (←pinProof body h tgt) })

private structure Factor where
  root : Name
  tail : Expr
  proof : Expr
  deriving Inhabited

private def rooted (e : Expr) :=
  !(ReachPath.children `ConsensusCoverage.SolvedWitnesses e).isEmpty

private partial def splitAt (rs : Array Name) (xs : Array Expr) (p : Expr) : MetaM Factor := do
  if p.isAppOf ``Exists then
    return ←withLocalDeclD `x (p.getArg! 0) fun a => do
      let body := p.appArg!.beta #[a]
      if body.isAppOf ``Exists then
        if let some result ← withLocalDeclD `y (body.getArg! 0) fun b => do
            let pair := body.appArg!.beta #[b]
            unless pair.isAppOf ``And do return none
            let call := pair.getArg! 0
            let some r := call.getAppFn.constName? | return none
            unless rs.contains r do return none
            let funR := mkAppN (mkConst r) xs
            let funF ← mkLambdaFVars #[a,b] pair.appArg!
            let pin := mkAppN (mkConst (pairName r)) xs
            let proof ← mkAppM ``bindTransition #[funR,funF,pin]
            let tr ← mkAppM ``Ctx.tr #[xs[3]!]
            return some ({ root := r, tail := funF.beta #[xs[2]!,tr], proof } : Factor)
          then return result
      let inner ← splitAt rs xs body
      let tail := mkApp2 p.getAppFn (p.getArg! 0) (←mkLambdaFVars #[a] inner.tail)
      return {inner with tail,proof := ←mkAppM ``ex #[←mkLambdaFVars #[a] inner.proof]}
  if p.isAppOf ``And then
    let a := p.getArg! 0
    let b := p.appArg!
    if rooted a && !rooted b then
      let x ← splitAt rs xs a
      return {x with tail := mkApp2 (mkConst ``And) x.tail b,proof := ←mkAppM ``left #[b,x.proof]}
    if !rooted a && rooted b then
      let x ← splitAt rs xs b
      return {x with tail := mkApp2 (mkConst ``And) a x.tail,proof := ←mkAppM ``right #[a,x.proof]}
  if p.isAppOf ``Or then
    let a ← splitAt rs xs (p.getArg! 0)
    let b ← splitAt rs xs p.appArg!
    unless a.root == b.root do throwError "alternative origins within an arm"
    return ⟨a.root,mkApp2 (mkConst ``Or) a.tail b.tail,←mkAppM ``either #[a.proof,b.proof]⟩
  if HandReadersBPaths.reaches p then
    let some q ← unfoldDefinition? p | throwError "opaque caller"
    return ← splitAt rs xs q
  throwError "nonlinear or missing dispatch origin in {p.getAppFn}"

private partial def disjuncts (p : Expr) : List Expr :=
  if p.isAppOf ``Or then p.getArg! 0 :: disjuncts p.appArg! else [p]

private partial def into (p val : Expr) (i : Nat) : MetaM Expr := do
  if p.isAppOf ``Or then
    if i == 0 then return ←mkAppOptM ``Or.inl #[none,some p.appArg!,some val]
    return ←mkAppOptM ``Or.inr #[some (p.getArg! 0),none,some (←into p.appArg! val (i-1))]
  unless i == 0 do throwError "missing alternative {i}"
  return val

private partial def outOf (p h tgt : Expr) (fs : List Expr) : MetaM Expr := do
  let f :: rest := fs | throwError "missing origin proof"
  if p.isAppOf ``Or then
    let g ← withLocalDeclD `r p.appArg! fun r => do mkLambdaFVars #[r] (←outOf p.appArg! r tgt rest)
    return ProofWalk.casesOr p h tgt f g
  return mkApp f h

private def factorName (n : Name) := (`ConsensusCoverage.HandReadersBFactor.Tail).str n.getString!
private def iffName (n : Name) := (`ConsensusCoverage.HandReadersBFactor.Exact).str n.getString!

private def compile (n : Name) : MetaM Unit := do
  let rs ← roots
  lambdaTelescope (←getConstInfo n).value! fun xs body => do
    let arms := disjuncts body
    let parts ← arms.mapM (splitAt rs xs)
    let clean := parts.head!.tail
    for part in parts do
      unless ←isDefEq clean part.tail do throwError "{n} has different residual tests"
    let src ← mkAppM ``Source #[xs[3]!]
    let quiet := mkAppN (mkConst ``Quiet) (xs.extract 0 3)
    let stem := xs ++ #[xs[2]!,←mkAppM ``Ctx.tr #[xs[3]!]]
    addDecl (.defnDecl {
      name := factorName n, levelParams := [], type := ←mkForallFVars xs (mkSort .zero)
      value := ←mkLambdaFVars xs clean,hints := .abbrev,safety := .safe })
    withLocalDeclD `absent (←mkArrow (mkNot src) quiet) fun absent => do
      let target := mkApp2 (mkConst ``And) src (mkAppN (mkConst (factorName n)) xs)
      let fw ← parts.mapM fun p => mkAppM ``forward #[p.proof,absent,mkAppN (mkConst (HandReadersBPaths.quietName p.root)) stem]
      let lhs := mkAppN (mkConst n) xs
      let forwardProof ← withLocalDeclD `hp lhs fun hp => do mkLambdaFVars #[hp] (←outOf body hp target fw)
      let arms' ← (#[15,16,9] : Array Nat).mapM fun i => do
        let some j := parts.findIdx? (·.root == rs[i]!) | throwError "unavailable positive origin {i}"
        let p := parts[j]!
        let root := mkAppN (mkConst p.root) stem
        withLocalDeclD `r root fun r => withLocalDeclD `yes clean fun yes => do
          let old ← mkAppM ``inject #[p.proof,r,yes]
          mkLambdaFVars #[r,yes] (←into body old j)
      let back ← mkAppM ``backwards arms'
      let pr ← mkAppM ``Iff.intro #[forwardProof,back]
      let vars := xs.push absent
      addDecl (.thmDecl {
        name := iffName n,levelParams := [],type := ←mkForallFVars vars (←mkAppM ``Iff #[lhs,target])
        value := ←mkLambdaFVars vars pr})

end

run_cmd liftTermElabM makePins

end ConsensusCoverage.HandReadersBFactor
