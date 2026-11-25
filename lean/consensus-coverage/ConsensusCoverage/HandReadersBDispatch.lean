module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersBPaths
import all ConsensusCoverage.HandReadersBGate
import all ConsensusCoverage.NominationArms
import all ConsensusCoverage.ProofWalk
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import Lean

namespace ConsensusCoverage.HandReadersBDispatch

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses HandReadersBGate
open Lean Meta Elab Term Command

set_option maxRecDepth 8192

meta section

private partial def specialize (p pred : Expr) : MetaM Expr := do
  if p.isAppOf ``Or then
    return mkApp2 (mkConst ``Or) (← specialize (p.getArg! 0) pred) (← specialize p.appArg! pred)
  let d := p.getArg! 0
  withLocalDeclD `event d fun e => do
    let body := p.appArg!.beta #[e]
    let clause := mkApp2 (mkConst ``And) (body.getArg! 0) (mkApp pred e)
    return mkApp2 p.getAppFn d (←mkLambdaFVars #[e] clause)

private def makeQuery : MetaM Unit := do
  let ci ← getConstInfo ``step_summary_event_receive
  lambdaTelescope ci.value! fun xs p => do
    withLocalDeclD `pred (←mkArrow (mkConst ``Event) (mkSort .zero)) fun pred => do
      let body ← specialize p pred
      addDecl (.defnDecl {
        name := `ConsensusCoverage.HandReadersBDispatch.Query, levelParams := []
        type := ←mkForallFVars (xs.push pred) (mkSort .zero)
        value := ←mkLambdaFVars (xs.push pred) body
        hints := .abbrev, safety := .safe })

end

run_cmd liftTermElabM makeQuery

private theorem leaf {Q : Prop} {e actual : Event} (p : Event → Prop)
    (pin : e = actual ∧ ¬Q) (branch : p e) : ¬Q ∧ p actual :=
  ⟨pin.2,pin.1 ▸ branch⟩

meta section
private partial def invert (body h tgt pred : Expr) : MetaM Expr := do
  if body.isAppOf ``Or then
    let arms ← #[body.getArg! 0,body.appArg!].mapM fun b => withLocalDeclD `alt b fun a =>
      do mkLambdaFVars #[a] (← invert b a tgt pred)
    return ProofWalk.casesOr body h tgt arms[0]! arms[1]!
  let arm ← withLocalDeclD `e (body.getArg! 0) fun e => do
    let ty := body.appArg!.beta #[e]
    withLocalDeclD `pair ty fun pair => do
      let (call,branch) := ProofWalk.conjuncts ty pair
      let name := HandReadersBPaths.lowerName call.1.getAppFn.constName!
      let pin := mkAppN (mkConst name) (call.1.getAppArgs.push call.2)
      mkLambdaFVars #[e,pair] (←mkAppM ``leaf #[pred,pin,branch.2])
  return ProofWalk.casesExists body h tgt arm

private def makeInversion : MetaM Unit := do
  let ci ← getConstInfo ``Query
  lambdaTelescope ci.value! fun xs body => do
    let p := xs.back!
    let e ← mkAppM ``Ctx.event #[xs[3]!]
    let q := mkAppN (mkConst ``Quiet) (xs.extract 0 3)
    let tgt := mkApp2 (mkConst ``And) (mkNot q) (mkApp p e)
    withLocalDeclD `h (mkAppN (mkConst ``Query) xs) fun h => do
      let vars := xs.push h
      addDecl (.thmDecl {
        name := `ConsensusCoverage.HandReadersBDispatch.necessary, levelParams := []
        type := ← mkForallFVars vars tgt
        value := ← mkLambdaFVars vars (← invert body h tgt p) })
end

run_cmd liftTermElabM makeInversion

variable [Consensus.Proofs.Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}

theorem query_iff (p : Event → Prop) (absent : ¬ Source c → Quiet f t) :
    Query f t c p ↔ Source c ∧ p c.event := by
  constructor
  · intro h
    have both := necessary f t c p h
    exact ⟨Classical.byContradiction (fun h => both.1 (absent h)),both.2⟩
  · rintro ⟨src,h⟩
    rcases site src with changed | packet | key
    · reach_arm step_summary_event_receive[15]
      exact ⟨c.event,⟨t,c.tr,changed,rfl⟩,h⟩
    · reach_arm step_summary_event_receive[16]
      exact ⟨c.event,⟨t,c.tr,packet,rfl⟩,h⟩
    · reach_arm step_summary_event_receive[9]
      exact ⟨c.event,⟨t,c.tr,key,rfl⟩,h⟩

end ConsensusCoverage.HandReadersBDispatch
