module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.CensusQueueStep
public meta import ConsensusCoverage.ReadersPolarCompiler
public meta import ConsensusCoverage.ReadersRequestTransport
import all ConsensusCoverage.ReadersPolarCompiler
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ActionProfile
import all Consensus.Proofs.SafetyInvariant
public meta import Lean

namespace ConsensusCoverage.CensusQueueSearch

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety ActionProfile
open ReadersAtoms GuardedDomain Lean Meta Elab Tactic

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192

meta section

private structure Input where
  step : Expr
  view : Expr
  ctx : Expr
  pools : Expr
  proofArgs : Array Expr
  rules : Simp.Context
  nodes : IO.Ref Nat
  stop : IO.Ref (Nat × String)
  memo : IO.Ref (Std.HashMap Expr (Option Expr))
  candidateCache : IO.Ref (Std.HashMap Expr (Array Expr))
  traceFile : Option System.FilePath

private def head (p : Expr) : String :=
  if let some n := p.getAppFn.constName? then n.getString!
  else if p.isForall then "forall" else if p.isSort then "Sort" else toString p.getAppFn.ctorName

private def noted (i : Input) (path : List String) (p : Expr) (detail : String) : MetaM Unit := do
  let (score, _) ← i.stop.get
  if path.length > score then
    i.stop.set (path.length, s!"{String.intercalate "/" path.reverse}: {detail} [{head p}]")

private unsafe def testCode (b : Expr) : MetaM Bool :=
  evalExpr Bool (mkConst ``Bool) b (checkMeta := false)

-- An untrusted optimization, not a decision principle. `decided` emits the
-- reflexivity proof; a false positive from the evaluator fails in the kernel.
@[implemented_by testCode] private def test (b : Expr) : MetaM Bool :=
  return (← withTransparency .all (whnf b)).isConstOf ``Bool.true

private def decided (p : Expr) : MetaM (Option Expr) := do
  try
    let .some inst ← withReducible <| trySynthInstance (mkApp (mkConst ``Decidable) p) | return none
    let inst ← instantiateMVars inst
    if (inst.find? fun e => e.isConstOf ``Classical.propDecidable || e.isConstOf ``Classical.choice).isSome then return none
    let result := mkApp2 (mkConst ``decide) p inst
    unless ← test result do return none
    return some (mkApp3 (mkConst ``of_decide_eq_true) p inst (← mkEqRefl (mkConst ``Bool.true)))
  catch _ => return none

private def eqProof (p : Expr) : MetaM (Option Expr) := do
  if p.isAppOfArity ``Eq 3 && (← withReducible (isDefEq (p.getArg! 1) p.appArg!)) then
    return some (← mkEqRefl p.appArg!)
  if p.isAppOfArity ``HEq 4 && (← withReducible (isDefEq (p.getArg! 1) p.appArg!)) then
    return some (← mkAppM ``HEq.refl #[p.appArg!])
  return none

private def generated (n : Name) : Bool :=
  ((privateToUserName? n).getD n).getPrefix == `ConsensusCoverage.SolvedWitnesses

private def collectCandidates (i : Input) (ty : Expr) : MetaM (Array Expr) := do
  let mut xs := #[]
  let mut values := #[i.ctx, mkApp (mkConst ``Step.after) i.step, mkApp (mkConst ``Step.before) i.step]
  let base := mkApp (mkConst ``XView.base) i.view
  values := values ++ #[← mkAppM ``Ctx.tr #[i.ctx], mkApp (mkConst ``View.actor) base,
    mkApp (mkConst ``View.pre) base, mkApp (mkConst ``View.post) base,
    mkApp (mkConst ``View.after) base, mkApp (mkConst ``View.before) base,
    mkApp (mkConst ``XView.event) i.view, mkApp (mkConst ``XView.outputs) i.view,
    mkApp (mkConst ``XView.sent) i.view]
  for v in values do
    if ← withReducible (isDefEq (← inferType v) ty) then xs := xs.push v
  let some pool ← ReadersPolarCompiler.poolFor i.pools ty | return xs
  -- Preserve a compact, replayable term; only branch selection is untrusted.
  let length ← mkAppM ``List.length #[pool]
  let mut index := 0
  while index < 8 do
    let j := mkNatLit index
    let bound ← mkAppM ``LT.lt #[j, length]
    let some ok ← decided bound | break
    let fin ← mkAppOptM ``Fin.mk #[length, j, ok]
    xs := xs.push (← mkAppM ``List.get #[pool, fin])
    index := index + 1
  return xs

private def candidates (i : Input) (ty : Expr) : MetaM (Array Expr) := do
  if let some cached := (← i.candidateCache.get)[ty]? then return cached
  let xs ← collectCandidates i ty
  i.candidateCache.modify (·.insert ty xs)
  return xs

private def exactAtom (i : Input) (p : Expr) : MetaM (Option Expr) := do
  let some n := p.getAppFn.constName? | return none
  unless generated n do return none
  let name := Name.mkStr `ConsensusCoverage.ReadersCompiler.R (n.getString! ++ "_iff")
  unless (← getEnv).contains name do return none
  let args := p.getAppArgs.extract 4 p.getAppNumArgs
  let mut proof := mkAppN (mkConst name) i.proofArgs
  for a in args do
    let ty ← inferType proof
    if let .forallE _ d .. := ty then
      if ← withReducible (isDefEq d (← inferType a)) then
        proof := mkApp proof a
  let type ← inferType proof
  unless type.isAppOfArity ``Iff 2 do return none
  unless ← withReducible (isDefEq type.appArg! p) do return none
  if let some h ← decided (type.getArg! 0) then
    return some (← mkAppM ``Iff.mp #[proof, h])
  return none

private def nodeBudget := 48

private partial def solve (i : Input) (p : Expr) (path : List String) : MetaM (Option Expr) := do
  let p := p.consumeMData
  if let some result := (← i.memo.get)[p]? then return result
  if let some file := i.traceFile then
    IO.FS.writeFile file s!"{String.intercalate "/" path.reverse}: {head p}"
  if (← i.nodes.get) ≥ nodeBudget then
    noted i path p "search node budget exhausted"
    return none
  i.nodes.modify (· + 1)
  let recurse (q : Expr) (name : String) := solve i q (name :: path)
  let attempt : MetaM (Option Expr) := do
    if p.isConstOf ``True then return some (mkConst ``True.intro)
    if let some proof ← eqProof p then return some proof
    if p.isAppOfArity ``And 2 then
      let some l ← recurse (p.getArg! 0) "&0" | return none
      let some r ← recurse p.appArg! "&1" | return none
      return some (mkApp4 (mkConst ``And.intro) (p.getArg! 0) p.appArg! l r)
    if p.isAppOfArity ``Or 2 then
      if let some l ← recurse (p.getArg! 0) "|0" then
        return some (mkApp3 (mkConst ``Or.inl) (p.getArg! 0) p.appArg! l)
      if let some r ← recurse p.appArg! "|1" then
        return some (mkApp3 (mkConst ``Or.inr) (p.getArg! 0) p.appArg! r)
      return none
    if p.isAppOfArity ``Exists 2 && p.appArg!.isLambda then
      let fn := p.appArg!
      let xs ← candidates i fn.bindingDomain!
      noted i path p s!"exists {fn.bindingName!} : {head fn.bindingDomain!}; {xs.size} candidates"
      for v in xs do
        if (← i.nodes.get) ≥ nodeBudget then break
        if let some h ← recurse (fn.beta #[v]) s!"exists:{fn.bindingName!}" then
          return some (← mkAppOptM ``Exists.intro #[some fn.bindingDomain!, some fn, some v, some h])
      return none
    if let some n := p.getAppFn.constName? then
      if generated n then
        if let some h ← exactAtom i p then return some h
        let some body ← unfoldDefinition? p | return none
        return ← recurse body n.getString!
    if let some h ← decided p then return some h
    let (r, _) ← withReducible <| simp p i.rules #[]
    if r.expr != p then
      if let some h ← recurse r.expr "view" then return some (← mkEqMPR (← r.getProof) h)
    noted i path p s!"atom not discharged: {(toString (← ppExpr p)).take 130}"
    return none
  let result ← attempt
  i.memo.modify (·.insert p result)
  return result

elab "queue_prove" : tactic => withMainContext do
  let goal ← getMainGoal
  let ty ← instantiateMVars (← goal.getType)
  unless ty.isAppOfArity ``Eq 3 do throwError "expected a concrete step label goal"
  let lhs := ty.getArg! 1
  unless lhs.isAppOfArity ``label 2 && ty.appArg!.isConstOf ``Bool.true &&
      lhs.appArg!.isAppOfArity ``FullProfile.Question.step 1 do throwError "expected a concrete step label goal"
  let s := lhs.getArg! 0
  let b := lhs.appArg!.appArg!
  let some col := b.constName? | throwError "expected a concrete branch"
  let n := Name.mkStr `ConsensusCoverage.SolvedWitnesses ("step_" ++ col.getString!)
  let v ← mkAppM ``CensusQueueStep.view #[s]
  let c ← mkAppM ``CensusQueueStep.context #[s]
  let ok ← mkAppM ``CensusQueueStep.reflected #[s]
  let args := (← inferType c).getAppArgs.push c
  let proofArgs := args ++ #[v, ok]
  let mut rules : SimpTheorems := {}
  for r in [``X.now_before, ``X.now_after, ``X.grant_before, ``X.grant_after,
      ``X.elected_before, ``X.elected_after, ``X.seen_before, ``X.seen_after,
      ``X.canon_before, ``X.canon_after, ``X.committed_before, ``X.committed_after,
      ``X.led_before, ``X.led_after, ``X.pending_before, ``X.pending_after] do
    let proof := mkAppN (mkConst r) (args.extract 0 3 ++ #[v, c, ok])
    rules ← rules.add (.other r) #[] proof
  let sc ← Simp.mkContext (simpTheorems := #[rules]) (congrTheorems := ← getSimpCongrTheorems)
  let i : Input := ⟨s, v, c, ← mkAppM ``CensusQueueStep.pools #[s], proofArgs, sc,
    ← IO.mkRef 0, ← IO.mkRef (0, "root"), ← IO.mkRef {}, ← IO.mkRef {},
    (← IO.getEnv "CCF_QUEUE_TRACE").map System.FilePath.mk⟩
  let some cert ← solve i (mkAppN (mkConst n) args) [n.getString!]
    | throwError "queue stopped after {← i.nodes.get} nodes: {(← i.stop.get).2}"
  goal.assign (← mkAppM ``CensusQueueStep.ofFormula #[s, b, cert])
  replaceMainGoal []

end
end ConsensusCoverage.CensusQueueSearch
