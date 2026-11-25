module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public meta import ConsensusCoverage.ReachPath
public meta import ConsensusCoverage.PinnedClasses
public meta import Lean
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersElectionB.Bridge

open Lean Meta Elab Command Term Tactic
open Consensus.Proofs.Safety SolvedWitnesses
set_option maxRecDepth 8192
set_option maxHeartbeats 2000000
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

meta section

/-- Rebuild one normalized caller tuple. Data witnesses retain their binder
names; proof witnesses can be transported by proof irrelevance. A call to a
different predicate needs a previously proved bridge, not just a name match. -/
private partial def assemble (rules : Array Name) (g : MVarId) (xs : List Expr) : MetaM Unit := g.withContext do
  let goal := (←instantiateMVars (←g.getType)).consumeMData.headBeta.consumeMData
  for x in xs do
    let ty ← inferType x
    if ← withReducible <| isDefEq ty goal then return ← g.assign x
    let ty := (←instantiateMVars ty).consumeMData
    if goal.getAppFn.constName?.any (·.getString!.startsWith "reach_") &&
        ty.getAppFn.constName?.any (·.getString!.startsWith "reach_") then
      for thm in rules do
        for (rich,forward) in [(ty,true),(goal,false)] do
          let args := rich.getAppArgs
          for actual in #[args,args.extract 0 4 ++ args.extract 5 args.size] do
            let pr := mkAppN (mkConst thm) actual
            try
              let sides ← inferType pr
              unless sides.isAppOf ``Iff do continue
              let a := sides.getArg! (if forward then 0 else 1)
              let b := sides.getArg! (if forward then 1 else 0)
              if (←withReducible <| isDefEq a ty) && (←withReducible <| isDefEq b goal) then
                return ←g.assign (←mkAppM (if forward then ``Iff.mp else ``Iff.mpr) #[pr,x])
            catch _ => pure ()
  if goal.isAppOf ``HEq then
    try
      let [] ← g.applyConst ``proof_irrel_heq | throwError "not proof witnesses"
      return
    catch _ => pure ()
    try g.hrefl; return catch _ => pure ()
  if goal.isAppOf ``Eq || goal.isAppOf ``HEq then
    try g.refl; return catch _ => pure ()
    let saved ← saveState
    try
      let next ← substVars g
      next.refl
      return
    catch _ => saved.restore
  if goal.isAppOf ``And then
    let [l,r] ← g.applyConst ``And.intro | throwError "expected conjunction"
    assemble rules l xs
    assemble rules r xs
    return
  if goal.isAppOf ``Or then
    for inj in [``Or.inl,``Or.inr] do
      let saved ← saveState
      try
        let [body] ← g.applyConst inj | throwError "expected disjunction"
        assemble rules body xs
        return
      catch _ => saved.restore
    throwError "no matching disjunct"
  if goal.isAppOf ``Exists then
    let ty := goal.getArg! 0
    let mut reason := m!"no candidates"
    let (preferred,rest) ← xs.partitionM fun x => do
      return (←x.fvarId!.getUserName).eraseMacroScopes == goal.appArg!.bindingName!.eraseMacroScopes
    for x in (if preferred.isEmpty then rest else preferred) do
      let xt ← inferType x
      unless ← withReducible <| isDefEq ty xt do continue
      let saved ← saveState
      try
        let inner ← mkFreshExprSyntheticOpaqueMVar (goal.appArg!.beta #[x])
        assemble rules inner.mvarId! xs
        g.assign (← mkAppOptM ``Exists.intro #[some ty,some goal.appArg!,some x,some inner])
        return
      catch e =>
        if (←e.toMessageData.toString).length > (←reason.toString).length then
          reason := e.toMessageData
        saved.restore
    throwError "no matching witness for {goal.appArg!.bindingName!} : {ty}: {reason}"
  throwError "missing {goal}"

private partial def unpack (rules : Array Name) (g : MVarId) (h : FVarId) : MetaM Unit := g.withContext do
  let p := (←instantiateMVars (←h.getType)).consumeMData.headBeta.consumeMData
  if p.isAppOf ``And || p.isAppOf ``Exists then
    let #[s] ← g.cases h | throwError "unexpected spine"
    let tail := s.fields.back!
    let next ← if p.isAppOf ``Exists then s.mvarId.rename s.fields[0]!.fvarId! p.appArg!.bindingName!
      else pure s.mvarId
    unpack rules next tail.fvarId!
  else if p.isAppOf ``Or then
    for s in ← g.cases h do unpack rules s.mvarId s.fields.back!.fvarId!
  else
    let saved ← saveState
    try
      assemble rules g ((← getLCtx).getFVarIds.toList.reverse.map mkFVar)
      return
    catch _ => saved.restore
    let g ← substVars g
    g.withContext do
      let xs := (← getLCtx).getFVarIds.toList.reverse.map mkFVar
      assemble rules g xs

local elab "bridgeSpine " h:ident "[" rules:ident,* "]" : tactic => withMainContext do
  unpack (rules.getElems.map (·.getId)) (←getMainGoal) (← getFVarId h)
  replaceMainGoal []

def name (i : Nat) : Name := (`ConsensusCoverage.HandReadersElectionB.Bridge.site).appendIndexAfter i

/-- Compare the two caller DAGs bottom-up, pinning an extra context to the
recorded context where the ordinary caller has already eliminated it. -/
private partial def derive (p q : Name) (path : List Nat) (seen : Std.HashMap (Name × Name) Name) :
    TermElabM (Std.HashMap (Name × Name) Name) := do
  if p == q || seen.contains (p,q) then return seen
  let pa := (←getConstInfo p).value!
  let pb := (←getConstInfo q).value!
  let mut seen := seen
  let mut rules := #[]
  let parents := (ReachPath.children p.getPrefix pa).zip (ReachPath.children q.getPrefix pb)
  for ((a,b),i) in parents.zipIdx do
    seen ← derive a b (path ++ [i]) seen
    if let some n := seen[(a,b)]? then rules := rules.push (mkIdent n)
  let n := name seen.size
  lambdaTelescope pa fun xs _ => do
    let args := xs.extract 4 xs.size
    let data ← args.filterM fun x => do return !(←isProp (←inferType x))
    let stem := xs.extract 0 4
    let raw := mkAppN (mkConst q) (stem ++ data)
    let omitCtx := !(← try check raw; isProp raw catch _ => pure false)
    let mut thin := stem
    let mut thick := stem
    let mut params := stem
    for x in args do
      let ty ←inferType x
      if omitCtx && ty.isAppOf ``Ctx then
        thick := thick.push stem[3]!
      else
        thick := thick.push x
        params := params.push x
        unless ←isProp ty do thin := thin.push x
    let ty ← mkAppM ``Iff #[mkAppN (mkConst p) thick,mkAppN (mkConst q) thin]
    let proof ← `(by
      unfold $(mkIdent p):ident $(mkIdent q):ident
      try simp only [$[$rules:ident],*, heq_self, eq_self, and_true, true_and]
      first | exact Iff.rfl | constructor <;> intro h <;> bridgeSpine h [$[$rules:ident],*])
    try
      let g ← mkFreshExprSyntheticOpaqueMVar ty
      let `(term| by $tac:tacticSeq) := proof | throwUnsupportedSyntax
      let gs ← Tactic.run g.mvarId! <| Tactic.withoutRecover (evalTactic tac)
      unless gs.isEmpty do throwError "open goals"
      let pf ←instantiateMVars g
      addDecl (.thmDecl {
        name := n, levelParams := [],type := ←mkForallFVars params ty
        value := ←mkLambdaFVars params pf})
    catch e => throwError "overlap caller {path}, {p.getString!}/{q.getString!}: {e.toMessageData}"
  return seen.insert (p,q) n

local elab "bridgeOverlap" : command => liftTermElabM do
  let p := ``step_activeConfigurations_overlap_chosen_bound_inr
  let q := ``step_activeConfigurations_overlap_le_total_inl
  let ps := ReachPath.children p.getPrefix (←getConstInfo p).value!
  let qs := ReachPath.children q.getPrefix (←getConstInfo q).value!
  let mut seen := {}
  for (x,i) in ps.zipIdx do
    seen ← derive x qs[i]! [i] seen
    let pr := Lean.mkConst seen[(x,qs[i]!)]!
    addDecl (.thmDecl {
      name := (`ConsensusCoverage.HandReadersElectionB.Bridge.origin).appendIndexAfter i
      levelParams := [], type := ←inferType pr, value := pr })

bridgeOverlap

end

end ConsensusCoverage.HandReadersElectionB.Bridge
