module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import Lean
public meta import ConsensusCoverage.ReachPath
public meta import ConsensusCoverage.PinnedClasses
public meta import ConsensusCoverage.SolvedWitnesses

namespace ConsensusCoverage.HandReadersOther.Facts

open Consensus Model Model.Node Proofs Safety SolvedWitnesses Lean Meta Elab Tactic
set_option maxRecDepth 8192
set_option maxHeartbeats 5000000

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)

abbrev Source := step_commit_backed_kind_append f t c ∨ step_commit_backed_kind_ack f t c ∨
  step_post_log_kind_append f t c ∨ step_post_log_kind_ack f t c ∨
  step_keep_log_kind_append f t c ∨ step_keep_log_kind_ack f t c ∨
  step_persist_pre_kind_append f t c ∨ step_persist_pre_kind_ack f t c

open Elab.Term in
local elab "fact_sites%" : term => do
  let q := ``step_facts_advance_inr
  let rs := ReachPath.children q.getPrefix (←getConstInfo q).value!
  lambdaTelescope (←getConstInfo rs[0]!).value! fun xs _ => do
    let es := rs.toList.map fun r => mkAppN (mkConst r) xs
    mkLambdaFVars xs (es.dropLast.foldr (mkApp2 (mkConst ``Or)) es.getLast!)

abbrev Sites := fact_sites%

private theorem strong (b : Backed (f.advance t) c.post.log c.post.commitIndex c.post.currentTerm) :
    (∃ term, Backed (f.advance t) c.post.log c.post.commitIndex term) ∧
      (¬c.post.role = .candidate → Led (f.advance t) c.actor c.post.currentTerm →
        Backed (f.advance t) c.post.log c.post.commitIndex c.post.currentTerm) := ⟨⟨_,b⟩,fun _ _ => b⟩
end

/- Both families record the same append/ACK witness. The generated paths have
different numbers of redundant conjunctions. Copy the matching witness fields
without unfolding any of the underlying reach predicates or protocol guards. -/
private meta def transparent (n : Name) : MetaM Bool := do
  let q := ``step_facts_advance_inr
  return n == ``Source || n == ``Sites || (ReachPath.children q.getPrefix (←getConstInfo q).value!).contains n ||
    #[``step_commit_backed_kind_append,``step_commit_backed_kind_ack,``step_post_log_kind_append,
      ``step_post_log_kind_ack,``step_keep_log_kind_append,``step_keep_log_kind_ack,
      ``step_persist_pre_kind_append,``step_persist_pre_kind_ack].contains n

private meta partial def peel (h : Expr) (xs : Array Expr) (finish : Array Expr → MetaM Expr) : MetaM Expr := do
  let mut p ← inferType h
  while ← transparent (p.getAppFn.constName?.getD .anonymous) do p := (←unfoldDefinition? p).get!
  if p.isAppOf ``Or then
    let body ← #[p.getArg! 0,p.appArg!].mapM fun a => withLocalDeclD `case a fun y => do
      mkLambdaFVars #[y] (←peel y xs finish)
    return ←mkAppM ``Or.elim #[h,body[0]!,body[1]!]
  if p.isAppOf ``And then
    return ←peel (mkProj ``And 1 h) (xs.push (mkProj ``And 0 h)) finish
  if p.isAppOf ``Exists then
    return ←withLocalDeclD `w (p.getArg! 0) fun w => withLocalDeclD `rest (p.appArg!.beta #[w]) fun r => do
      mkAppM ``Exists.elim #[h,←mkLambdaFVars #[w,r] (←peel r (xs.push w) finish)]
  finish (xs.push h)

private meta def matching (a b : Expr) : MetaM Bool := do
  if a == b then return true
  if a.getAppFn != b.getAppFn && !(a.isForall && b.isForall) then return false
  withReducible <| isDefEq a b

private meta partial def pack (p : Expr) (xs : Array (Expr × Expr)) : MetaM (Option Expr) := do
  for (x,t) in xs do
    if ← matching t p then return some x
  if p.isAppOf ``Eq && (←withReducible <| isDefEq (p.getArg! 1) p.appArg!) then
    return some (←mkEqRefl p.appArg!)
  if p.isAppOf ``Or then
    if let some h ← pack (p.getArg! 0) xs then return some (←mkAppOptM ``Or.inl #[none,p.appArg!,h])
    if let some h ← pack p.appArg! xs then return some (←mkAppOptM ``Or.inr #[p.getArg! 0,none,h])
  if p.isAppOf ``And then
    let some a ← pack (p.getArg! 0) xs | return none
    let some b ← pack p.appArg! xs | return none
    return some (←mkAppM ``And.intro #[a,b])
  if p.isAppOf ``Exists then
    for (x,t) in xs do
      if ← matching t (p.getArg! 0) then
        if let some h ← pack (p.appArg!.beta #[x]) xs then
          return some (←mkAppOptM ``Exists.intro #[none,p.appArg!,x,h])
  if let some n := p.getAppFn.constName? then
    if ← transparent n then return ←pack (←unfoldDefinition? p).get! xs
  return none

private meta def assemble (goal : Expr) (xs : Array Expr) : MetaM Expr := do
  let ctx ← xs.mapM fun x => do return (x,←inferType x)
  let some proof ← pack goal ctx | throwError "no matching caller for {goal.getAppFn}: {ctx.map (·.2.getAppFn)}"
  mkExpectedTypeHint proof goal

local elab "invert_sites " h:ident " at " mid:ident : tactic => withMainContext do
  let g ← getMainGoal
  let m ← getFVarFromUserName mid.getId
  let goal ← g.getType
  let c ← getFVarFromUserName `c
  let term ← peel (← getFVarFromUserName h.getId) #[] fun xs => do
    let some eq ← xs.findSomeM? (fun x => do
      let p ← inferType x
      return if p.isAppOf ``Eq && p.getArg! 1 == m then some x else none)
      | throwError "missing intermediate state pin"
    let idx ← mkAppM ``congrArg #[mkConst ``NodeState.commitIndex,eq]
    assemble goal (xs ++ #[idx,←mkAppM ``strong #[c]])
  g.assign term

local elab "restore_sites " h:ident : tactic => withMainContext do
  let g ← getMainGoal
  let goal ← g.getType
  let c ← getFVarFromUserName `c
  let term ← peel (←getFVarFromUserName h.getId) #[] fun xs => do
    let some a ← xs.findSomeM? (fun x => do return if (←inferType x).isAppOf ``Safety.Advance then some x else none)
      | throwError "missing Advance witness"
    let args := (←inferType a).getAppArgs
    let m := args[args.size-2]!
    let body := goal.appArg!.beta #[m]
    let facts := xs ++ #[←mkAppM ``Ctx.post_now #[c],←mkAppM ``Safety.Advance.log #[a],←mkAppM ``Safety.Advance.term #[a]]
    mkExpectedTypeHint (←mkAppOptM ``Exists.intro #[none,goal.appArg!,m,←assemble body facts]) goal
  g.assign term

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)

theorem decode {self m z} (h : Sites f t c self m z) :
    m.commitIndex = c.pre.commitIndex ∧ z = c.post ∧ c.pre.role = .primary ∧ Source c := by invert_sites h at m

theorem encode (h : Source c) : ∃ m, Sites f t c c.actor m c.post ∧
    Safety.Advance c.actor m c.post ∧ m.commitIndex = c.pre.commitIndex := by restore_sites h
end

end ConsensusCoverage.HandReadersOther.Facts
