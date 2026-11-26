module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ReadersRequestCuts
import all ConsensusCoverage.ReadersRequestCuts
import all ConsensusCoverage.ReadersAtoms
import all Consensus.Proofs.SafetyInvariant
public meta import Lean

namespace ConsensusCoverage.RequestTransport

open Lean Elab Command Meta
open Consensus Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open ConsensusCoverage ConsensusCoverage.ReadersAtoms ConsensusCoverage.ReadersShapes

theorem andUnder {p p' q q' : Prop} (left : p ↔ p') (right : p → (q ↔ q')) :
    p ∧ q ↔ p' ∧ q' :=
  ⟨fun ⟨p, q⟩ => ⟨left.mp p, (right p).mp q⟩, fun ⟨p', q'⟩ =>
    let p := left.mpr p'
    ⟨p, (right p).mpr q'⟩⟩

theorem somePin {α : Type} {a b : α} (e : some a = some b) : b = a :=
  (Option.some.inj e).symm

theorem stateMember {s : Model.State} {n : NodeID} {st : NodeState}
    (h : (n, st) ∈ s.nodes) : ∃ n, (n, st) ∈ s.nodes := ⟨n, h⟩

meta section

private partial def facts (h : Expr) : MetaM (Array (Expr × Expr)) := do
  let t := (← inferType h).consumeMData
  if t.isAppOfArity ``And 2 then
    return (← facts (← mkAppM ``And.left #[h])) ++ (← facts (← mkAppM ``And.right #[h]))
  else return #[(t, h)]

private partial def preserve (generated : Name → Bool) (ok r current p q : Expr)
    (localFacts : Array (Expr × Expr) := #[]) : MetaM Expr := do
  let p := p.consumeMData
  let q := q.consumeMData
  if p == q then return mkApp (mkConst ``Iff.rfl) p
  let desired ← mkAppM ``Iff #[p, q]
  let same a b := withReducible (isDefEq a b)
  let pin (prior : Expr) : MetaM (Option Expr) := do
    if ← same prior current then return some (← mkEqRefl prior)
    for (ty, h) in localFacts do
      if ty.isAppOfArity ``Eq 3 then
        let l := (ty.getArg! 1).consumeMData
        let z := ty.appArg!.consumeMData
        if (← same z prior) && (← same l current) then return some (← mkEqSymm h)
        if (← same l prior) && (← same z current) then return some h
        if l.isAppOf ``Option.some && z.isAppOf ``Option.some then
          if (← same z.appArg! prior) && (← same l.appArg! current) then
            return some (← mkAppM ``somePin #[h])
          if (← same l.appArg! prior) && (← same z.appArg! current) then
            return some (← mkAppM ``Option.some.inj #[h])
    return none
  let tryRule (rule : Name) (args : Array Expr) : MetaM (Option Expr) := withNewMCtxDepth do
    try
      let candidate ← mkAppM rule args
      let flipped ← mkAppM ``Iff.symm #[candidate]
      if ← withReducible (isDefEq (← inferType flipped) desired) then
        let proof ← instantiateMVars flipped
        if !proof.hasExprMVar then return some proof
      return none
    catch _ => return none
  if p.isAppOfArity ``And 2 && q.isAppOfArity ``And 2 then
    let l := p.getArg! 0
    let left ← preserve generated ok r current l (q.getArg! 0) localFacts
    let right ← withLocalDeclD `left l fun h => do
      let proof ← preserve generated ok r current p.appArg! q.appArg! (localFacts ++ (← facts h))
      mkLambdaFVars #[h] proof
    return ← mkAppM ``andUnder #[left, right]
  if p.isAppOfArity ``Or 2 && q.isAppOfArity ``Or 2 then
    return ← mkAppM ``or_congr #[← preserve generated ok r current (p.getArg! 0) (q.getArg! 0) localFacts,
      ← preserve generated ok r current p.appArg! q.appArg! localFacts]
  if p.isAppOfArity ``Not 1 && q.isAppOfArity ``Not 1 then
    return ← mkAppM ``not_congr #[← preserve generated ok r current p.appArg! q.appArg! localFacts]
  if p.isAppOfArity ``Exists 2 && q.isAppOfArity ``Exists 2 && p.getArg! 0 == q.getArg! 0 then
    let evidence ← withLocalDeclD `witness (p.getArg! 0) fun w => do
      let proof ← preserve generated ok r current (p.appArg!.beta #[w]) (q.appArg!.beta #[w]) localFacts
      mkLambdaFVars #[w] proof
    return ← mkAppM ``exists_congr #[evidence]
  if let .const n _ := p.getAppFn then
    if generated n && q.isAppOf n then
      let v := (← getConstInfo n).value!
      let proof ← preserve generated ok r current (v.beta p.getAppArgs) (v.beta q.getAppArgs) localFacts
      return mkExpectedPropHint proof desired
  if p.isAppOfArity ``voteLogUpToDate 2 then
    let state := p.getArg! 0
    for (ty, h) in localFacts do
      if ty.isAppOfArity ``Membership.mem 5 && ty.appArg!.isAppOfArity ``Prod.mk 4 &&
          ty.appArg!.appArg! == state then
        if let some proof ← tryRule ``request_vote_before #[ok, ← mkAppM ``stateMember #[h], r] then
          return proof
  else if p.isAppOf ``LogFacts.GrantAt then
    let args := p.getAppArgs
    let offset := args.size - 6
    if let some h ← pin args[offset]! then
      if let some proof ← tryRule ``request_grantAt_prior
          (#[ok, h] ++ args.extract (offset + 1) (args.size - 1) ++ #[r]) then
        return proof
    throwError "could not preserve grant {p}; arguments {args}; offset {offset}; facts {localFacts.map Prod.fst}"
  else if p.isAppOf ``VoterRank then
    let args := p.getAppArgs
    if let some proof ← tryRule ``request_rank_before
        (#[ok] ++ args.extract (args.size - 4) (args.size - 1) ++ #[r]) then return proof
  else if p.getAppNumArgs == 5 then
    let args := #[ok, p.getArg! 1, p.getArg! 2, p.getArg! 3, r]
    for rule in [``request_grant_before, ``request_grant_after] do
      if let some proof ← tryRule rule args then return proof
  throwError "unsupported request use {p}"

private def requestBinder (e : Expr) : Bool := Id.run do
  unless e.isAppOfArity ``Exists 2 && (e.getArg! 0).isConstOf ``RequestVoteRequest do
    return false
  let .lam _ _ body _ := e.appArg! | return false
  unless body.isAppOfArity ``And 2 do return true
  let guard := body.getArg! 0
  return !(guard.isAppOfArity ``Membership.mem 5 && (guard.getArg! 3).isAppOf ``replayRequests)

/-- Bound a request only after proving the whole body invariant under replacement. -/
public def normalize (generated : Name → Bool) (ok xv f p : Expr) : MetaM Simp.Result := do
  unless (p.find? requestBinder).isSome do return { expr := p }
  let hist := mkApp (mkConst ``requestHistory) xv
  let current := mkApp (mkConst ``Frame.current) f
  let rewrite ← IO.mkRef false
  let methods : Simp.Methods := { pre := fun e => do
    unless requestBinder e do return .continue
    let cert? ← withNewMCtxDepth do
      try
        withLocalDeclD `request (e.getArg! 0) fun r => do
          let rep ← mkAppM ``replayRequestRep #[hist, r]
          let lhs := e.appArg!.beta #[r]
          let rhs := e.appArg!.beta #[rep]
          let same ← preserve generated ok r current lhs rhs
          let same ← mkLambdaFVars #[r] same
          let cert ← withTransparency .all <| mkAppOptM ``replayRequests_bound #[hist, e.appArg!, same]
          let cert ← instantiateMVars cert
          return if cert.hasExprMVar then none else some cert
      catch _ => pure none
    let some cert := cert? | return .continue
    rewrite.set true
    return .visit {expr := (← inferType cert).appArg!, proof? := some (← mkAppM ``propext #[cert])} }
  let ctx ← Simp.mkContext (congrTheorems := ← getSimpCongrTheorems)
    (config := {autoUnfold := false})
  let (result, _) ← Simp.main p ctx (methods := methods)
  return if ← rewrite.get then result else { expr := p }

end
end ConsensusCoverage.RequestTransport
