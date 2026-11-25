module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ActionProfile
public import ConsensusCoverage.StableGrantImpossibleB
public import ConsensusCoverage.PromotionImpossibleB
import all ConsensusCoverage.CaseUnreachable
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
meta import Lean

namespace ConsensusCoverage.CaseUnreachableB

open ActionProfile Consensus Consensus.Proofs
open Lean Meta Elab Tactic

set_option maxRecDepth 16384
set_option maxHeartbeats 0

private theorem primary_of_guard {r : Model.Node.Role} (h : ¬ (r != .primary) = true) :
    r = .primary := by simpa using h

-- The normalized caller alternatives differ, but all carry an impossible
-- role equation. Only open propositional constructors, never the call graph.
private meta def conflictingRoles (equalities : Array (Expr × Expr × Expr)) :
    MetaM Expr := do
  let role := ``Model.Node.Role
  for start in #[role.str "candidate", role.str "primary", role.str "none"] do
    let a := mkConst start
    let mut paths := #[(a, ← mkEqRefl a)]
    let mut i := 0
    while h : i < paths.size do
      let (b, ab) := paths[i]
      for (x, y, xy) in equalities do
        for (from_, to_, forward) in #[(x, y, true), (y, x, false)] do
          if ← isDefEq b from_ then
            unless ← paths.anyM (fun (z, _) => isDefEq to_ z) do
              let p ← mkEqTrans ab (← if forward then pure xy else mkEqSymm xy)
              let n := (← whnf to_).getAppFn.constName?
              if let some n := n then
                if n.getPrefix == role && n != start then
                  return ← mkNoConfusion (mkConst ``False) p
              paths := paths.push (to_, p)
      i := i + 1
  throwError "no incompatible node roles in this alternative"

private meta partial def rejectArm (todo : List (Expr × Expr))
    (eqs : Array (Expr × Expr × Expr)) : MetaM Expr := do
  let (p, h) :: rest := todo | return ← conflictingRoles eqs
  let p := p.consumeMData
  if p.isAppOfArity ``And 2 then
    return ← rejectArm ((p.getArg! 0, mkProj ``And 0 h) ::
      (p.getArg! 1, mkProj ``And 1 h) :: rest) eqs
  if p.isAppOfArity ``Exists 2 then
    let pred := p.getArg! 1
    return ← withLocalDeclD `w (p.getArg! 0) fun w => do
      let body := pred.beta #[w]
      withLocalDeclD `hw body fun hw => do
        let pr ← rejectArm ((body, hw) :: rest) eqs
        mkAppM ``Exists.elim #[h, ← mkLambdaFVars #[w, hw] pr]
  if p.isAppOfArity ``Eq 3 then
    if ← isDefEq (p.getArg! 0) (mkConst ``Model.Node.Role) then
      return ← rejectArm rest (eqs.push (p.getArg! 1, p.getArg! 2, h))
  if p.isAppOf ``Not then
    if let some primary ← observing? (mkAppM ``primary_of_guard #[h]) then
      let t ← inferType primary
      return ← rejectArm rest (eqs.push (t.getArg! 1, t.getArg! 2, primary))
  rejectArm rest eqs

private meta partial def rejectAlternatives (p h : Expr) : MetaM Expr := do
  if p.isAppOfArity ``Or 2 then
    let branch (q : Expr) := withLocalDeclD `branch q fun hb => do
      mkLambdaFVars #[hb] (← rejectAlternatives q hb)
    mkAppM ``Or.elim #[h, ← branch (p.getArg! 0), ← branch (p.getArg! 1)]
  else rejectArm [(p, h)] #[]

local elab "reject_roles " h:ident : tactic => withMainContext do
  let h ← getFVarFromUserName h.getId
  let some p ← unfoldDefinition? (← inferType h) | throwError "expected a case formula"
  (← getMainGoal).assign (← rejectAlternatives p h)
  replaceMainGoal []

local macro "role_case " s:ident b:ident : tactic => do
  let f := mkIdent ((`ConsensusCoverage.SolvedWitnesses).str ("step_" ++ b.getId.getString!))
  `(tactic|
    (letI : Config.InitialConfiguration := ⟨Step.cfg $s⟩
     apply CaseUnreachable.solved_false
     change ¬ $f (Step.frame $s) (Step.after $s) (Step.context $s)
     intro hypothesis
     reject_roles hypothesis))

public theorem ack_primary (s : Step) :
    label s (.step .appendEntriesResponse_summary_role_inl) = false := by
  role_case s appendEntriesResponse_summary_role_inl

public theorem ack_retired (s : Step) :
    label s (.step .appendEntriesResponse_summary_role_inr) = false := by
  role_case s appendEntriesResponse_summary_role_inr

public def refuted : List Classes.StepBranch :=
  [.appendEntriesResponse_summary_role_inl, .appendEntriesResponse_summary_role_inr,
   .voteRequest_summary_granted_inl, .voteRequest_summary_granted_inr,
   .campaign_summary_role_inr, .sentIndex_advance_inr]

public theorem count : refuted.Nodup ∧ refuted.length = 6 := by decide +kernel

public theorem label_false {b : Classes.StepBranch} (mem : b ∈ refuted) :
    ∀ s : Step, label s (.step b) = false := by
  simp only [refuted, List.mem_cons, List.not_mem_nil, or_false] at mem
  rcases mem with rfl | rfl | rfl | rfl | rfl | rfl
  · exact ack_primary
  · exact ack_retired
  · exact StableGrantImpossibleB.none
  · exact StableGrantImpossibleB.previous
  · exact PromotionImpossibleB.campaign_role
  · exact PromotionImpossibleB.sent_advance

end ConsensusCoverage.CaseUnreachableB
