module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.StableGrantImpossibleB
import all ConsensusCoverage.CaseUnreachable
import all ConsensusCoverage.StableGrantImpossibleB
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ReachPath
import all Consensus.Proofs.SafetyInvariant
meta import Lean

namespace ConsensusCoverage.PromotionImpossibleB

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open Lean Meta Elab Tactic ActionProfile SolvedWitnesses

set_option maxRecDepth 16384
set_option maxHeartbeats 0

private abbrev Old (s : NodeState) := ∀ e ∈ s.log, e.term < s.currentTerm

private theorem campOld [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)
    {self before candidate event} (pre : before = c.pre) (camp : Campaign self before event candidate) :
    Old candidate := by
  subst before
  obtain ⟨_, log, _, fresh | prior⟩ := camp
  · intro e h
    rw [fresh.2.1]
    exact Nat.lt_succ_of_le (c.inv.terms _ _ c.pre_now e (log ▸ h))
  · intro e h
    rw [prior.2.1]
    exact (c.inv.candidate _ _ c.pre_now prior.1).2.2.2.2 e (log ▸ h)

private theorem noAdvance {self : NodeID} {candidate : NodeState} (old : Old candidate) :
    ¬(primaryState candidate).commitIndex < highestCommittableIndex (primaryState candidate) self := by
  intro grows
  obtain ⟨_, sigAt, term, _⟩ := highestCommittableIndex_spec _ _ grows
  obtain ⟨entry, found, _⟩ := Ledger.isSignatureAtTrue sigAt
  have member := Ledger.entryAt_mem found
  have sub : (primaryState candidate).log <+: candidate.log := by
    simp only [primaryState]
    split <;> first | exact List.take_prefix _ _ | exact List.prefix_refl _
  have lt := old entry (sub.subset member)
  change ((entryAt? _ _).map Entry.term).getD 0 = candidate.currentTerm at term
  rw [found] at term
  have eq : entry.term = candidate.currentTerm := term
  exact (Nat.ne_of_lt lt) eq

private theorem primaryOnly {self} {candidate state : NodeState} (old : Old candidate)
    (adv : Advance self (primaryState candidate) state) : state.role = .primary := by
  rcases adv with rfl | ⟨_, _, _, _, _, _, grew, target, _⟩
  · rfl
  · exact (noAdvance old (target ▸ grew)).elim

private theorem preEq [Config.InitialConfiguration] {f : Frame} {t dst : Model.State} (c : Ctx f t)
    (tr : LocalTransition f.current dst) (id : dst = t ∧ HEq tr c.tr) : tr.pre = c.pre := by
  obtain ⟨rfl, id⟩ := id
  obtain rfl := eq_of_heq id
  rfl

private meta def conjunctions (body h : Expr) : Array (Expr × Expr) := Id.run do
  let mut r := #[]
  let mut b := body
  let mut p := h
  while b.isAppOf ``And do
    r := r.push (b.getArg! 0, mkProj ``And 0 p)
    b := b.getArg! 1
    p := mkProj ``And 1 p
  return r.push (b,p)

-- Project the actual pre-state, stopping at the shared transition source
-- instead of unfolding any historical invariant that led to that source.
private meta partial def beforeOrigin (c lhs body h : Expr) : MetaM Expr := do
  if body.isAppOf ``Or then
    let arm (q : Expr) := withLocalDeclD `arm q fun a => do mkLambdaFVars #[a] (← beforeOrigin c lhs q a)
    return ← mkAppM ``Or.elim #[h, ← arm (body.getArg! 0), ← arm (body.getArg! 1)]
  if body.isAppOf ``Exists then
    let s := body.getArg! 1
    return ← withLocalDeclD s.bindingName! (body.getArg! 0) fun x => do
      let ty := s.beta #[x]
      withLocalDeclD `entry ty fun a => do
        let p ← beforeOrigin c lhs ty a
        mkAppM ``Exists.elim #[h, ← mkLambdaFVars #[x,a] p]
  let fields := conjunctions body h
  let some (r,proof) := fields.find? fun (p,_) =>
    p.getAppFn.constName?.any (·.getString!.startsWith "reach_") | throwError "not a caller {body.getAppFn}"
  let some value ← unfoldDefinition? r | throwError "opaque caller"
  let tr := r.appArg!
  let trType ← inferType tr
  if trType.isAppOf ``LocalTransition then
    let target ← mkEq (trType.getArg! 1) (← inferType c).appArg!
    let idType ← mkAppM ``And #[target, ← mkHEq tr (←mkAppM ``Ctx.tr #[c])]
    let idProof ← StableGrantImpossibleB.ends value proof idType
    let pre ← mkAppM ``preEq #[c, tr, idProof]
    for (p,v) in fields do
      if p.isAppOf ``Eq && (← isDefEq (p.getArg! 1) lhs) then
        if let some ans ← observing? (mkEqTrans v pre) then return ans
    throwError "pre-state not tied to transition"
  beforeOrigin c lhs value proof

local elab "actor_before " c:term:arg before:ident h:ident : tactic => withMainContext do
  let c ← Term.elabTerm c none
  let b ← getFVarFromUserName before.getId
  let h ← getFVarFromUserName h.getId
  let some body ← unfoldDefinition? (←inferType h) | throwError "expected summary caller"
  (←getMainGoal).assign (←beforeOrigin c b body h)
  replaceMainGoal []

local macro "campaign_candidate " p:ident : tactic => `(tactic|
  (obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, cand, none, _⟩ := $p
   exact Role.noConfusion (cand.symm.trans none)))

local macro "campaign_heartbeat " s:ident p:ident : tactic => `(tactic|
  (obtain ⟨_, before, _, _, _, _, origin, _, _, _, adv, _, _, _, _, _, _, _, _, _, none, camp, _⟩ := $p
   have pre : before = ($s).context.pre := by actor_before ($s).context before origin
   exact Role.noConfusion ((primaryOnly (campOld ($s).context pre camp) adv).symm.trans none)))

local macro "campaign_request " p:ident : tactic => `(tactic|
  (obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, cand, none, _⟩ := $p
   exact Role.noConfusion (cand.symm.trans none)))

public theorem campaign_role (s : Step) : label s (.step .campaign_summary_role_inr) = false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  apply CaseUnreachable.solved_false
  change ¬ step_campaign_summary_role_inr s.frame s.after s.context
  intro p
  iterate 25 (rcases p with p | p; case inl => campaign_candidate p)
  iterate 25 (rcases p with p | p; case inl => campaign_heartbeat s p)
  iterate 24 (rcases p with p | p; case inl => campaign_request p)
  campaign_request p

end ConsensusCoverage.PromotionImpossibleB
