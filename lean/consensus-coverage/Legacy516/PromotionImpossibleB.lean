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

private abbrev Bound (s : NodeState) := ∀ e ∈ s.log, e.term ≤ s.currentTerm

private theorem sameBound [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) {s middle before : NodeState} (eq : s = middle) (pre : before = c.pre)
    (log : middle.log = before.log) (term : middle.currentTerm = before.currentTerm) : Bound s := by
  subst s before
  intro e mem
  rw [term]
  exact c.inv.terms _ _ c.pre_now e (log ▸ mem)

private theorem freshOld {self s candidate} (eq : candidate = freshCandidate self s) (age : Bound s) :
    Old candidate := eq ▸ fun e h => Nat.lt_succ_of_le (age e h)

private theorem votedOld [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)
    {self before middle event candidate} (eq : candidate = middle) (pre : before = c.pre)
    (camp : Campaign self before event middle) : Old candidate := eq ▸ campOld c pre camp

private theorem cannotGrow (self : NodeID) {middle candidate : NodeState} (eq : middle = primaryState candidate)
    (age : Old candidate) : ¬middle.commitIndex < highestCommittableIndex middle self :=
  eq ▸ noAdvance age

private abbrev Fields := Array (Expr × Expr)

private meta partial def withFields (p h : Expr) (acc : Fields)
    (finish : Fields → MetaM Expr) : MetaM Expr := do
  if p.isAppOf ``Or then
    let branch (q : Expr) := withLocalDeclD `arm q fun a => do
      mkLambdaFVars #[a] (← withFields q a acc finish)
    return ← mkAppM ``Or.elim #[h, ← branch (p.getArg! 0), ← branch (p.getArg! 1)]
  if p.isAppOf ``Exists then
    let f := p.getArg! 1
    return ← withLocalDeclD f.bindingName! (p.getArg! 0) fun x => do
      let q := f.beta #[x]
      withLocalDeclD `arm q fun a => do
        let outcome ← withFields q a acc finish
        mkAppM ``Exists.elim #[h, ← mkLambdaFVars #[x,a] outcome]
  if p.isAppOf ``And then
    return ← withFields (p.getArg! 1) (mkProj ``And 1 h)
      (acc.push (p.getArg! 0, mkProj ``And 0 h)) finish
  finish (acc.push (p,h))

private meta def firstReach (xs : Fields) : MetaM (Expr × Expr × Expr) := do
  let some (p,h) := xs.find? fun (p,_) =>
    p.getAppFn.constName?.any (·.getString!.startsWith "reach_") | throwError "expected caller"
  let some body ← unfoldDefinition? p | throwError "opaque caller"
  return (p,h,body)

private meta def nodeEq (s : Expr) (xs : Fields) : MetaM (Expr × Expr) := do
  for (p,h) in xs do
    if p.isAppOf ``Eq && p.getArg! 1 == s then return (p.getArg! 2, h)
  throwError "missing equation for {s}"

private meta def freshBound (c s p h : Expr) : MetaM Expr :=
  withFields p h #[] fun xs => do
    let (_,h,p) ← firstReach xs
    withFields p h #[] fun ys => do
      let (r,hr,body) ← firstReach ys
      let some before ← r.getAppArgs.findM? fun x => do
        return x.isFVar && (← inferType x).isConstOf ``NodeState | throwError "no source state"
      let (middle,eq) ← (nodeEq s ys) <|> pure (s, ← mkEqRefl s)
      let pre ← beforeOrigin c before body hr
      mkAppM ``sameBound #[c, eq, pre, ← mkEqRefl (←mkAppM ``NodeState.log #[middle]),
        ← mkEqRefl (←mkAppM ``NodeState.currentTerm #[middle])]

private meta def candidateAge (c candidate p h : Expr) : MetaM Expr :=
  withFields p h #[] fun xs => do
    let (_,h,p) ← firstReach xs
    withFields p h #[] fun ys => do
      let (_,hr,body) ← firstReach ys
      let (rhs,eq) ← nodeEq candidate ys
      if rhs.isAppOf ``freshCandidate then
        return ← mkAppM ``freshOld #[eq, ← freshBound c rhs.appArg! body hr]
      let some (camp, hc) := ys.find? (fun (p,_) => p.isAppOf ``Campaign) | throwError "no campaign"
      let pre ← beforeOrigin c (camp.getArg! 1) body hr
      mkAppM ``votedOld #[c,eq,pre,hc]

local elab "no_promotion_growth " c:term:arg mid:ident orig:ident : tactic => withMainContext do
  let c ← Term.elabTerm c none
  let mid ← getFVarFromUserName mid.getId
  let h ← getFVarFromUserName orig.getId
  let some p ← unfoldDefinition? (←inferType h) | throwError "no origin"
  let result ← withFields p h #[] fun xs => do
    let (r,hr,body) ← firstReach xs
    let (leader,eq) ← nodeEq mid xs
    let age ← candidateAge c leader.appArg! body hr
    mkAppM ``cannotGrow #[r.appFn!.appArg!,eq,age]
  (←getMainGoal).assign result
  replaceMainGoal []

local macro "reject_sender " s:ident p:ident : tactic => `(tactic|
  (obtain ⟨self, middle, _, origin, ⟨_, _, _, _, _, _, grew, target, _⟩, _⟩ := $p
   have no : ¬ middle.commitIndex < highestCommittableIndex middle self := by
     no_promotion_growth ($s).context middle origin
   exact no (target ▸ grew)))

public theorem sent_advance (s : Step) : label s (.step .sentIndex_advance_inr) = false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  apply CaseUnreachable.solved_false
  change ¬ step_sentIndex_advance_inr s.frame s.after s.context
  intro p
  iterate 24 (rcases p with p | p; case inl => reject_sender s p)
  reject_sender s p

end ConsensusCoverage.PromotionImpossibleB
