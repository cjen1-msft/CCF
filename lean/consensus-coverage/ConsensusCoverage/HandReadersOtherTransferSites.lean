module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersOtherWeaken
import all ConsensusCoverage.HandReadersOtherShorten
import all ConsensusCoverage.HandReadersOtherFactsSites
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersOtherFactsSites
public meta import Lean

namespace ConsensusCoverage.HandReadersOther.Transfer

open Consensus Model Model.Node Proofs Safety Ledger ActionProfile SolvedWitnesses
open Lean Meta Elab Tactic
set_option maxRecDepth 8192
set_option maxHeartbeats 3000000
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)

abbrev Site (l l' : List Entry) (i k : Nat) :=
  (reach% step_transfer_backed_inr[0]) f t c l l' i k ∨
  (reach% step_transfer_backed_inr[1]) f t c l l' i k ∨
  (reach% step_transfer_backed_inr[2]) f t c l l' i k ∨
  (reach% step_transfer_backed_inr[3]) f t c l l' i k

abbrev AnySite := (reach% step_transfer_backed_inr[0,1]) f t c c ∨
  (reach% step_transfer_backed_inr[1,1]) f t c c ∨ (reach% step_transfer_backed_inr[0,2]) f t c c ∨
  (reach% step_transfer_backed_inr[1,2]) f t c c
abbrev AnyGate := step_commit_backed_kind_same f t c ∨ step_accept_backed_max_eq_or_inl f t c
end

/- A transfer extends existing witness tuples. Only unwrap the selected
source/target definitions: the mathematical premises themselves stay opaque. -/
private meta partial def alternatives (expand : List Name) (goal : Expr) (xs : Array Expr) : MetaM (Option Expr) := do
  let goal := goal.consumeMData
  if expand.contains (goal.getAppFn.constName?.getD .anonymous) then
    return ← alternatives expand (←unfoldDefinition? goal).get! xs
  if goal.isAppOf ``Or then
    if let some h ← alternatives expand (goal.getArg! 0) xs then
      return some (←mkAppOptM ``Or.inl #[none,goal.appArg!,h])
    if let some h ← alternatives expand goal.appArg! xs then
      return some (←mkAppOptM ``Or.inr #[goal.getArg! 0,none,h])
    return none
  Facts.pack goal (←xs.mapM fun x => do return (x,←inferType x))

private meta partial def unpack (expand : List Name) (p h : Expr) (xs : Array Expr)
    (finish : Array Expr → MetaM Expr) : MetaM Expr := do
  let p := p.consumeMData
  if expand.contains (p.getAppFn.constName?.getD .anonymous) then
    return ←unpack expand (←unfoldDefinition? p).get! h xs finish
  if p.isAppOf ``Or then
    let fs ← #[p.getArg! 0,p.appArg!].mapM fun a => withLocalDeclD `branch a fun w => do
      mkLambdaFVars #[w] (←unpack expand a w xs finish)
    return ←mkAppM ``Or.elim #[h,fs[0]!,fs[1]!]
  if p.isAppOf ``Exists then
    return ←withLocalDeclD `w (p.getArg! 0) fun w => do
      let a := p.appArg!.beta #[w]
      withLocalDeclD `tail a fun r => do
        mkAppM ``Exists.elim #[h,←mkLambdaFVars #[w,r] (←unpack expand a r (xs.push w) finish)]
  if p.isAppOf ``And then
    return ←unpack expand p.appArg! (mkProj ``And 1 h) (xs.push (mkProj ``And 0 h)) finish
  finish (xs.push h)

local elab "splice " h:ident " using " tags:ident,* : tactic => withMainContext do
  let mut expand := [``Site,``Weaken.Site,``AnySite,``AnyGate,``Shorten.Incoming]
  for tag in tags.getElems do
    let n ← realizeGlobalConstNoOverloadWithInfo tag
    expand := n::expand ++ (ReachPath.children n.getPrefix (←getConstInfo n).value!).toList
  let goal ← instantiateMVars (←(←getMainGoal).getType)
  let x ← getFVarFromUserName h.getId
  let mut locals := #[]
  for decl in ←getLCtx do
    unless decl.isImplementationDetail do locals := locals.push decl.toExpr
  let available := locals
  let pf ← unpack expand (←instantiateMVars (←inferType x)) x #[] fun xs => do
    let some pf ← alternatives expand goal (xs ++ available) |
      throwError "missing transfer fields for {goal.getAppFn}, have {(←xs.mapM fun a => do return (←inferType a).getAppFn)}"
    mkExpectedTypeHint pf goal
  (←getMainGoal).assign pf

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)

theorem weakened {q : Bool} (src : Weaken.Gate c q) :
    Site c c.pre.log c.post.log c.pre.commitIndex c.post.currentTerm ∧
      Backed f c.pre.log c.pre.commitIndex c.post.currentTerm ∧ Weaken.Agree c := by
  obtain ⟨h,b,agree,le⟩ := Weaken.encode c q src
  refine ⟨?_,b.weaken le,agree⟩
  splice h using step_weaken_backed_inr,step_transfer_backed_inr

private theorem any_gate (h : AnySite c) : AnyGate c := by
  -- The outer calls state the shape's actual equality, not an inferred action tag.
  rcases h with h | h | h | h
  all_goals first
    | obtain ⟨rt,a,b,log,idx,eq,now,strong,_⟩ := h
      left
      first | exact .inl ⟨rt,a,b,log,idx,eq,now,strong⟩ | exact .inr ⟨rt,a,b,log,idx,eq,now,strong⟩
    | right
      first
      | reach_unfold step_transfer_backed_inr[0,2] at h; splice h using step_accept_backed_max_eq_or_inl
      | reach_unfold step_transfer_backed_inr[1,2] at h; splice h using step_accept_backed_max_eq_or_inl

private theorem take_agree {n r} (ev : c.event = .receive n (.appendEntriesRequest r)) (acc : Accepted c.pre r c.post) :
    Weaken.Agree c := by
  obtain ⟨l,_,_,_,same | ⟨eq,_⟩,prior⟩ := c.accept_shape ev acc
  · unfold Weaken.Agree; rw [same]
  · unfold Weaken.Agree
    have le := acc.2.2.1
    rw [eq,List.take_take,Nat.min_eq_left (Nat.le_trans le (Nat.le_add_right _ _))]
    have h := congrArg (List.take c.pre.commitIndex) prior
    simpa only [List.take_take,Nat.min_eq_left le] using h.symm

private theorem any_ready (h : AnyGate c) : AnySite c ∧ Weaken.Agree c := by
  rcases h with (h | h) | (h | h)
  all_goals first
    | obtain ⟨rt,a,b,log,idx,eq,now,strong⟩ := h
      have agree : Weaken.Agree c := by unfold Weaken.Agree; rw [log]
      refine ⟨?_,agree⟩
      first | exact .inl ⟨rt,a,b,log,idx,eq,now,strong,agree,rfl⟩
            | exact .inr (.inl ⟨rt,a,b,log,idx,eq,now,strong,agree,rfl⟩)
    | obtain ⟨n,r,src,l,rest⟩ := h
      have ev : c.event = .receive n (.appendEntriesRequest r) := by
        repeat' first | exact rest.1 | obtain ⟨_,rest⟩ := rest
      have acc : Accepted c.pre r c.post := by repeat' first | exact rest | obtain ⟨_,rest⟩ := rest
      refine ⟨?_,take_agree c ev acc⟩
      right; right
      first
      | left; reach_unfold step_transfer_backed_inr[0,2]; splice rest using
      | right; reach_unfold step_transfer_backed_inr[1,2]; splice rest using

theorem unbounded {k} (h : AnyGate c) (b : Backed f c.pre.log c.pre.commitIndex k) :
    Site c c.pre.log c.post.log c.pre.commitIndex k ∧ Weaken.Agree c := by
  obtain ⟨r,agree⟩ := any_ready c h
  have inv := c.inv.commit_backed _ _ c.pre_now
  refine ⟨?_,agree⟩; rcases r with r | r | r | r
  · exact .inl (.inr (.inr (.inl ⟨r,inv.1,inv.2,b,agree,rfl,rfl,rfl⟩)))
  · exact .inr (.inl (.inr (.inr (.inl ⟨r,inv.1,inv.2,b,agree,rfl,rfl,rfl⟩))))
  · exact .inl (.inr (.inr (.inr (.inl ⟨r,inv.1,inv.2,b,agree,rfl,rfl,rfl⟩))))
  · exact .inr (.inl (.inr (.inr (.inr (.inl ⟨r,inv.1,inv.2,b,agree,rfl,rfl,rfl⟩)))))

private abbrev Later := step_accept_backed_max_eq_or_inr f t c

theorem later_ready (h : Later c) : ∃ l, Site c l c.post.log c.post.commitIndex c.post.currentTerm ∧
    Backed f l c.post.commitIndex c.post.currentTerm ∧ l.take c.post.commitIndex = c.post.log.take c.post.commitIndex := by
  rcases h with h | h
  all_goals
    obtain ⟨n,r,src,l,rest⟩ := h
    have b := rest.1.1.backed
    have postTake := rest.1.2.2.1
    have acc : Accepted c.pre r c.post := by repeat' first | exact rest | obtain ⟨_,rest⟩ := rest
    have pick : max c.pre.commitIndex (Shorten.Limit c r) = Shorten.Limit c r := by
      repeat' first | exact rest.1 | obtain ⟨_,rest⟩ := rest
    have lim := Safety.maxCommittableIndexUpTo_le c.post.log (min r.primaryCommit (r.prevLogIndex+r.entries.length))
    have pin : c.post.commitIndex = Shorten.Limit c r := acc.2.2.2.2.2.2.trans pick
    rw [pin,←acc.1]
    refine ⟨l,?_,b.shorten (Nat.le_trans lim (Nat.min_le_left ..)),?_⟩
    · have sh := rest.1
      have ev : c.event = .receive n (.appendEntriesRequest r) := by
        repeat' first | exact rest.1 | obtain ⟨_,rest⟩ := rest
      first
      | left; right; right; right; right; refine ⟨n,r,src,?_⟩
      | right; left; right; right; right; right; refine ⟨n,r,src,?_⟩
      exact ⟨sh,sh.1,sh.2,sh.2.1,sh.2.2,sh.2.2.1,sh.2.2.2,sh.2.2.2.1,sh.2.2.2.2,
        acc.1,acc.2,acc.2.1,acc.2.2,acc.2.2.1,acc.2.2.2,acc.2.2.2.1,acc.2.2.2.2,acc.2.2.2.2.1,
        acc.2.2.2.2.2,acc.2.2.2.2.2.1,acc.2.2.2.2.2.2,pick,ev,acc,lim,rfl,rfl,rfl⟩
    · have a := congrArg (List.take (Shorten.Limit c r)) postTake
      simpa only [List.take_take,Nat.min_eq_left (Nat.le_trans lim (Nat.min_le_right ..))] using a.symm

inductive Origin (l : List Entry) (i k : Nat) : Prop where
  | weaken (gate : ∃ q, Weaken.Gate c q) (idx : i = c.pre.commitIndex) (term : k = c.post.currentTerm)
  | any (gate : AnyGate c) (idx : i = c.pre.commitIndex)
  | later (gate : Later c) (idx : i = c.post.commitIndex) (term : k = c.post.currentTerm)

theorem origin {l l' i k} (co : Site c l l' i k) : Origin c l i k := by
  rcases co with h | h | h | h
  all_goals repeat' (change _ ∨ _ at h; rcases h with h | h)
  all_goals first
    | obtain ⟨r,_,_,_,_,_,_,idx⟩ := h
      refine Origin.any ?_ idx
      apply any_gate c
      repeat' first | exact r | exact Or.inl r | apply Or.inr
      done
    | obtain ⟨n,r,src,rest⟩ := h
      have e : Accepted c.pre r c.post := by repeat' first | exact rest.1 | obtain ⟨_,rest⟩ := rest
      have pin : i = Shorten.Limit c r := by repeat' first | exact rest.1 | obtain ⟨_,rest⟩ := rest
      have pick : max c.pre.commitIndex (Shorten.Limit c r) = Shorten.Limit c r := by
        repeat' first | exact rest.1 | obtain ⟨_,rest⟩ := rest
      have term : k = r.term := by repeat' first | exact rest | obtain ⟨_,rest⟩ := rest
      refine Origin.later ?_ (pin.trans (e.2.2.2.2.2.2.trans pick).symm) (term.trans e.1)
      unfold Later; splice rest using step_accept_backed_max_eq_or_inr
    | have idx : i = c.pre.commitIndex := by
        have r := h; repeat' first | exact r.1 | obtain ⟨_,r⟩ := r
      have term : k = c.post.currentTerm := by
        have r := h; repeat' first | exact r | obtain ⟨_,r⟩ := r
      refine Origin.weaken ?_ idx term
      first
      | have q : Weaken.Site c c.pre.log c.pre.commitIndex (c.post.currentTerm-1) c.post.currentTerm := by
          splice h using step_weaken_backed_inr
        exact (Weaken.decode c q).2.2.2.imp fun _ p => p.1
      | have q : Weaken.Site c c.pre.log c.pre.commitIndex c.pre.currentTerm c.post.currentTerm := by
          splice h using step_weaken_backed_inr
        exact (Weaken.decode c q).2.2.2.imp fun _ p => p.1
end

end ConsensusCoverage.HandReadersOther.Transfer
