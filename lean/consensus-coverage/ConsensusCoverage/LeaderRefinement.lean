module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.LeaderCoverage
import all ConsensusCoverage.ActionContext
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.LeaderCoverage
import all ConsensusCoverage.LeaderEffect
import all ConsensusCoverage.PinnedClasses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.LeaderRefinement

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open ActionProfile

private theorem has_entry [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)
    (h : PinnedClasses.sig c .terms_now_after_inl) : ∃ e, e ∈ c.post.log := by
  rcases h with h | h <;> obtain ⟨_, rfl, _, _, _, _, e, mem, ⟨_, rfl⟩, _⟩ := h <;> exact ⟨e, mem⟩

private theorem terms_of_change [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)
    (changed : ¬ Now f c.actor c.post) {e} (mem : e ∈ c.post.log) :
    PinnedClasses.sig c .terms_now_after_inl :=
  .inl ⟨c, rfl, ⟨c, rfl, c.actor, c.post, c.post_now, changed, rfl⟩,
    c.actor, c.post, c.post_now, e, mem, ⟨rfl, rfl⟩, rfl, rfl⟩

private def target : Model.Action → NodeID
  | .local n _ => n
  | .deliver e => e.target

private theorem actor (s : Step) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    s.context.actor = target s.act := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have h := (s.context_eq s.context).mpr rfl
  rw [← h]
  change s.context.tr.actor = target (ActionContext.encode s.context.tr.actor s.context.tr.event)
  cases s.context.tr.event <;> rfl

private abbrev config : CCF.Finset NodeID := {0, 1}
private instance : Config.InitialConfiguration := ⟨config⟩
private def setup : FrontierRows.Run := ⟨config, [0,1,2], []⟩
private abbrev s0 := FrontierRows.initial setup
private abbrev system := transitionSystem config [0,1,2]

private noncomputable def first (a : Model.Action) (ok : (system.step s0 a).isSome) : Step :=
  ⟨config, [0,1,2], s0, [], a, _, .initial (FrontierRows.initialized setup (by unfold FrontierRows.Run.valid; decide)),
    (Option.some_get ok).symm⟩

private noncomputable def down := first (.local 0 (.timeout .checkQuorum)) (by decide +kernel)
private noncomputable def backup := first (.local 2 (.initAsBackup [])) (by decide +kernel)

private theorem down_yes : label down (.step .terms_now_after_inl) = true := by
  apply (label_true ..).mpr
  let c := down.context
  have who : c.actor = 0 := actor down
  have now := c.post_now
  change (c.actor, c.post) ∈ down.after.nodes at now
  rw [who] at now
  let post := down.after.nodes[0]'(by decide +kernel) |>.2
  have eq : c.post = post := state_unique c.keys_after now (List.mem_cons_self ..)
  have pre := c.pre_now
  change (c.actor, c.pre) ∈ s0.nodes at pre
  rw [who] at pre
  have preEq : c.pre = initialNodeState config 0 := state_unique c.inv.distinct pre (List.mem_cons_self ..)
  apply terms_of_change c (e := post.log[0]'(by decide +kernel))
  case changed =>
    intro old
    have same := congrArg NodeState.role (c.now_pre old)
    rw [eq, preEq] at same
    contradiction
  case mem => rw [eq]; apply List.getElem_mem

private theorem backup_no : label backup (.step .terms_now_after_inl) = false := by
  apply Bool.eq_false_iff.mpr
  intro yes
  let c := backup.context
  obtain ⟨e, mem⟩ := has_entry c ((label_true ..).mp yes)
  have who : c.actor = 2 := actor backup
  have now := c.post_now
  change (c.actor, c.post) ∈ backup.after.nodes at now
  rw [who] at now
  let post := backup.after.nodes[2]'(by decide +kernel) |>.2
  have eq : c.post = post := state_unique c.keys_after now
    (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (List.mem_cons_self ..)))
  rw [eq] at mem
  exact List.not_mem_nil mem

/-- In the same three-node initial state, stepping down the primary and initializing an
empty backup agree on all 27 leader-projection answers, but not on the terms branch. -/
public theorem strict : ∃ s t : Step, LeaderCoverage.MultiNode s.nodes ∧ LeaderCoverage.MultiNode t.nodes ∧
    ActionFrontier.project (label s) = ActionFrontier.project (label t) ∧ label s ≠ label t := by
  refine ⟨down, backup, ⟨0, by decide, 1, by decide, by decide⟩,
    ⟨0, by decide, 1, by decide, by decide⟩, ?_, ?_⟩
  · rw [ActionFrontier.project_eq, ActionFrontier.project_eq]
    decide +kernel
  · intro same
    exact Bool.noConfusion (down_yes.symm.trans ((congrFun same _).trans backup_no))

private theorem split_bound {keys : List LeaderWitnesses.Key} (distinct : keys.Nodup)
    {rows : List FullProfile.Profile} (covered : ∀ k ∈ keys, ∃ p ∈ rows, ActionFrontier.project p = k)
    {p q : FullProfile.Profile} (hp : p ∈ rows) (hq : q ∈ rows) (ne : p ≠ q)
    (same : ActionFrontier.project p = ActionFrontier.project q) : keys.length < rows.length := by
  classical
  have sub : keys ⊆ (rows.erase p).map ActionFrontier.project := by
    intro k hk
    obtain ⟨r, hr, rfl⟩ := covered k hk
    by_cases eq : r = p
    · subst r
      exact List.mem_map.mpr ⟨q, (List.mem_erase_of_ne ne.symm).mpr hq, same.symm⟩
    · exact List.mem_map.mpr ⟨r, (List.mem_erase_of_ne eq).mpr hr, rfl⟩
  have h := distinct.length_le_of_subset sub
  rw [List.length_map, List.length_erase_of_mem hp] at h
  have pos := List.length_pos_of_mem hp
  omega

public theorem multi_lower_bound {rows : List FullProfile.Profile}
    (complete : ∀ s : Step, LeaderCoverage.MultiNode s.nodes → label s ∈ rows) : 14 ≤ rows.length := by
  obtain ⟨s, t, ms, mt, same, ne⟩ := strict
  have h := split_bound LeaderCoverage.multi_count.1 (rows := rows) (fun k hk => by
    obtain ⟨u, mu, eq⟩ := (LeaderCoverage.multi_exact k).mp hk
    exact ⟨_, complete u mu, eq⟩) (complete s ms) (complete t mt) ne same
  simpa only [LeaderCoverage.multi_count.2, Nat.lt_iff_add_one_le] using h

public theorem full_lower_bound {rows : List FullProfile.Profile}
    (complete : ∀ s : Step, label s ∈ rows) : 15 ≤ rows.length := by
  obtain ⟨s, t, _, _, same, ne⟩ := strict
  have h := split_bound LeaderWitnesses.table_count.1 (rows := rows) (fun k hk => by
    obtain ⟨cfg, ns, x, y, past, a, run, ran, rfl⟩ := LeaderWitnesses.table_occurs hk
    let u : Step := ⟨cfg, ns, x, past, a, y, run, ran⟩
    exact ⟨_, complete u, ActionFrontier.project_eq u⟩) (complete s) (complete t) ne same
  simpa only [LeaderWitnesses.table_count.2, Nat.lt_iff_add_one_le] using h

end ConsensusCoverage.LeaderRefinement
