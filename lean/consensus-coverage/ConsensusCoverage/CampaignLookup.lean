module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.CampaignFrontier
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ActionProfile
import all Consensus.Proofs.SafetyInvariant
meta import ConsensusCoverage.PathPremises

namespace ConsensusCoverage.CampaignLookup

open CCF Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Ledger Safety SolvedWitnesses ActionProfile
set_option maxRecDepth 8192
set_option maxHeartbeats 2500000

-- A grant for a term newer than the actor cannot depend on a prior observation
-- of that actor in the term. Thus a voter in a fresh election must be the actor.
private theorem elected_positive (s : Step) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩;
    let c := s.context;
    ElectStep s.frame s.after c.actor c.post.currentTerm c.pre.log c.pre.commitIndex →
      c.pre.currentTerm < c.post.currentTerm →
      0 < max c.pre.commitIndex (maxCommittableIndex c.pre.log) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  intro c election fresh
  obtain ⟨_, _, _, _, _, role, _⟩ := c.electStep election
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, voters, quorum, grants⟩ := election
  have rooted := c.inv.rooted _ _ c.pre_now
  obtain ⟨v, member, _⟩ := quorums_intersect Config.GENESIS_configured rooted rooted
    (k := c.pre.commitIndex) rfl (Nat.le_refl _) (Nat.le_refl _) quorum quorum
  have unseen {l} (seen : s.frame.logs.seen c.actor c.post.currentTerm l) : False :=
    (Nat.not_le_of_gt fresh) (c.inv.term_mono _ _ ⟨_,_⟩ c.pre_now seen)
  have vote : c.post.votedFor = some c.actor := by
    rcases grants v member with old | ⟨prev, eq, grant, route⟩
    · obtain ⟨_, l, seen⟩ := c.inv.grantFacts _ _ _ _ old
      exact (unseen seen).elim
    · rcases route with rfl | ⟨_,seen⟩
      · obtain ⟨_, post, _, mem, _, _, vote, _⟩ := grant
        exact c.now_post mem ▸ vote
      · exact (unseen seen).elim
  exact CampaignFrontier.positive_campaign s fresh vote (by
    rcases role with role | role <;> rw [role] <;> decide)

private theorem present {l : List Entry} {i : Nat} (pos : 0 < i) (le : i ≤ l.length)
    (missing : entryAt? l i = none) : False := by
  have idx : i - 1 < l.length := by omega
  simp [entryAt?, Nat.ne_of_gt pos, idx] at missing

local macro "backing_front " s:ident c:ident r:ident : tactic => `(tactic|
  first
  | apply elected_positive $s
    · path_premise $r
    · path_premise $r
  | obtain ⟨_, source, _⟩ := $r
    have role : ($c).post.role = .candidate := by path_premise source
    have term : ($c).post.currentTerm = ($c).pre.currentTerm + 1 := by path_premise source
    have vote : ($c).post.votedFor = some ($c).actor := by path_premise source
    exact CampaignFrontier.positive_campaign $s (Nat.lt_of_lt_of_eq (Nat.lt_succ_self _) term.symm) vote (by rw [role]; decide))

local macro "fresh_term_anchor " h:ident m:ident : tactic => `(tactic|
  (obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, stlog, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, pos, _, _, _, _, _, _, bound, log, _, ix⟩ := $h
   exact present (ix ▸ pos) (ix ▸ (log.trans stlog).symm ▸ bound) $m))

local macro "same_term_anchor " h:ident m:ident : tactic => `(tactic|
  (obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, stlog, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, pos, _, _, _, _, _, _, _, _, bound, _, _, log, _, ix⟩ := $h
   exact present (ix ▸ pos) (ix ▸ (log.trans stlog).symm ▸ bound) $m))

local macro "blocked_campaign " s:ident c:ident h:ident m:ident : tactic => `(tactic|
  (obtain ⟨_, r, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, log, _, ix⟩ := $h
   have pos : 0 < max ($c).pre.commitIndex (maxCommittableIndex ($c).pre.log) := by backing_front $s $c r
   have le := Nat.max_le.mpr ⟨($c).frontier_pre, maxCommittableIndexBounded ($c).pre.log⟩
   exact present (ix ▸ pos) (ix ▸ log.symm ▸ le) $m))

local macro "within_leader " h:ident m:ident : tactic => `(tactic|
  (obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, pos, _, _, _, _, ix⟩ := $h
   exact present (ix ▸ pos) (ix ▸ Nat.le_refl _) $m))

local macro "past_leader " h:ident m:ident : tactic => `(tactic|
  (obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, pos, _, _, _, _, _, ix⟩ := $h
   exact present (ix ▸ pos) (ix ▸ Nat.le_refl _) $m))

/-- Every term lookup actually called on an initialized step has an entry: its
    argument is a positive election anchor, a campaign frontier, or a signed prefix tip. -/
theorem lookup_false (s : Step) : label s (.step .termAt_le_of_mem_found_none) = false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  apply Bool.eq_false_iff.mpr
  intro yes
  have h := (sig_iff c _).mp ((label_true s _).mp yes)
  change step_termAt_le_of_mem_found_none _ _ c at h
  rcases h with h | h | h | h | h | h | h | h | h | h | h | h
  all_goals obtain ⟨_, _, _, h, missing, _⟩ := h
  · rcases h with h | h | h | h | h
    · fresh_term_anchor h missing
    · fresh_term_anchor h missing
    · same_term_anchor h missing
    · same_term_anchor h missing
    · blocked_campaign s c h missing
  · rcases h with h | h | h | h | h | h
    · fresh_term_anchor h missing
    · fresh_term_anchor h missing
    · same_term_anchor h missing
    · same_term_anchor h missing
    · blocked_campaign s c h missing
    · blocked_campaign s c h missing
  · rcases h with h | h | h
    · fresh_term_anchor h missing
    · same_term_anchor h missing
    · blocked_campaign s c h missing
  · rcases h with h | h | h
    · fresh_term_anchor h missing
    · same_term_anchor h missing
    · blocked_campaign s c h missing
  · rcases h with h | h | h
    · fresh_term_anchor h missing
    · same_term_anchor h missing
    · blocked_campaign s c h missing
  · rcases h with h | h | h
    · fresh_term_anchor h missing
    · same_term_anchor h missing
    · blocked_campaign s c h missing
  · rcases h with h | h | h | h
    · fresh_term_anchor h missing
    · same_term_anchor h missing
    · blocked_campaign s c h missing
    · blocked_campaign s c h missing
  · rcases h with h | h | h | h
    · fresh_term_anchor h missing
    · same_term_anchor h missing
    · blocked_campaign s c h missing
    · blocked_campaign s c h missing
  · blocked_campaign s c h missing
  · blocked_campaign s c h missing
  · blocked_campaign s c h missing
  · rcases h with h | h
    · within_leader h missing
    · past_leader h missing

end ConsensusCoverage.CampaignLookup
