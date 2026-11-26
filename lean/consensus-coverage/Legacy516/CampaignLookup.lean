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

local macro "election_anchor " l:ident i:ident h:ident m:ident : tactic => `(tactic|
  (obtain ⟨_, _, log, commit, _, st, path⟩ := $h
   have stlog : st.log = log := by path_premise path
   have actual : $l = st.log := by path_premise path
   have index : $i = max commit (maxCommittableIndex log) := by path_premise path
   have pos : 0 < max commit (maxCommittableIndex log) := by path_premise path
   have bound : max commit (maxCommittableIndex log) ≤ log.length := by path_premise path
   exact present (index ▸ pos) (index ▸ (actual.trans stlog).symm ▸ bound) $m))

local macro "blocked_campaign " s:ident c:ident l:ident i:ident h:ident m:ident : tactic => `(tactic|
  (obtain ⟨_, r, path⟩ := $h
   have log : $l = ($c).pre.log := by path_premise path
   have ix : $i = max ($c).pre.commitIndex (maxCommittableIndex ($c).pre.log) := by path_premise path
   have pos : 0 < max ($c).pre.commitIndex (maxCommittableIndex ($c).pre.log) := by backing_front $s $c r
   have le := Nat.max_le.mpr ⟨($c).frontier_pre, maxCommittableIndexBounded ($c).pre.log⟩
   exact present (ix ▸ pos) (ix ▸ log.symm ▸ le) $m))

local macro "accepted_tip " l:ident i:ident h:ident m:ident : tactic => `(tactic|
  (have pos : 0 < ($l).length := by path_premise $h
   have ix : $i = ($l).length := by path_premise $h
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
  all_goals obtain ⟨log, _, index, h, missing, _⟩ := h
  · rcases h with h | h | h | h | h
    · election_anchor log index h missing
    · election_anchor log index h missing
    · election_anchor log index h missing
    · election_anchor log index h missing
    · blocked_campaign s c log index h missing
  · rcases h with h | h | h | h | h | h
    · election_anchor log index h missing
    · election_anchor log index h missing
    · election_anchor log index h missing
    · election_anchor log index h missing
    · blocked_campaign s c log index h missing
    · blocked_campaign s c log index h missing
  · rcases h with h | h | h
    · election_anchor log index h missing
    · election_anchor log index h missing
    · blocked_campaign s c log index h missing
  · rcases h with h | h | h
    · election_anchor log index h missing
    · election_anchor log index h missing
    · blocked_campaign s c log index h missing
  · rcases h with h | h | h
    · election_anchor log index h missing
    · election_anchor log index h missing
    · blocked_campaign s c log index h missing
  · rcases h with h | h | h
    · election_anchor log index h missing
    · election_anchor log index h missing
    · blocked_campaign s c log index h missing
  · rcases h with h | h | h | h
    · election_anchor log index h missing
    · election_anchor log index h missing
    · blocked_campaign s c log index h missing
    · blocked_campaign s c log index h missing
  · rcases h with h | h | h | h
    · election_anchor log index h missing
    · election_anchor log index h missing
    · blocked_campaign s c log index h missing
    · blocked_campaign s c log index h missing
  · blocked_campaign s c log index h missing
  · blocked_campaign s c log index h missing
  · blocked_campaign s c log index h missing
  · rcases h with h | h
    · accepted_tip log index h missing
    · accepted_tip log index h missing

-- A positive committed index is already signed, so the signed index by itself is positive.
private theorem signed_campaign (s : Step) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩;
    s.context.pre.currentTerm < s.context.post.currentTerm →
      s.context.post.votedFor = some s.context.actor → s.context.post.role ≠ .follower →
      0 < maxCommittableIndex s.context.pre.log := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  intro fresh vote role
  let c := s.context
  have front := CampaignFrontier.positive_campaign s fresh vote role
  have le : c.pre.commitIndex ≤ maxCommittableIndex c.pre.log := by
    rcases Nat.eq_zero_or_pos c.pre.commitIndex with zero | pos
    · rw [zero]; exact Nat.zero_le _
    · exact signatureIndex_le_maxCommittableIndex ((c.inv.frontier _ _ c.pre_now).2 pos)
  exact (Nat.max_eq_right le) ▸ front

local macro "grant_zero " h:ident : tactic => `(tactic|
  (obtain ⟨_, _, _, _, _, log, _, path⟩ := $h
   have sig : isSignatureAt log 0 = true := by path_premise path
   exact (Nat.lt_irrefl 0) (signature_pos sig)))

local macro "core_zero " h:ident : tactic => `(tactic|
  (obtain ⟨_, _, _, _, _, commit, _, _, _, log, _, path⟩ := $h
   have pos : 0 < max commit (maxCommittableIndex log) := by path_premise path
   have zero : 0 = max commit (maxCommittableIndex log) := by path_premise path
   exact (Nat.ne_of_gt pos) zero.symm))

local macro "own_zero " s:ident c:ident h:ident : tactic => `(tactic|
  (obtain ⟨st, own, _, _, _, zero, _⟩ := $h
   obtain ⟨campaign, _, vote, stateEq⟩ := own
   have actual : maxCommittableIndex ($c).pre.log = 0 := by rw [← stateEq]; exact zero.symm
   obtain ⟨candidate, origin, path⟩ := campaign
   have fresh : candidate.currentTerm = ($c).pre.currentTerm + 1 := by path_premise path
   have term : ($c).post.currentTerm = candidate.currentTerm := by path_premise path
   have role : ($c).post.role ≠ .follower := by
     first
     | have candidate : ($c).post.role = .candidate := by path_premise origin
       rw [candidate]; decide
     | have winner : ($c).post.role = .primary ∨ ($c).post.role = .none := by path_premise origin
       rcases winner with win | win <;> rw [win] <;> decide
   exact (Nat.ne_of_gt (signed_campaign $s
     (Nat.lt_of_lt_of_eq (Nat.lt_succ_self _) (term.trans fresh).symm) vote role)) actual))

/-- Each lower index comes from a voter signature, a positive comparison anchor,
    or the signed frontier of an actual fresh self-vote. -/
theorem mono_false (s : Step) : label s (.step .termAt_mono_eq_zero_or_pos_inl) = false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  apply Bool.eq_false_iff.mpr
  intro yes
  have h := (sig_iff c _).mp ((label_true s _).mp yes)
  change step_termAt_mono_eq_zero_or_pos_inl _ _ c at h
  rcases h with h | h | h | h | h | h | h | h | h | h | h | h | h | h | h
  all_goals obtain ⟨_, _, h, _⟩ := h
  · grant_zero h
  · rcases h with h | h
    · grant_zero h
    · core_zero h
  · rcases h with h | h | h | h
    · grant_zero h
    · core_zero h
    · core_zero h
    · own_zero s c h
  · rcases h with h | h
    · grant_zero h
    · core_zero h
  · rcases h with h | h | h
    · grant_zero h
    · core_zero h
    · own_zero s c h
  · rcases h with h | h | h
    · grant_zero h
    · core_zero h
    · own_zero s c h
  · rcases h with h | h | h
    · grant_zero h
    · core_zero h
    · own_zero s c h
  · rcases h with h | h | h
    · grant_zero h
    · core_zero h
    · own_zero s c h
  · rcases h with h | h | h
    · grant_zero h
    · core_zero h
    · own_zero s c h
  · grant_zero h
  · grant_zero h
  · rcases h with h | h
    · grant_zero h
    · own_zero s c h
  · own_zero s c h
  · own_zero s c h
  · own_zero s c h

end ConsensusCoverage.CampaignLookup
