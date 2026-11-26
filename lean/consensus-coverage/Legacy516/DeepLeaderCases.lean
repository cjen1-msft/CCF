module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.GuardedDomain
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.DeepLeaderCases

open Consensus Consensus.Proofs Consensus.Model Consensus.Model.Node Safety SolvedWitnesses

set_option maxRecDepth 8192

variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)
  (old : c.pre.role ≠ .primary) (primary : c.post.role = .primary) (log : c.pre.log ≠ [])

include old primary in
private theorem won : Wins c.actor c.pre c.event c.post :=
  (Summary.leader c.sum primary).resolve_left (fun prior => old prior.1)

include old in
private theorem changed : ¬(Now f c.actor c.post ∧ c.post.role = .primary) := by
  rintro ⟨was, role⟩
  exact old ((c.now_pre was) ▸ role)

-- The generated conjunctions retain the same intermediate facts several
-- times. Supply a single winning candidate, then reassemble its facts.
local macro "leader_case " c:ident old:ident primary:ident commit:ident : tactic => `(tactic| {
  have now := Ctx.post_now $c
  have wins := won $c $old $primary
  have root : (reach% SolvedWitnesses.step_leader_logs_commit_pos[0]) _ _ $c $c _ _ :=
    ⟨now, $primary, changed $c $old, rfl⟩
  obtain ⟨candidate, facts⟩ := Wins.facts wins
  obtain ⟨campaign, quorum, postLog, term, vote, matchEq, role, le⟩ := facts
  obtain ⟨candRole, candLog, candCommit, active⟩ := campaign
  have three := Ctx.campaign_three $c (candidate := candidate) ⟨candRole, candLog, candCommit, active⟩
  have guard := $commit
  rw [← candCommit] at guard
  first
  | refine ⟨root, now, $primary, now, wins, candidate, ?_⟩
  | refine Or.inl ⟨⟨root, now, $primary, now, wins, now, $primary, rfl⟩, candidate, ?_⟩
  have bound := three.1
  have cases_ := three.2
  repeat' first | assumption | apply And.intro })

include old primary log in
theorem leaderPositive (commit : 0 < c.pre.commitIndex) : step_leader_logs_commit_pos f t c := by
  leader_case c old primary commit

include old primary log in
theorem leaderZero (commit : ¬0 < c.pre.commitIndex) : step_leader_logs_commit_neg f t c := by
  leader_case c old primary commit

include old primary in
theorem electedPositive (commit : 0 < c.pre.commitIndex) : step_wins_elect_committed_pos f t c := by
  leader_case c old primary commit

include old primary in
theorem electedZero (commit : ¬0 < c.pre.commitIndex) : step_wins_elect_committed_neg f t c := by
  leader_case c old primary commit

-- Only the actor view is evaluated. Its compatibility theorem, not
-- evaluation of the noncomputable step context, transports the guard.
def guardAt (s : ActionProfile.Step) (positive : Bool) : Bool :=
  (GuardedDomain.ofAction s.cfg s.before s.after s.past s.act).any fun v =>
    decide (v.pre.role ≠ .primary ∧ v.post.role = .primary ∧ v.pre.log ≠ [] ∧
      decide (0 < v.pre.commitIndex) = positive)

omit [Config.InitialConfiguration] in
theorem ofGuard (s : ActionProfile.Step) (positive : Bool) (passed : guardAt s positive = true) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    s.context.pre.role ≠ .primary ∧ s.context.post.role = .primary ∧ s.context.pre.log ≠ [] ∧
      decide (0 < s.context.pre.commitIndex) = positive := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨v, made, ok⟩ := GuardedDomain.ofAction_matches s
  simpa only [guardAt, made, Option.any_some, decide_eq_true_eq,
    GuardedDomain.View.pre_eq ok, GuardedDomain.View.post_eq ok] using passed

end ConsensusCoverage.DeepLeaderCases
