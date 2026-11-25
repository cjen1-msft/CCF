module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.CensusQueueStep
import all ConsensusCoverage.DeepLeaderCases
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.GuardedDomain
import all Consensus.Proofs.SafetyInvariant
public meta import Lean

namespace ConsensusCoverage.CensusQueueElection

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open ReadersAtoms GuardedDomain SolvedWitnesses

set_option maxRecDepth 8192

-- A proof-level witness (Wins) gives us the intermediate candidate, which
-- need not occur as an endpoint in the schedule. The terminal guard is
-- supplied by evaluation of the actual pre-state, not by this rule.
local macro "winning_commit " c:ident ok:ident changed:ident won:ident guard:ident : tactic =>
  `(tactic| {
    have now := Ctx.post_now $c
    have fresh : ¬Now _ (Ctx.actor $c) (Ctx.post $c) := fun old =>
      Bool.noConfusion (Eq.trans (Eq.symm $changed) ((View.old_post (And.left $ok)).mp old))
    have root : (reach% step_commit_backed_eq_zero_or_pos_inl[0]) _ _ $c $c _ _ := ⟨now, fresh, rfl⟩
    have elect := Ctx.wins_elect $c $won
    have winning := (Ctx.electStep $c elect).2.2.2.2.2.2.1
    obtain ⟨candidate, facts⟩ := $won
    obtain ⟨campaign, quorum, advance⟩ := facts
    have ⟨role, log, commit, alternatives⟩ := campaign
    refine Or.inl ?_
    refine ⟨root, now, now, ⟨candidate, campaign, quorum, advance⟩, rfl, candidate, ?_⟩
    repeat' first | assumption | exact $guard | apply And.intro })

section
variable [Config.InitialConfiguration] {f : Frame} {after : Model.State} (c : Ctx f after)
  {x : XView} (ok : x.Matches c) (changed : x.base.changed = true)
  (won : Wins c.actor c.pre c.event c.post)

include ok changed won

theorem zero (h : c.pre.commitIndex = 0) : step_commit_backed_eq_zero_or_pos_inl f after c := by
  winning_commit c ok changed won h

theorem positive (h : c.pre.commitIndex > 0) : step_commit_backed_eq_zero_or_pos_inr f after c := by
  winning_commit c ok changed won h
end

private theorem wins (s : ActionProfile.Step)
    (old : (CensusQueueStep.view s).base.pre.role ≠ .primary)
    (post : (CensusQueueStep.view s).base.post.role = .primary) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    let c := CensusQueueStep.context s
    Wins c.actor c.pre c.event c.post := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  exact DeepLeaderCases.won (CensusQueueStep.context s) old post

open Lean Elab Tactic Meta in
elab "queue_win " step:term : tactic => withMainContext do
  let target ← (← getMainGoal).getType
  let b := target.getArg! 1 |>.appArg! |>.appArg!
  let some n := b.constName? | throwError "a concrete branch is required"
  let name := n.getString!
  let lemma ← match name with
    | "commit_backed_eq_zero_or_pos_inl" => pure ``zero
    | "commit_backed_eq_zero_or_pos_inr" => pure ``positive
    | _ => throwError "not a winning commit split"
  let r := mkIdent lemma
  evalTactic (← `(tactic| (
    refine CensusQueueStep.ofFormula $step _ ?_
    exact @$(r):ident ⟨ActionProfile.Step.cfg $step⟩ _ _ (CensusQueueStep.context $step) _
      (CensusQueueStep.reflected $step) (by decide +kernel)
      (wins $step (by decide +kernel) (by decide +kernel)) (by decide +kernel))))

end ConsensusCoverage.CensusQueueElection
