module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.SolvedWitnesses
public import ConsensusCoverage.ActionProfile
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.CensusBallots

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open SolvedWitnesses ActionProfile

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192

private theorem never_reelect [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)
    {n other term commit : Nat} {log : List Entry} (e : ElectStep f t n term log commit)
    (old : Led f other term) : False := by
  obtain rfl := c.new_old_unique e old
  obtain ⟨rfl, _, _, campaign, _⟩ := c.electStep e
  rcases c.inv.led_cur _ _ _ c.pre_now old with lt | ⟨eq, role⟩ <;>
    rcases campaign with fresh | ⟨kept, candidate⟩ <;> first | omega | exact role candidate

private theorem old_vote [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)
    {v term n k : Nat} {st : NodeState}
    (stamp : VoteFacts.Stamp.mk v term (some n) ∈ f.votes) (now : (v, st) ∈ t.nodes)
    (current : st.currentTerm = k) (lt : k < term) : False := by
  have bound := c.ballots.bounds _ (VoteFacts.mem_advance.mpr (.inr stamp)) st now
  change term ≤ st.currentTerm at bound
  omega

private theorem new_vote [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)
    {v term n k : Nat} {st : NodeState}
    (stamp : VoteFacts.Stamp.mk v term (some n) ∈ (f.advance t).votes) (now : (v, st) ∈ t.nodes)
    (current : st.currentTerm = k) (lt : k < term) : False := by
  have bound := c.ballots.bounds _ stamp st now
  change term ≤ st.currentTerm at bound
  omega

private theorem blocked [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t) :
    ¬ (reach_132 f t c c ∨ reach_133 f t c c ∨ reach_134 f t c c ∨ reach_135 f t c c ∨
      reach_136 f t c c ∨ reach_137 f t c c ∨ reach_138 f t c c ∨ reach_139 f t c c ∨
      reach_140 f t c c ∨ reach_141 f t c c ∨ reach_142 f t c c ∨ reach_143 f t c c) := by
  have failedElection := @never_reelect _ _ _ c
  have pastVote := @old_vote _ _ _ c
  have nextVote := @new_vote _ _ _ c
  intro h
  rcases h with h|h|h|h|h|h|h|h|h|h|h|h
  all_goals
    first
    | unfold reach_132 at h | unfold reach_133 at h | unfold reach_134 at h
    | unfold reach_135 at h | unfold reach_136 at h | unfold reach_137 at h
    | unfold reach_138 at h | unfold reach_139 at h | unfold reach_140 at h
    | unfold reach_141 at h | unfold reach_142 at h | unfold reach_143 at h
    grind only

/-- Reaching either side of this split would require a voter observed below
the term of its own vote, or a new election in a term that already had a leader. -/
public theorem label_false (s : Step) {b : Classes.StepBranch}
    (which : b = .ballot_step_mem_after_inl ∨ b = .ballot_step_mem_after_inr) :
    label s (.step b) = false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  apply Bool.eq_false_iff.mpr
  intro yes
  have arm := (SolvedWitnesses.sig_iff s.context b).mp ((label_true s _).mp yes)
  apply blocked s.context
  rcases which with rfl | rfl
  all_goals
    first
    | change step_ballot_step_mem_after_inl _ _ _ at arm
    | change step_ballot_step_mem_after_inr _ _ _ at arm
    first | unfold step_ballot_step_mem_after_inl at arm | unfold step_ballot_step_mem_after_inr at arm
    simp only [reach_144, reach_145, reach_146, reach_147, reach_148, reach_149,
      reach_150, reach_151, reach_152, reach_153, reach_154, reach_155] at arm
    grind only

public def answer (b : Classes.StepBranch) : Option Bool :=
  if b = .ballot_step_mem_after_inl ∨ b = .ballot_step_mem_after_inr then some false else none

public theorem answer_correct (s : Step) {b : Classes.StepBranch} {v : Bool}
    (read : answer b = some v) : label s (.step b) = v := by
  unfold answer at read
  split at read
  · obtain rfl := Option.some.inj read
    exact label_false s ‹_ ∨ _›
  · cases read

/-- Adding these two newly total coordinates cannot split any wider-key
class on actual initialized steps, regardless of the old key's shape. -/
public theorem same_projection {α : Type} (key : Step → α) (s t : Step) :
    (key s, label s (.step .ballot_step_mem_after_inl), label s (.step .ballot_step_mem_after_inr)) =
      (key t, label t (.step .ballot_step_mem_after_inl), label t (.step .ballot_step_mem_after_inr)) ↔
      key s = key t := by
  simp only [label_false s (.inl rfl), label_false s (.inr rfl),
    label_false t (.inl rfl), label_false t (.inr rfl), Prod.mk.injEq, and_true]

end ConsensusCoverage.CensusBallots
