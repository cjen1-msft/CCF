module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

meta import ConsensusCoverage.ReachPath
public import ConsensusCoverage.LeaderEffect
public import ConsensusCoverage.PinnedClasses
import all ConsensusCoverage.LeaderEffect
import all ConsensusCoverage.PairQuestions
import all ConsensusCoverage.PinnedClasses
import all Consensus.Proofs.SafetyInvariant

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

/-! The three `leader_led` answers for the supplied step context. -/

namespace ConsensusCoverage.PinnedLeader

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

private theorem changedActor [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) :
    LeaderEffect.changedPrimary f.current t = true ↔
      c.post.role = .primary ∧ ¬ Now f c.actor c.post := by
  rw [LeaderEffect.changedPrimary_mem c]
  refine ⟨?_, fun ⟨primary, fresh⟩ => ⟨c.actor, c.post, c.post_now, primary, fresh⟩⟩
  rintro ⟨node, post, now, primary, fresh⟩
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, old⟩
  · exact ⟨primary, fresh⟩
  · exact (fresh old).elim

/-- Common generated path into the actor branch of `leader_led`. -/
private theorem leaderReach [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) :
    (reach% PinnedClasses.step_leader_led_now_after_inl[0]) f t c c c.actor c.post ↔
      c.post.role = .primary ∧ ¬ Now f c.actor c.post := by
  constructor
  · rintro ⟨_, rfl, _, _, _, primary, fresh, _, rfl, rfl⟩
    exact ⟨primary, fun old => fresh ⟨old, primary⟩⟩
  · rintro ⟨primary, fresh⟩
    exact ⟨c, rfl, c.actor, c.post, c.post_now, primary, fun old => fresh old.1, rfl, rfl, rfl⟩

/-- The pinned actor branch tests for a changed primary in the snapshots. -/
public theorem changedPrimary_iff [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) :
    PinnedClasses.sig c .leader_led_now_after_inl ↔
      LeaderEffect.changedPrimary (FullProfile.current f) t = true := by
  change PinnedClasses.step_leader_led_now_after_inl f t c ↔
    LeaderEffect.changedPrimary f.current t = true
  rw [changedActor c]
  constructor
  · rintro ⟨w, pin, _, _, reach, ⟨rfl, rfl⟩, _⟩
    subst w
    exact (leaderReach c).mp reach
  · intro h
    exact ⟨c, rfl, c.actor, c.post, (leaderReach c).mpr h, ⟨rfl, rfl⟩,
      rfl, rfl, c.post_now, h.1⟩

private theorem wins_newPrimary [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) (primary : c.post.role = .primary) (wins : Wins c.actor c.pre c.event c.post) :
    PairQuestions.newPrimary f.current t = true := by
  refine (PairQuestions.newPrimary_iff _ _).mpr ⟨c.actor, c.post, c.post_now, primary, ?_⟩
  rintro ⟨pre, old, role, term⟩
  obtain rfl := c.now_pre old
  obtain ⟨_, _, _, termCase, _, _⟩ := c.electStep (c.wins_elect wins)
  rcases termCase with lt | ⟨_, cand⟩
  · omega
  · simp [role] at cand

/-- The pinned election branch tests for a primary not seen in the same term before. -/
public theorem won_iff [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) :
    PinnedClasses.sig c .leader_led_leader_inr ↔
      PairQuestions.answer (FullProfile.current f) t .wonPrimary = true := by
  change PinnedClasses.step_leader_led_leader_inr f t c ↔ PairQuestions.newPrimary f.current t = true
  constructor
  · rintro ⟨w, pin, _, _, _, _, _, _, _, primary, _, wins, _⟩
    subst w
    exact wins_newPrimary c primary wins
  · intro won
    obtain ⟨node, post, now, primary, notOld⟩ := (PairQuestions.newPrimary_iff _ _).mp won
    rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, old⟩
    · have fresh : ¬ Now f c.actor c.post := fun old => notOld ⟨c.post, old, primary, rfl⟩
      rcases Summary.leader c.sum primary with ⟨preRole, term⟩ | wins
      · exact (notOld ⟨c.pre, c.pre_now, preRole, term.symm⟩).elim
      · exact ⟨c, rfl, c.actor, c.post, (leaderReach c).mpr ⟨primary, fresh⟩, ⟨rfl, rfl⟩,
          rfl, rfl, now, primary, now, wins, now, primary⟩
    · exact (notOld ⟨post, old, primary, rfl⟩).elim

/-- The pinned incumbent branch tests for a changed primary with no election. -/
public theorem changedIncumbent_iff [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) :
    PinnedClasses.sig c .leader_led_leader_inl ↔
      LeaderEffect.changedIncumbent (FullProfile.current f) t = true := by
  change PinnedClasses.step_leader_led_leader_inl f t c ↔
    (LeaderEffect.changedPrimary f.current t && !PairQuestions.newPrimary f.current t) = true
  rw [Bool.and_eq_true, Bool.not_eq_true', Bool.eq_false_iff, changedActor c]
  constructor
  · rintro ⟨w, pin, _, _, reach, ⟨rfl, rfl⟩, _, _, _, _, _, ⟨preRole, term⟩, _⟩
    subst w
    refine ⟨(leaderReach c).mp reach, ?_⟩
    intro won
    obtain ⟨node, post, now, primary, notOld⟩ := (PairQuestions.newPrimary_iff _ _).mp won
    rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, old⟩
    · exact notOld ⟨c.pre, c.pre_now, preRole, term.symm⟩
    · exact notOld ⟨post, old, primary, rfl⟩
  · rintro ⟨⟨primary, fresh⟩, notWon⟩
    rcases Summary.leader c.sum primary with ⟨preRole, term⟩ | wins
    · exact ⟨c, rfl, c.actor, c.post, (leaderReach c).mpr ⟨primary, fresh⟩, ⟨rfl, rfl⟩,
        rfl, rfl, c.post_now, primary, c.post_now, ⟨preRole, term⟩,
        preRole, term, c.post_now, primary⟩
    · exact (notWon (wins_newPrimary c primary wins)).elim

end ConsensusCoverage.PinnedLeader
