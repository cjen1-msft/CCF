module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkDConditionEvents
import all ConsensusCoverage.HandReadersTrunkDConditionQueries
import all ConsensusCoverage.HandReadersTrunkDConditionHandlers
import all ConsensusCoverage.HandReadersTrunkDConditionProof
import all ConsensusCoverage.HandReadersTrunkBFactor
import all ConsensusCoverage.HandReadersOtherConditionBase
import all ConsensusCoverage.HandReadersOtherConditionOnly
import all ConsensusCoverage.HandReadersOtherPromotion
import all ConsensusCoverage.AssistEffectA
import all ConsensusCoverage.HandReadersTrunkABatch
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersTrunkD.Condition

open Consensus Model Model.Node Proofs Safety
open HandReadersOther.Condition (timeQuorum firstVote inner)
set_option maxRecDepth 8192
set_option maxHeartbeats 1000000

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private theorem timeout (b : Bool) (ev : c.event = .internal (.timeout .election)) (can : canStartElection c.pre c.actor)
    (cut : Picks b (timeQuorum c.actor c.pre)) : Answer c b := by
  unfold Answer; rw [ev]; exact decide_eq_true ⟨can,cut⟩

theorem batchPhase (b : Bool) (h : HandReadersTrunkBFactor.Tail.Batch f t c (Family.Batch.guard b)) : Answer c b := by
  obtain ⟨_,_,_,_,_,⟨xs,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,_⟩,_⟩ := h
  unfold Answer; rw [show c.event = .internal (.append xs) from ev]; rfl

private theorem admissible (b : Bool) {src m} (ev : c.event = .receive src m)
    (kind : (∃ r, m = .requestVoteResponse r) ∨ (∃ r, m = .requestPreVoteResponse r) ∨ ∃ r, m = .appendEntriesResponse r)
    (peer : ¬(True ∧ blocked c.actor c.pre src)) (pass : inner c.actor c.pre m) : Answer c b := by
  unfold Answer; rw [ev]
  rcases kind with ⟨_,rfl⟩ | ⟨_,rfl⟩ | ⟨_,rfl⟩
  all_goals apply decide_eq_true; cases b <;> first | exact .inr pass | exact fun bad=>peer ⟨trivial,bad⟩

private theorem campaigns (b : Bool) (k : NodeID → NodeState → Prop)
    (timed : canStartElection c.pre c.actor → timeQuorum c.actor c.pre →
      k c.actor (freshCandidate c.actor (firstVote c.actor c.pre)) → Picks b (timeQuorum c.actor c.pre))
    (h : HandReadersTrunkBFactor.Tail.Elect f t c k) : Answer c b := by
  rcases h with ⟨_,_,⟨_,src,r,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,peer,_,_,stable,g,_,rfl⟩,_⟩ |
    ⟨_,_,⟨_,⟨_,⟨⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,can,_,_,q,_,rfl⟩,_⟩,rfl⟩,cut⟩ |
    ⟨_,_,⟨_,⟨_,⟨src,r,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,peer,_,_,stable,g,_,_,rfl⟩,_⟩,rfl⟩,_⟩ |
    ⟨_,_,⟨_,⟨_,⟨src,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,_,can,_,rfl⟩,_⟩,rfl⟩,_⟩
  · exact admissible c b ev (.inl ⟨r,rfl⟩) peer (by simpa [inner,stable] using g)
  · exact timeout c b ev can (timed can q cut)
  · exact admissible c b ev (.inr (.inl ⟨r,rfl⟩)) peer (by simpa [inner,stable] using g)
  · unfold Answer; rw [show c.event = .receive src (.proposeRequestVoteRequest c.pre.currentTerm) from ev]
    exact decide_eq_true (fun _=>⟨rfl,can⟩)

theorem electPhase (b : Bool) (h : HandReadersTrunkBFactor.Tail.Elect f t c (Family.Elect.guard b)) : Answer c b := by
  apply campaigns c b _ _ h
  intro can quorum cut
  cases b
  · exact (cut ⟨rfl,quorum,can.2.2⟩).elim
  · exact quorum

theorem advancePhase (b : Bool) (h : HandReadersTrunkBFactor.Tail.Advance f t c (Family.Advance.guard b)) : Answer c b := by
  rcases h with h | h | promote
  · obtain ⟨_,_,⟨_,xs,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,_⟩,_⟩ := h
    unfold Answer; rw [show c.event = .internal (.append xs) from ev]; rfl
  · obtain ⟨_,_,⟨_,src,r,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,peer,_,_,stable,_,ok,_⟩,_⟩ := h
    exact admissible c b ev (.inr (.inr ⟨r,rfl⟩)) peer (by simp [inner,stable,ok])
  · let k := fun n cand=>Family.Advance.guard b n (primaryState cand)
    apply campaigns c b k
    · intro _ quorum cut
      cases b
      · have le := HandReadersOther.Condition.timedHigh c
        rcases cut with ⟨bad,_⟩ | ⟨bad,_⟩ | bad
        all_goals exact (bad le).elim
      · exact quorum
    · rcases promote with ⟨n,_,⟨cand,⟨r,_⟩,rfl⟩,cut⟩ | ⟨n,_,⟨cand,⟨r,_⟩,rfl⟩,cut⟩ |
        ⟨n,_,⟨cand,⟨r,_⟩,rfl⟩,cut⟩ | ⟨n,_,⟨cand,⟨r,_⟩,rfl⟩,cut⟩
      all_goals first
        | exact Or.inl ⟨n,cand,r,cut⟩
        | exact Or.inr (Or.inl ⟨n,cand,r,cut⟩)
        | exact Or.inr (Or.inr (Or.inl ⟨n,cand,r,cut⟩))
        | exact Or.inr (Or.inr (Or.inr ⟨n,cand,r,cut⟩))
end

end ConsensusCoverage.HandReadersTrunkD.Condition
