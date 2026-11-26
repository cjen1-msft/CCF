module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkDConditionHandlers
import all ConsensusCoverage.HandReadersTrunkDConditionQueries
import all ConsensusCoverage.HandReadersTrunkDConditionProof
import all ConsensusCoverage.HandReadersTrunkBFactor
import all ConsensusCoverage.HandReadersOtherConditionBase
import all ConsensusCoverage.AssistReplyA
import all ConsensusCoverage.AssistConflictA
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersTrunkD.Condition

open Consensus Model Model.Node Proofs Safety
open HandReadersOther.Condition (inner timeQuorum reject)
open AssistReplyA (observed)
set_option maxRecDepth 8192
set_option maxHeartbeats 1000000
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private instance (b n s src msg) : Decidable (remote b n s src msg) := by cases b <;> unfold remote <;> dsimp <;> infer_instance
private instance (b z r) : Decidable (req b z r) := by cases b <;> unfold req <;> infer_instance
private instance (b : Bool) (p : Prop) [Decidable p] : Decidable (Picks b p) := by cases b <;> unfold Picks <;> infer_instance

def test (b : Bool) (n : NodeID) (s : NodeState) (ev : Event) (_ : NodeState) := match ev with
  | .internal (.append _) => true
  | .internal (.timeout .election) => decide (canStartElection s n ∧ Picks b (timeQuorum n s))
  | .receive src m@(.appendEntriesResponse _) | .receive src m@(.requestVoteResponse _) |
      .receive src m@(.requestPreVoteResponse _) => decide (remote b n s src m)
  | .receive _ (.proposeRequestVoteRequest k) => decide (b = true → k = s.currentTerm ∧ canStartElection s n)
  | .receive _ (.appendEntriesRequest r) => decide (req b (observed s r) r)
  | _ => false

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

abbrev Answer (b : Bool) := test b c.actor c.pre c.event c.post = true
abbrev EventCases (b : Bool) :=
  (∃ xs, c.event = .internal (.append xs)) ∨
  (c.event = .internal (.timeout .election) ∧ canStartElection c.pre c.actor ∧ Picks b (timeQuorum c.actor c.pre)) ∨
  (∃ n r, c.event = .receive n (.appendEntriesResponse r) ∧ remote b c.actor c.pre n (.appendEntriesResponse r)) ∨
  (∃ n r, c.event = .receive n (.requestVoteResponse r) ∧ remote b c.actor c.pre n (.requestVoteResponse r)) ∨
  (∃ n r, c.event = .receive n (.requestPreVoteResponse r) ∧ remote b c.actor c.pre n (.requestPreVoteResponse r)) ∨
  (∃ n k, c.event = .receive n (.proposeRequestVoteRequest k) ∧ (b = true → k = c.pre.currentTerm ∧ canStartElection c.pre c.actor)) ∨
  (∃ n r, c.event = .receive n (.appendEntriesRequest r) ∧ req b (observed c.pre r) r)

theorem events (b : Bool) : EventCases c b ↔ Answer c b := by
  unfold EventCases Answer
  cases c.event with
  | internal i =>
    cases i <;> simp [test]
    case timeout k => cases k <;> cases b <;> simp [Picks,timeQuorum,canStartElection,hasQuorum] <;> grind only
  | receive n m =>
    cases m <;> cases b <;> simp [test,remote,req,and_assoc]
    simp [reject,AssistConflictA.Bad,appendEntryMatchesLog]
    grind only

theorem timePhase (b : Bool) : HandReadersTrunkBFactor.Tail.Timeout f t c (Family.Timeout.guard b) ↔
    c.event = .internal (.timeout .election) ∧ canStartElection c.pre c.actor ∧ Picks b (timeQuorum c.actor c.pre) := by
  constructor
  · rintro ⟨_,_,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,g⟩
    exact ⟨ev,(timeoutGuard ..).mp g⟩
  · rintro ⟨ev,h⟩
    exact ⟨_,_,⟨c.event,⟨rfl,rfl,rfl⟩,_,ev,ev,rfl⟩,(timeoutGuard ..).mpr h⟩

local macro "at_receive " cc:term:arg eq:term : tactic => `(tactic|
  (constructor
   · rintro ⟨_,_,src,r,⟨_,⟨ha,hp,he⟩,_,ev,_,hm⟩,g⟩; subst_vars; exact ⟨src,r,ev,($eq).mp g⟩
   · rintro ⟨src,r,ev,g⟩; exact ⟨_,_,src,r,⟨($cc).event,⟨rfl,rfl,rfl⟩,_,ev,ev,rfl⟩,($eq).mpr g⟩))

theorem ackPhase (b : Bool) : HandReadersTrunkBFactor.Tail.Ack f t c (Family.Ack.guard b) ↔
    ∃ n r, c.event = .receive n (.appendEntriesResponse r) ∧ remote b c.actor c.pre n (.appendEntriesResponse r) := by
  at_receive c (ackGuard ..)
theorem votePhase (b : Bool) : HandReadersTrunkBFactor.Tail.Vote f t c (Family.Vote.guard b) ↔
    ∃ n r, c.event = .receive n (.requestVoteResponse r) ∧ remote b c.actor c.pre n (.requestVoteResponse r) := by
  at_receive c (voteGuard ..)
theorem preVotePhase (b : Bool) : HandReadersTrunkBFactor.Tail.PreVote f t c (Family.PreVote.guard b) ↔
    ∃ n r, c.event = .receive n (.requestPreVoteResponse r) ∧ remote b c.actor c.pre n (.requestPreVoteResponse r) := by
  at_receive c (preVoteGuard ..)
theorem proposalPhase (b : Bool) : HandReadersTrunkBFactor.Tail.Proposal f t c (Family.Proposal.guard b) ↔
    ∃ n k, c.event = .receive n (.proposeRequestVoteRequest k) ∧ (b = true → k = c.pre.currentTerm ∧ canStartElection c.pre c.actor) := by
  at_receive c (proposalGuard ..)

omit [Config.InitialConfiguration] in
private theorem observedLe (s : NodeState) (r : AppendEntriesRequest) : r.term ≤ (observed s r).currentTerm := by
  obtain raised | stable := observe_bumping s (message := .appendEntriesRequest r) trivial
  · rw [show observed s r = _ from raised.2]; exact Nat.le_refl _
  · rw [show observed s r = _ from stable.2]; exact stable.1

theorem requestPhase (b : Bool) : HandReadersTrunkBFactor.Tail.Request f t c (Family.Request.guard b) ↔
    ∃ n r, c.event = .receive n (.appendEntriesRequest r) ∧ req b (observed c.pre r) r := by
  constructor
  · rintro (⟨_,src,_,r,⟨_,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,_,_,pin,rfl⟩,g⟩ |
      ⟨_,src,_,r,⟨⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,_,pin⟩,g⟩)
    all_goals
      refine ⟨src,r,ev,(requestGuard b c.actor src _ r (observedLe ..)).mp ?_⟩
      rw [show observed c.pre r = _ from pin]
      exact g
  · rintro ⟨src,r,ev,g⟩
    have yes := (requestGuard b c.actor src _ r (observedLe c.pre r)).mpr g
    obtain rise | stable := observe_bumping c.pre (message := .appendEntriesRequest r) trivial
    · exact .inl ⟨_,src,_,r,⟨c.pre,⟨c.event,⟨rfl,rfl,rfl⟩,_,ev,ev,rfl⟩,rise,rise.1,rise.2,rise.2⟩,yes⟩
    · rw [show observed c.pre r = _ from stable.2] at yes
      exact .inr ⟨_,src,_,r,⟨⟨c.event,⟨rfl,rfl,rfl⟩,_,ev,ev,rfl⟩,stable.1,stable.2⟩,yes⟩
end

end ConsensusCoverage.HandReadersTrunkD.Condition
