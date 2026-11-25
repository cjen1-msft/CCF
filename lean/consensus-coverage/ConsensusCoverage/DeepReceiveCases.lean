module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.DeepInputCases
import all ConsensusCoverage.QueueSamplesA
import all ConsensusCoverage.DeepSchedules
import all ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ReachPath
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.DeepReceiveCases

open Consensus Consensus.Proofs Consensus.Model Consensus.Model.Node Safety
open ActionProfile ReadersAtoms GuardedDomain SolvedWitnesses

set_option maxRecDepth 8192

inductive ReceiveCase where
  | higherAck | stableAck | higherAppend | sameRole | followerRole | noneRole | follower | retired
  deriving DecidableEq

def ReceiveCase.column : ReceiveCase → Classes.StepBranch
  | .higherAck => .appendEntriesResponse_summary_observe_response_inl
  | .stableAck => .appendEntriesResponse_summary_observe_response_inr
  | .higherAppend => .appendEntriesRequest_summary_observe_bumping_inl
  | .sameRole => .appendEntriesRequest_summary_role_inl
  | .followerRole => .appendEntriesRequest_summary_role_inr_inl
  | .noneRole => .appendEntriesRequest_summary_role_inr_inr
  | .follower => .appendEntriesRequest_summary_follower_inl
  | .retired => .appendEntriesRequest_summary_follower_inr

private def test (x : XView) (k : ReceiveCase) : Bool :=
  match k, x.event with
  | .higherAck, .receive n (.appendEntriesResponse q) =>
    decide (n ∈ eligiblePeers x.base.pre x.base.actor ∧ x.base.pre.role = .primary ∧
      x.base.pre.currentTerm < q.term)
  | .stableAck, .receive n (.appendEntriesResponse q) =>
    decide (n ∈ eligiblePeers x.base.pre x.base.actor ∧ q.term ≤ x.base.pre.currentTerm)
  | .higherAck, _ | .stableAck, _ => false
  | _, .receive _ (.appendEntriesRequest q) => decide (x.base.pre.currentTerm < q.term)
  | _, _ => false

def check (s : Step) (k : ReceiveCase) : Bool :=
  (ofXAction s.cfg s.before s.after s.past s.act).any fun x => x.base.changed && test x k

private theorem emptyReply (self n : NodeID) (st : NodeState) (r : AppendEntriesRequest) (gone : Bool) :
    AEReply self n (bumpedState st r.term) r
      {bumpedState st r.term with role := if gone then .none else .follower} [] := by
  cases gone <;>
    refine ⟨rfl, rfl, rfl, ?_, (fun h => Role.noConfusion h), Or.inl ⟨rfl, rfl, ?_⟩⟩
  all_goals first | exact Or.inr (Or.inr rfl) | exact Or.inl rfl | simp

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)
  (root : (reach% step_initAsBackup_summary_eq_zero_or_pos_inl[15,0,0]) f t c t c.tr)
include root

local macro "long_event " c:ident rt:ident ev:ident : tactic => `(tactic|
  exact ⟨($c).event, ⟨_, ($c).tr, $rt, rfl, rfl, rfl⟩, _, $ev, $ev, rfl⟩)

private theorem ack (n : NodeID) (q : AppendEntriesResponse)
    (ev : c.event = .receive n (.appendEntriesResponse q)) (peer : n ∈ eligiblePeers c.pre c.actor) :
    (c.pre.role = .primary ∧ c.pre.currentTerm < q.term →
      step_appendEntriesResponse_summary_observe_response_inl f t c) ∧
    (q.term ≤ c.pre.currentTerm → step_appendEntriesResponse_summary_observe_response_inr f t c) := by
  have path : (reach% step_appendEntriesResponse_summary_observe_response_inl[15])
      f t c c.actor c.pre n q := by long_event c root ev
  constructor
  · rintro ⟨role, higher⟩
    obtain h | h := observe_response c.pre q
    · iterate 15 right
      exact Or.inl ⟨_, _, _, _, path, fun no => no.2 peer, h⟩
    · exact absurd (h.1 role) (Nat.not_le_of_lt higher)
  · intro stable
    obtain h | h := observe_response c.pre q
    · exact absurd stable (Nat.not_le_of_lt h.2.1)
    · iterate 15 right
      exact Or.inl ⟨_, _, _, _, path, fun no => no.2 peer, h⟩

private theorem request (n : NodeID) (q : AppendEntriesRequest)
    (ev : c.event = .receive n (.appendEntriesRequest q)) (higher : c.pre.currentTerm < q.term) :
    ∀ k : ReceiveCase, k ≠ .higherAck → k ≠ .stableAck → sig c k.column := by
  have path : (reach% step_appendEntriesRequest_summary_role_inl[15]) f t c c.actor c.pre n q := by
    long_event c root ev
  obtain raised | stable := observe_bumping c.pre (message := .appendEntriesRequest q) trivial
  case inr => exact absurd stable.1 (Nat.not_le_of_lt higher)
  intro k h₁ h₂
  cases k with
  | higherAck => exact (h₁ rfl).elim
  | stableAck => exact (h₂ rfl).elim
  | higherAppend =>
    iterate 15 right
    exact Or.inl ⟨_, _, ⟨c.event, ⟨_, c.tr, root, rfl, rfl⟩, n, _, ev, ev, rfl⟩, raised⟩
  | sameRole | followerRole | noneRole | follower | retired =>
    iterate 15 right
    left
    refine ⟨c.actor, c.pre, n, q, path, raised, raised.1, raised.2, ?_⟩
    first
    | refine ⟨_, [], emptyReply c.actor n c.pre q false, ?_⟩
      have reply := emptyReply c.actor n c.pre q false
      have info := aeReply_summary (before := c.pre) (z := bumpedState c.pre q.term) rfl rfl
        (Nat.le_of_lt higher) reply
      first
      | exact ⟨info.1, info.2, reply.1, reply.2, reply.2.1, reply.2.2, reply.2.2.1, reply.2.2.2,
          reply.2.2.2.1, reply.2.2.2.2, reply.2.2.2.2.1, reply.2.2.2.2.2, rfl⟩
      | exact ⟨info.1, info.2, reply.1, reply.2, reply.2.1, reply.2.2, reply.2.2.1, reply.2.2.2,
          reply.2.2.2.1, reply.2.2.2.2, reply.2.2.2.2.1, reply.2.2.2.2.2, Or.inl rfl, rfl⟩
      | exact ⟨info.1, info.2, reply.1, reply.2, reply.2.1, reply.2.2, reply.2.2.1, reply.2.2.2,
          reply.2.2.2.1, reply.2.2.2.2, reply.2.2.2.2.1, reply.2.2.2.2.2, rfl, Or.inl rfl⟩
    | refine ⟨_, [], emptyReply c.actor n c.pre q true, ?_⟩
      have reply := emptyReply c.actor n c.pre q true
      have info := aeReply_summary (before := c.pre) (z := bumpedState c.pre q.term) rfl rfl
        (Nat.le_of_lt higher) reply
      first
      | exact ⟨info.1, info.2, reply.1, reply.2, reply.2.1, reply.2.2, reply.2.2.1, reply.2.2.2,
          reply.2.2.2.1, reply.2.2.2.2, reply.2.2.2.2.1, reply.2.2.2.2.2, Or.inr rfl, rfl⟩
      | exact ⟨info.1, info.2, reply.1, reply.2, reply.2.1, reply.2.2, reply.2.2.1, reply.2.2.2,
          reply.2.2.2.1, reply.2.2.2.2, reply.2.2.2.2.1, reply.2.2.2.2.2, rfl, Or.inr rfl⟩
end

theorem correct (s : Step) (k : ReceiveCase) (yes : check s k = true) : label s (.step k.column) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  obtain ⟨x, made, ok⟩ := ofXAction_matches s
  simp only [check, made, Option.any_some, Bool.and_eq_true] at yes
  obtain ⟨changed, guard⟩ := yes
  have root := DeepInputCases.summary c fun h =>
    Bool.noConfusion (changed.symm.trans ((View.old_post ok.1).mp h))
  refine (label_true s _).mpr ((sig_iff c _).mpr ?_)
  cases event : x.event with
  | internal => cases k <;> simp [test, event] at guard
  | receive n m =>
    have ev := (X.event_eq ok).trans event
    cases m <;> cases k <;> simp only [test, event, Bool.false_eq_true, decide_eq_true_eq] at guard
    all_goals
      try rw [← View.pre_eq ok.1, ← View.actor_eq ok.1] at guard
      try rw [← View.pre_eq ok.1] at guard
      first
      | exact guard.elim
      | exact (ack c root n _ ev guard.1).1 guard.2
      | exact (ack c root n _ ev guard.1).2 guard.2
      | exact request c root n _ ev guard _ (by decide) (by decide)

open QueueSamplesA FrontierRows DeepSchedules in
local macro "receive_at " k:term:arg sc:term:arg i:num : term =>
  `(checked (ReceiveCase.column $k) (selected $sc (by unfold Run.valid; decide) $i)
    (check · $k) (by decide +kernel) (correct · $k))

open DeepSchedules in
def certificates : List QueueSamplesA.Certificate :=
  [receive_at .higherAck higherReply 12, receive_at .stableAck installLater 2,
   receive_at .higherAppend divergent 10, receive_at .sameRole divergent 10,
   receive_at .followerRole divergent 10, receive_at .noneRole divergent 10,
   receive_at .follower divergent 10, receive_at .retired divergent 10]

end ConsensusCoverage.DeepReceiveCases
