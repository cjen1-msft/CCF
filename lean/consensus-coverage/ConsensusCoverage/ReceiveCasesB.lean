module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.DeepSchedulesB
import all ConsensusCoverage.DeepSchedulesB
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ReachPath
import all Consensus.Proofs.SafetyInvariant
meta import Lean

namespace ConsensusCoverage.ReceiveCasesB

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open ActionProfile ReadersAtoms SolvedWitnesses DeepSchedulesB Lean Elab Tactic

set_option maxHeartbeats 500000
set_option maxRecDepth 8192

-- A changed actor reaches the transition summary even without any new
-- envelope, grant, or commit. The backing implication just reuses its premise.
private theorem changedSummary [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    {c : Ctx f t} {x : XView} (ok : x.Matches c) (changed : x.base.changed = true) :
    (reach% step_voteRequest_summary_observe_bumping_inl[15,0,0]) f t c t c.tr := by
  refine ⟨Or.inl ⟨⟨c.post_now, ?_, rfl⟩, c.post_now, c.post_now, c.post_now,
    fun backing => ⟨⟨_, backing⟩, fun _ _ => backing⟩, rfl⟩, rfl, HEq.rfl⟩
  exact fun old => Bool.noConfusion (changed.symm.trans ((GuardedDomain.View.old_post ok.1).mp old))

-- Discharge exactly one normalized caller; no search through unrelated paths.
local elab "branch_at " i:num : tactic => do
  for _ in [:i.getNat] do evalTactic (← `(tactic| right))
  evalTactic (← `(tactic| left))

private structure Sample where
  s : Step
  x : XView
  ok : @XView.Matches ⟨s.cfg⟩ _ _ x s.context

private def asSample (r : Replay) (i : Nat) (hs : (r.atStep i).isSome)
    (hv : let s := (r.atStep i).get hs
          (ofXAction s.cfg s.before s.after s.past s.act).isSome) : Sample := by
  let s := (r.atStep i).get hs
  let v := ofXAction s.cfg s.before s.after s.past s.act
  refine ⟨s, v.get hv, ?_⟩
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨x, hx, ok⟩ := ofXAction_matches s
  exact (Option.some.inj ((Option.eq_some_of_isSome hv).symm.trans hx)).symm ▸ ok

private def src : Event → NodeID
  | .receive source _ => source
  | _ => 0

private def msg : Event → Node.Message
  | .receive _ m => m
  | _ => .proposeRequestVoteRequest 0

private def request : Node.Message → RequestVoteRequest
  | .requestVoteRequest q | .requestPreVoteRequest q => q
  | _ => ⟨0, 0, 0⟩

private def response : Node.Message → RequestVoteResponse
  | .requestVoteResponse q | .requestPreVoteResponse q => q
  | _ => ⟨0, false⟩

private def ack : Node.Message → AppendEntriesResponse
  | .appendEntriesResponse q => q
  | _ => ⟨0, false, 0⟩

private abbrev Certificate := {b : Classes.StepBranch // ∃ s : Step, label s (.step b) = true}

local macro "at_sample " r:term:arg i:num b:term:arg a:ident c:ident ok:ident : tactic => `(tactic|
  (let $a := asSample $r $i (by decide +kernel) (by decide +kernel)
   letI : Config.InitialConfiguration := ⟨($a).s.cfg⟩
   let $c := ($a).s.context
   have $ok := ($a).ok
   refine ⟨($a).s, (label_true ($a).s (.step $b)).mpr ((sig_iff $c $b).mpr ?_)⟩))

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State}
  {c : Ctx f t} {x : XView} (ok : x.Matches c) (changed : x.base.changed = true)
  (n : NodeID)
include ok changed

local macro "short_path " ok:ident fresh:ident ev:ident : tactic => `(tactic|
  exact ⟨_, ⟨_, _, changedSummary $ok $fresh, (X.tr_pre_eq $ok).symm, (X.tr_event_eq $ok).symm⟩,
    _, _, $ev, $ev, rfl⟩)

local macro "long_path " ok:ident fresh:ident ev:ident : tactic => `(tactic|
  exact ⟨_, ⟨_, _, changedSummary $ok $fresh, (X.tr_actor_eq $ok).symm,
    (X.tr_pre_eq $ok).symm, (X.tr_event_eq $ok).symm⟩, _, $ev, $ev, rfl⟩)

private theorem voteNew (q : RequestVoteRequest) (ev : x.event = .receive n (.requestVoteRequest q))
    (bump : x.base.pre.currentTerm < q.term) : step_voteRequest_summary_observe_bumping_inl f t c := by
  branch_at 15
  refine ⟨x.base.pre, q, ⟨x.event, ⟨t, c.tr, changedSummary ok changed,
    (X.tr_pre_eq ok).symm, (X.tr_event_eq ok).symm⟩, n, _, ev, ev, rfl⟩, bump, ?_⟩
  rcases observe_bumping x.base.pre (message := .requestVoteRequest q) trivial with h | h
  · exact h.2
  · exact absurd h.1 (Nat.not_le_of_lt bump)

private theorem preNew (q : RequestVoteRequest) (ev : x.event = .receive n (.requestPreVoteRequest q))
    (bump : x.base.pre.currentTerm < q.term) : step_preVoteRequest_summary_observe_bumping_inl f t c := by
  branch_at 15
  refine ⟨x.base.pre, q, ?_, bump, ?_⟩
  · short_path ok changed ev
  · rcases observe_bumping x.base.pre (message := .requestPreVoteRequest q) trivial with h | h
    · exact h.2
    · exact absurd h.1 (Nat.not_le_of_lt bump)

private theorem voteReplyNew (q : RequestVoteResponse) (ev : x.event = .receive n (.requestVoteResponse q))
    (peer : n ∈ eligiblePeers x.base.pre x.base.actor) (bump : x.base.pre.currentTerm < q.term) :
    step_voteResponse_summary_observe_bumping_inl f t c := by
  branch_at 15
  refine ⟨x.base.actor, x.base.pre, n, q, ?_, fun h => h.2 peer, bump, ?_⟩
  · long_path ok changed ev
  · rcases observe_bumping x.base.pre (message := .requestVoteResponse q) trivial with h | h
    · exact h.2
    · exact absurd h.1 (Nat.not_le_of_lt bump)

private theorem preReplyNew (q : RequestVoteResponse) (ev : x.event = .receive n (.requestPreVoteResponse q))
    (peer : n ∈ eligiblePeers x.base.pre x.base.actor) (bump : x.base.pre.currentTerm < q.term) :
    step_preVoteResponse_summary_observe_bumping_inl f t c := by
  branch_at 15
  refine ⟨x.base.actor, x.base.pre, n, q, ?_, fun h => h.2 peer, bump, ?_⟩
  · long_path ok changed ev
  · rcases observe_bumping x.base.pre (message := .requestPreVoteResponse q) trivial with h | h
    · exact h.2
    · exact absurd h.1 (Nat.not_le_of_lt bump)

private theorem voteReplyStable (q : RequestVoteResponse) (ev : x.event = .receive n (.requestVoteResponse q))
    (peer : n ∈ eligiblePeers x.base.pre x.base.actor) (le : q.term ≤ x.base.pre.currentTerm) :
    step_voteResponse_summary_observe_bumping_inr f t c := by
  branch_at 15
  refine ⟨x.base.actor, x.base.pre, n, q, ?_, fun h => h.2 peer, le, ?_⟩
  · long_path ok changed ev
  · rcases observe_bumping x.base.pre (message := .requestVoteResponse q) trivial with h | h
    · exact absurd h.1 (Nat.not_lt_of_ge le)
    · exact h.2

private theorem preReplyStable (q : RequestVoteResponse) (ev : x.event = .receive n (.requestPreVoteResponse q))
    (peer : n ∈ eligiblePeers x.base.pre x.base.actor) (le : q.term ≤ x.base.pre.currentTerm) :
    step_preVoteResponse_summary_observe_bumping_inr f t c := by
  branch_at 15
  refine ⟨x.base.actor, x.base.pre, n, q, ?_, fun h => h.2 peer, le, ?_⟩
  · long_path ok changed ev
  · rcases observe_bumping x.base.pre (message := .requestPreVoteResponse q) trivial with h | h
    · exact absurd h.1 (Nat.not_lt_of_ge le)
    · exact h.2

end

private def voteBump : Certificate := by
  refine ⟨.voteRequest_summary_observe_bumping_inl, ?_⟩
  at_sample campaign 4 .voteRequest_summary_observe_bumping_inl a c ok
  exact voteNew (c := c) (x := a.x) ok (by decide +kernel) (src a.x.event) (request (msg a.x.event))
    (by decide +kernel) (by decide +kernel)

local macro "check_receive " b:term:arg r:term:arg i:num get:ident cert:ident : term => `(by
  refine ⟨$b, ?_⟩
  at_sample $r $i $b a c ok
  apply $cert (c := c) (x := a.x) ok (by decide +kernel) (src a.x.event) ($get (msg a.x.event))
  all_goals decide +kernel)

private def certificates : List Certificate := [
  voteBump,
  check_receive .preVoteRequest_summary_observe_bumping_inl higherPreRequest 8 request preNew,
  check_receive .voteResponse_summary_observe_bumping_inl higherVoteReply 20 response voteReplyNew,
  check_receive .preVoteResponse_summary_observe_bumping_inl higherPreReply 21 response preReplyNew,
  check_receive .voteResponse_summary_observe_bumping_inr campaign 5 response voteReplyStable,
  check_receive .preVoteResponse_summary_observe_bumping_inr preVote 4 response preReplyStable]

public def witnessed : List Classes.StepBranch := certificates.map Subtype.val

public theorem occurs {b : Classes.StepBranch} (mem : b ∈ witnessed) :
    ∃ s : Step, label s (.step b) = true := by
  obtain ⟨cert, _, rfl⟩ := List.mem_map.mp mem
  exact cert.property

end ConsensusCoverage.ReceiveCasesB
