module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.DeepSchedulesB
import all ConsensusCoverage.DeepSchedulesB
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReadersPolarObserve
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

private def appendRequest : Node.Message → AppendEntriesRequest
  | .appendEntriesRequest q => q
  | _ => ⟨0, 0, 0, [], 0⟩

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

private abbrev peerGuard (m : Node.Message) (n : NodeID) (x : XView) : Prop :=
  match m with
  | .requestVoteResponse _ | .requestPreVoteResponse _ => n ∈ eligiblePeers x.base.pre x.base.actor
  | _ => True

private theorem bumpEntry (m : Node.Message) (ev : x.event = .receive n m)
    (kind : Bumping m) (peer : peerGuard m n x) :
    (reach% step_observe_bumping_bump_pos[15]) f t c x.base.pre m := by
  cases m with
  | appendEntriesRequest q =>
    exact Or.inl ⟨q, by short_path ok changed ev, rfl⟩
  | requestVoteRequest q =>
    exact Or.inr (.inl ⟨q, by short_path ok changed ev, rfl⟩)
  | requestVoteResponse q =>
    exact Or.inr (.inr (.inl ⟨x.base.actor, n, q, by long_path ok changed ev, fun h => h.2 peer, rfl⟩))
  | requestPreVoteRequest q =>
    exact Or.inr (.inr (.inr (.inl ⟨q, by short_path ok changed ev, rfl⟩)))
  | requestPreVoteResponse q =>
    exact Or.inr (.inr (.inr (.inr ⟨x.base.actor, n, q, by long_path ok changed ev, fun h => h.2 peer, rfl⟩)))
  | appendEntriesResponse | proposeRequestVoteRequest => exact kind.elim

private theorem bumpYes (m : Node.Message) (ev : x.event = .receive n m)
    (kind : Bumping m) (peer : peerGuard m n x) (lt : x.base.pre.currentTerm < m.term) :
    ∀ {b}, Classes.StepBranch.observe_bumping_bump_pos = b → sig c b := by
  rintro _ rfl
  branch_at 15
  exact ⟨_, _, bumpEntry ok changed n m ev kind peer, lt⟩

private theorem bumpNo (m : Node.Message) (ev : x.event = .receive n m)
    (kind : Bumping m) (peer : peerGuard m n x) (le : ¬x.base.pre.currentTerm < m.term) :
    ∀ {b}, Classes.StepBranch.observe_bumping_bump_neg = b → sig c b := by
  rintro _ rfl
  branch_at 15
  exact ⟨_, _, bumpEntry ok changed n m ev kind peer, le⟩

private abbrev bumpQuestion : Node.Message → Classes.StepBranch
  | .appendEntriesRequest _ => .observe_bumping_message_appendEntriesRequest
  | .requestVoteRequest _ => .observe_bumping_message_requestVoteRequest
  | .requestVoteResponse _ => .observe_bumping_message_requestVoteResponse
  | .requestPreVoteRequest _ => .observe_bumping_message_requestPreVoteRequest
  | .requestPreVoteResponse _ => .observe_bumping_message_requestPreVoteResponse
  | _ => .observe_bumping_bump_pos

private theorem bumpKind (m : Node.Message) (ev : x.event = .receive n m)
    (kind : Bumping m) (peer : peerGuard m n x) (lt : x.base.pre.currentTerm < m.term)
    {b : Classes.StepBranch} (same : bumpQuestion m = b) : sig c b := by
  subst b
  have entry := bumpEntry ok changed n m ev kind peer
  cases m <;> first | exact kind.elim | (branch_at 15; exact
    ⟨_, _, entry, lt, _, rfl, trivial, lt, Nat.ne_of_lt lt, Nat.ne_of_lt lt⟩)

private theorem ackLeader (q : AppendEntriesResponse) (ev : x.event = .receive n (.appendEntriesResponse q))
    (peer : n ∈ eligiblePeers x.base.pre x.base.actor)
    (leader : x.base.pre.role = .primary) : step_observe_response_leader_pos f t c := by
  branch_at 15
  refine ⟨x.base.pre, ⟨x.base.actor, n, ?_, fun h => h.2 peer⟩, leader⟩
  exact ⟨x.event, ⟨t, c.tr, changedSummary ok changed, (X.tr_actor_eq ok).symm,
    (X.tr_pre_eq ok).symm, (X.tr_event_eq ok).symm⟩, _, ev, ev, q, rfl⟩

private theorem ackHigher (q : AppendEntriesResponse) (ev : x.event = .receive n (.appendEntriesResponse q))
    (peer : n ∈ eligiblePeers x.base.pre x.base.actor) (leader : x.base.pre.role = .primary)
    (lt : x.base.pre.currentTerm < q.term) : step_observe_response_bump_pos f t c := by
  branch_at 15
  exact ⟨x.base.pre, q, ⟨x.base.actor, n, by long_path ok changed ev, fun h => h.2 peer⟩, leader, lt⟩

private theorem ackStable (q : AppendEntriesResponse) (ev : x.event = .receive n (.appendEntriesResponse q))
    (peer : n ∈ eligiblePeers x.base.pre x.base.actor) (leader : x.base.pre.role = .primary)
    (le : ¬x.base.pre.currentTerm < q.term) : step_observe_response_bump_neg f t c := by
  branch_at 15
  exact ⟨x.base.pre, q, ⟨x.base.actor, n, by long_path ok changed ev, fun h => h.2 peer⟩, leader, le⟩

private def grant (p : NodeState) (n : NodeID) (q : RequestVoteRequest) : Bool :=
  let p := bumpedState p q.term
  decide (q.term = p.currentTerm ∧ voteLogUpToDate p q ∧ (!p.primaryKnown) = true ∧
    (p.votedFor = none ∨ p.votedFor = some n))

local macro "grant_path " x:ident ok:ident ch:ident n:ident q:ident ev:ident lt:ident g:ident : tactic => `(tactic|
  (branch_at 15
   rcases observe_bumping ($x).base.pre (message := .requestVoteRequest $q) trivial with h | h
   · refine ⟨($x).base.actor, ($x).base.pre, $n, $q, ?_, h, h.1, h.2, $g,
       $n, _, rfl, trivial, Nat.le_refl _⟩
     long_path $ok $ch $ev
   · exact absurd h.1 (Nat.not_le_of_lt $lt)))

private theorem grantYes (q : RequestVoteRequest) (ev : x.event = .receive n (.requestVoteRequest q))
    (lt : x.base.pre.currentTerm < q.term) (g : grant x.base.pre n q = true) :
    step_voteRequest_summary_granted_pos f t c := by grant_path x ok changed n q ev lt g

private theorem grantNo (q : RequestVoteRequest) (ev : x.event = .receive n (.requestVoteRequest q))
    (lt : x.base.pre.currentTerm < q.term) (g : ¬grant x.base.pre n q = true) :
    step_voteRequest_summary_granted_neg f t c := by grant_path x ok changed n q ev lt g

local macro "insert_path " x:ident ok:ident ch:ident n:ident q:ident ev:ident peer:ident
    guard:ident " with " member:tacticSeq : tactic => `(tactic|
  (branch_at 15
   rcases observe_bumping ($x).base.pre (message := .requestVoteResponse $q) trivial with h | h
   · exact absurd h.1 (Nat.not_lt_of_ge (Nat.le_of_eq ($guard).2.1))
   · refine ⟨($x).base.actor, ($x).base.pre, $n, $q, ?_, fun h => h.2 $peer,
       h, h.1, h.2, $guard, _, [], Or.inl ⟨rfl, rfl⟩, ?_⟩
     · long_path $ok $ch $ev
     · $member))

private theorem inserted (q : RequestVoteResponse) (ev : x.event = .receive n (.requestVoteResponse q))
    (peer : n ∈ eligiblePeers x.base.pre x.base.actor)
    (g : x.base.pre.role = .candidate ∧ q.term = x.base.pre.currentTerm ∧ q.voteGranted = true) :
    step_voteResponse_summary_mem_insert_inl f t c := by
  insert_path x ok changed n q ev peer g with
    exact CCF.Finset.mem_insert.mpr (Or.inl rfl)

private theorem oldVote (q : RequestVoteResponse) (ev : x.event = .receive n (.requestVoteResponse q))
    (peer : n ∈ eligiblePeers x.base.pre x.base.actor)
    (g : x.base.pre.role = .candidate ∧ q.term = x.base.pre.currentTerm ∧ q.voteGranted = true)
    (selfVote : x.base.actor ∈ x.base.pre.votesGranted) : step_voteResponse_summary_mem_insert_inr f t c := by
  insert_path x ok changed n q ev peer g with
    exact ⟨_, CCF.Finset.mem_insert.mpr (Or.inr selfVote), selfVote⟩

end

private def voteBump : Certificate := by
  refine ⟨.voteRequest_summary_observe_bumping_inl, ?_⟩
  at_sample campaign 4 .voteRequest_summary_observe_bumping_inl a c ok
  exact voteNew (c := c) (x := a.x) ok (by decide +kernel) (src a.x.event) (request (msg a.x.event))
    (by decide +kernel) (by decide +kernel)

-- Check the successful disjunct alone rather than scanning earlier terms.
local macro "polar_at " b:term:arg r:term:arg i:num test:ident sound:ident arm:num : term => `(by
  refine ⟨$b, ?_⟩
  at_sample $r $i $b a c ok
  apply $sound _ _ c a.x ok (ReadersPolar.prepare a.s.cfg a.x)
  unfold $test
  iterate $arm (rw [Bool.or_eq_true]; right)
  rw [Bool.or_eq_true]; left
  decide +kernel)

local macro "check_receive " b:term:arg r:term:arg i:num get:ident cert:ident : term => `(by
  refine ⟨$b, ?_⟩
  at_sample $r $i $b a c ok
  apply $cert (c := c) (x := a.x) ok (by decide +kernel) (src a.x.event) ($get (msg a.x.event))
  all_goals decide +kernel)

local macro "check_bump " b:term:arg r:term:arg i:num tag:term:arg get:ident cert:ident : term => `(by
  refine ⟨$b, ?_⟩
  at_sample $r $i $b a c ok
  exact $cert (c := c) (x := a.x) ok (by decide +kernel) (src a.x.event) ($tag ($get (msg a.x.event)))
    (by decide +kernel) True.intro (by first | exact True.intro | decide +kernel) (by decide +kernel) (b := $b) rfl)

open ReadersPolarObserve.R in
private def certificates : List Certificate := [
  voteBump,
  polar_at .voteRequest_summary_observe_bumping_inr stableVote 10
    yes_step_voteRequest_summary_observe_bumping_inr yes_step_voteRequest_summary_observe_bumping_inr_sound 15,
  polar_at .observe_response_leader_neg delayedAck 9
    yes_step_observe_response_leader_neg yes_step_observe_response_leader_neg_sound 9,
  check_receive .voteResponse_summary_mem_insert_inl campaign 5 response inserted,
  check_receive .voteResponse_summary_mem_insert_inr campaign 5 response oldVote,
  check_receive .voteRequest_summary_granted_pos campaign 4 request grantYes,
  check_receive .voteRequest_summary_granted_neg denyVote 7 request grantNo,
  check_receive .preVoteRequest_summary_observe_bumping_inl higherPreRequest 8 request preNew,
  check_receive .voteResponse_summary_observe_bumping_inl higherVoteReply 20 response voteReplyNew,
  check_receive .preVoteResponse_summary_observe_bumping_inl higherPreReply 21 response preReplyNew,
  check_receive .voteResponse_summary_observe_bumping_inr campaign 5 response voteReplyStable,
  check_receive .preVoteResponse_summary_observe_bumping_inr preVote 4 response preReplyStable,
  check_receive .observe_response_leader_pos firstAck 2 ack ackLeader,
  check_receive .observe_response_bump_neg firstAck 2 ack ackStable,
  check_receive .observe_response_bump_pos higherAck 12 ack ackHigher,
  check_bump .observe_bumping_bump_pos campaign 4 Node.Message.requestVoteRequest request bumpYes,
  check_bump .observe_bumping_bump_neg firstAck 1 Node.Message.appendEntriesRequest appendRequest bumpNo,
  check_bump .observe_bumping_message_appendEntriesRequest divergent 10 Node.Message.appendEntriesRequest appendRequest bumpKind,
  check_bump .observe_bumping_message_requestVoteRequest campaign 4 Node.Message.requestVoteRequest request bumpKind,
  check_bump .observe_bumping_message_requestVoteResponse higherVoteReply 20 Node.Message.requestVoteResponse response bumpKind,
  check_bump .observe_bumping_message_requestPreVoteRequest higherPreRequest 8 Node.Message.requestPreVoteRequest request bumpKind,
  check_bump .observe_bumping_message_requestPreVoteResponse higherPreReply 21 Node.Message.requestPreVoteResponse response bumpKind]

public def witnessed : List Classes.StepBranch := certificates.map Subtype.val

public theorem occurs {b : Classes.StepBranch} (mem : b ∈ witnessed) :
    ∃ s : Step, label s (.step b) = true := by
  obtain ⟨cert, _, rfl⟩ := List.mem_map.mp mem
  exact cert.property

end ConsensusCoverage.ReceiveCasesB
