module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.RetiredRoleOrigin
import all ConsensusCoverage.FullProfile
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.CampaignFrontier

open CCF Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open Consensus.Proofs.Direct

/-- Election eligibility requires a signed configuration or a committed retirement. -/
private theorem can_positive {st : NodeState} {self : NodeID} (can : canStartElection st self) :
    0 < max st.commitIndex (maxCommittableIndex st.log) := by
  apply Nat.pos_of_ne_zero
  intro zero
  have ci : st.commitIndex = 0 := by
    have := Nat.le_max_left st.commitIndex (maxCommittableIndex st.log)
    omega
  have si : maxCommittableIndex st.log = 0 := by
    have := Nat.le_max_right st.commitIndex (maxCommittableIndex st.log)
    omega
  have empty : st.signedActiveConfigurations = [] := by
    apply List.eq_nil_iff_forall_not_mem.mpr
    intro cfg h
    have ⟨active,b⟩ := List.mem_filter.mp h
    have hist : cfg ∈ configurationHistory st.log := List.mem_of_mem_drop active
    have pos := (mem_history_filterMap (start := 1) hist).1
    have ub := of_decide_eq_true b
    omega
  rcases can.2.1 with m | m
  · simp [empty,configurationMembers] at m
  · simp [NodeState.retirementCompletedNodes,NodeState.committedLog,ci,configurationHistory,configurationMembers] at m

private abbrev Positive (st : NodeState) := 0 < max st.commitIndex (maxCommittableIndex st.log)
private abbrev HasFront (st : NodeState) := st.role = .preVoteCandidate → Positive st

private def Transition (self : NodeID) (p st : NodeState) : Prop :=
  HasFront st ∧ (p.currentTerm < st.currentTerm → st.votedFor = some self → st.role ≠ .follower → Positive p)

private theorem copy {p st : NodeState} {self} (prior : Transition self p st) {w : NodeState}
    (role : w.role = st.role) (term : w.currentTerm = st.currentTerm)
    (log : w.log = st.log) (commit : w.commitIndex = st.commitIndex) (vote : w.votedFor = st.votedFor) :
    Transition self p w := by
  refine ⟨fun h => ?_,fun fresh voted active => prior.2 (term ▸ fresh) (vote ▸ voted) (role ▸ active)⟩
  change 0 < max w.commitIndex (maxCommittableIndex w.log)
  rw [log,commit]
  exact prior.1 (role ▸ h)

private theorem unchanged {st : NodeState} (self : NodeID) (ok : HasFront st) : Transition self st st :=
  ⟨ok,fun fresh => (Nat.lt_irrefl _ fresh).elim⟩

private theorem disabled {self p st} (role : st.role ≠ .preVoteCandidate)
    (term : st.currentTerm = p.currentTerm) : Transition self p st :=
  ⟨fun h => (role h).elim,fun fresh => ((Nat.ne_of_lt fresh) term.symm).elim⟩

private theorem advance {self p mid st} (prior : Transition self p mid)
    (active : mid.role = .primary) (a : Advance self mid st) : Transition self p st := by
  rcases a with rfl | ⟨_,stamp,vote,_,_,_,_,_,keep | gone⟩
  · exact prior
  · refine ⟨fun h => ?_,fun lt v _ => prior.2 (stamp ▸ lt) (vote ▸ v) (by rw [active]; decide)⟩
    rw [keep,active] at h; contradiction
  · refine ⟨fun h => ?_,fun lt v _ => prior.2 (stamp ▸ lt) (vote ▸ v) (by rw [active]; decide)⟩
    rw [gone] at h; contradiction

private theorem start {self p mid} (pos : Positive p) :
    Keeps (Transition self p) (becomeCandidate (Capabilities.record self) mid self) := by
  refine ConsensusCoverage.RetiredRoleOrigin.result (becomeCandidate_sends self mid) ?_
  rintro _ _ (⟨rfl,_⟩|⟨_,a,_⟩)
  · exact ⟨(fun h => by cases h),fun _ _ _ => pos⟩
  · exact advance ⟨(fun h => by cases h),fun _ _ _ => pos⟩ rfl a

private theorem observed (p : NodeState) (m : Message) (self : NodeID) (ok : HasFront p) :
    Transition self p (observeTerm p m) := by
  have aware (t : Nat) : Transition self p (becomeAwareOfNewTerm p t) :=
    ⟨(fun h => by cases h),fun _ _ h => (h rfl).elim⟩
  have bump (t : Nat) : Transition self p (updateTerm p t) := by
    unfold updateTerm
    split
    · exact aware _
    · exact unchanged self ok
  cases m <;> simp only [observeTerm]
  all_goals first | exact bump _ | exact unchanged self ok | split <;> first | exact bump _ | exact unchanged self ok

private theorem local_step (self : NodeID) (p : NodeState) (input : Input) (ok : HasFront p) :
    Keeps (Transition self p) (act (Capabilities.record self) self p input) := by
  cases input with
  | append xs =>
    unfold act appendBatch
    refine Keeps.bind' Keeps.guard' fun _ allow => ?_
    refine Keeps.bind' (Keeps.foldlM' (P := fun st =>
      st.role = p.role ∧ st.currentTerm = p.currentTerm) (fun st entry h => ?_)
        xs p ⟨rfl,rfl⟩) fun mid h =>
      ConsensusCoverage.RetiredRoleOrigin.result (advanceCommit_sends self mid) (fun _ _ done =>
        advance (disabled (by rw [h.1,allow.1]; decide) h.2) (h.1.trans allow.1) done.1)
    refine Keeps.bind' (ConsensusCoverage.RetiredRoleOrigin.result
      (appendEntry_batch self st st [] entry.content (ConsensusCoverage.RetiredRoleOrigin.batch_start ..))
      (fun _ _ batch => ConsensusCoverage.RetiredRoleOrigin.batch_fields h batch)) fun appended h => ?_
    exact Keeps.foldlM' (fun cur (peer,idx) h => ConsensusCoverage.RetiredRoleOrigin.result
      (sendEntries_batch self cur cur [] peer idx (ConsensusCoverage.RetiredRoleOrigin.batch_start ..))
      fun _ _ batch => ConsensusCoverage.RetiredRoleOrigin.batch_fields h batch) entry.flushes appended h
  | sendEntries => exact Keeps.seq' fun _ => Keeps.seq' fun _ => Keeps.pure' (unchanged self ok)
  | nominateSuccessor =>
    exact ConsensusCoverage.RetiredRoleOrigin.result (nominate_sends self p) fun _ _ h => by rw [h.1]; exact unchanged self ok
  | initAsBackup => exact Keeps.seq' fun _ => Keeps.pure' ⟨(fun h => by cases h),fun _ _ h => (h rfl).elim⟩
  | timeout k =>
    cases k with
    | checkQuorum => exact Keeps.seq' fun _ => Keeps.pure' ⟨(fun h => by cases h),fun _ _ h => (h rfl).elim⟩
    | election =>
      unfold act startElection becomePreVoteCandidate
      refine Keeps.bind' Keeps.guard' fun _ can => Keeps.ite' (fun _ => start (can_positive can)) (fun _ => ?_)
      exact Keeps.seq' fun _ => Keeps.pure' ⟨fun _ => (can_positive (st := p) can),fun h => (Nat.lt_irrefl _ h).elim⟩

private theorem bumped (p : NodeState) (m : Message) :
    p.currentTerm < (observeTerm p m).currentTerm →
      (observeTerm p m).role = .follower ∧ (observeTerm p m).votedFor = none := by
  cases m <;> simp only [observeTerm,updateTerm] <;> repeat' split
  all_goals simp_all [becomeAwareOfNewTerm,Nat.ne_of_lt]

private theorem append_receive (self src : NodeID) (p : NodeState) (r : AppendEntriesRequest) (ok : HasFront p) :
    let z := observeTerm p (.appendEntriesRequest r)
    Keeps (Transition self p) (handleAppendEntriesRequest (Capabilities.record self) self src z r) := by
  intro z
  have old := observed p (.appendEntriesRequest r) self ok
  have le : r.term ≤ z.currentTerm := by
    rcases observe_bumping p (message := .appendEntriesRequest r) trivial with ⟨_,eq⟩ | ⟨le,eq⟩
    · simp only [z,eq]; exact Nat.le_refl _
    · rw [show z = p from eq]; exact le
  by_cases isOld : r.term < z.currentTerm
  · have ne := Nat.ne_of_lt isOld
    simp [handleAppendEntriesRequest,ne,isOld]
    exact Keeps.seq' fun _ => Keeps.pure' old
  have same := Nat.le_antisymm le (Nat.le_of_not_lt isOld)
  let cap : Caps := Capabilities.record self
  have done (w : NodeState) (notPv : w.role ≠ .preVoteCandidate) (tw : w.currentTerm = z.currentTerm)
      (vw : w.votedFor = z.votedFor) (req : r.term ≤ w.currentTerm) :
      Keeps (Transition self p) (handleAppendEntriesRequest cap self src w r) := by
    refine ConsensusCoverage.RetiredRoleOrigin.result (aeReply self src w r req) ?_
    intro post sent ans
    refine ⟨?_,?_⟩
    · intro pv
      rcases ans.2.2.2.1 with keep | follower | none
      · exact (notPv (keep ▸ pv)).elim
      · rw [follower] at pv; contradiction
      · rw [none] at pv; contradiction
    · intro hi selfVote _
      have vz := (bumped p (.appendEntriesRequest r) ((ans.1.trans tw) ▸ hi)).2
      have impossible := (ans.2.1.trans (vw.trans vz)).symm.trans selfVote
      cases impossible
  by_cases pv : z.role = .preVoteCandidate
  · let w := becomeAwareOfNewTerm z r.term
    have hr : handleAppendEntriesRequest cap self src z r = handleAppendEntriesRequest cap self src w r := by
      simp [handleAppendEntriesRequest,w,same,pv,becomeAwareOfNewTerm]
    rw [hr]
    exact done w (by simp [w,becomeAwareOfNewTerm]) same (by simp [w,becomeAwareOfNewTerm,same]) (Nat.le_refl _)
  · exact done z pv rfl rfl le

private theorem receive_step (self src : NodeID) (p : NodeState) (m : Message) (ok : HasFront p) :
    Keeps (Transition self p) (receive (Capabilities.record self) self src p m) := by
  unfold receive
  refine Keeps.ite' (fun _ => Keeps.pure' (unchanged self ok)) fun _ => ?_
  have old := observed p m self ok
  have bump := bumped p m
  have front : Positive (observeTerm p m) → Positive p := by
    simp only [Positive,Concrete.observeTerm_log,Concrete.observeTerm_commitIndex,imp_self]
  cases m with
  | appendEntriesRequest r => exact append_receive self src p r ok
  | requestVoteRequest r =>
    unfold handleRequestVoteRequest
    apply Keeps.seq'; intro _
    split
    · exact Keeps.pure' ⟨old.1,fun hi _ nf => (nf (bump hi).1).elim⟩
    · exact Keeps.pure' old
  | requestPreVoteRequest => exact Keeps.seq' fun _ => Keeps.pure' old
  | proposeRequestVoteRequest =>
    exact Keeps.ite' (fun can => start (front (can_positive can.2))) fun _ => Keeps.pure' old
  | requestPreVoteResponse =>
    unfold handleRequestPreVoteResponse
    refine Keeps.ite' (fun vote => Keeps.ite' (fun _ => start (front (old.1 vote.1)))
      (fun _ => Keeps.pure' old)) fun _ => Keeps.pure' old
  | requestVoteResponse =>
    unfold handleRequestVoteResponse
    refine Keeps.ite' (fun cond => ?_) fun _ => Keeps.pure' old
    refine ConsensusCoverage.RetiredRoleOrigin.result (electIfQuorum_sends self _) ?_
    rintro _ _ (⟨rfl,_⟩ | ⟨_,_,adv,_⟩)
    · exact old
    · apply advance _ rfl adv
      exact ⟨(fun h => by cases h), fun lt _ _ => by have h := (bump lt).1; rw [cond.1] at h; contradiction⟩
  | appendEntriesResponse r =>
    unfold handleAppendEntriesResponse
    refine Keeps.ite' (fun _ => Keeps.pure' old) fun primary => ?_
    have role : (observeTerm p (.appendEntriesResponse r)).role = .primary := by simpa using primary
    refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (copy old rfl rfl rfl rfl rfl)
    refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' old
    refine ConsensusCoverage.RetiredRoleOrigin.result (advanceCommit_sends self _) ?_
    intro _ _ adv
    apply advance _ _ adv.1
    · exact copy old rfl rfl rfl rfl rfl
    · exact role

private theorem step [Config.InitialConfiguration] {f : Frame} {after : Model.State} (c : Ctx f after)
    (ok : HasFront c.pre) : Transition c.actor c.pre c.post := by
  have proof (p : NodeState) (e : Event) (ok : HasFront p) : Keeps (Transition c.actor p)
      (Node.step (Capabilities.record c.actor) c.actor p e) := by
    cases e with
    | internal i => exact local_step _ _ i ok
    | receive src msg => exact receive_step _ src _ msg ok
  exact proof _ _ ok {} _ _ c.tr.ran

open ConsensusCoverage
private theorem folded [cfgI : Config.InitialConfiguration] {nodes : List NodeID}
    {f : FullProfile.ProofFrame} (run : FullProfile.Folded cfgI.configuration nodes f) :
    ∀ n st, Now f n st → HasFront st := by
  induction run with
  | initial init =>
    intro n st now role
    have eq := initial_state init now
    rw [eq] at role
    simp only [initialLocal] at role
    split at role
    · cases role
    · split at role <;> cases role
  | step prior ran ih =>
    obtain ⟨tr⟩ := LocalTransition.ofStep ran
    let c := Ctx.mk tr prior.invariant
    intro n st now
    rcases c.now_after now with ⟨rfl,rfl⟩ | ⟨_,prev⟩
    · exact (step c (ih _ _ c.pre_now)).1
    · exact ih _ _ prev

/-- A freshly self-voting campaign starts after a positive signed frontier, including
    promotions from a pre-vote quorum after the original eligibility check. -/
theorem positive_campaign (s : ActionProfile.Step) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩;
    s.context.pre.currentTerm < s.context.post.currentTerm →
    s.context.post.votedFor = some s.context.actor → s.context.post.role ≠ .follower →
    0 < max s.context.pre.commitIndex (maxCommittableIndex s.context.pre.log) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  exact (step s.context (folded s.folded _ _ s.context.pre_now)).2

end ConsensusCoverage.CampaignFrontier
