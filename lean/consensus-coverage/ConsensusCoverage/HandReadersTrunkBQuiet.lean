module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersASummary
import all ConsensusCoverage.HandReadersTrunkBFactor
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersTrunkBFactor

namespace ConsensusCoverage.HandReadersTrunkB.QuietRows

open Consensus Model Model.Node Proofs Safety ActionProfile HandReadersA HandReadersBGate SolvedWitnesses
open Lean Elab Command

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxHeartbeats 3000000
set_option maxRecDepth 16384

private abbrev sendGuard (self : NodeID) (st : NodeState) (n i : Nat) :=
  st.role = .primary ∧ n ∈ eligiblePeers st self ∧ st.sentIndex n ≤ i ∧ i ≤ st.log.length ∧
  ((messageEntries st.log (st.sentIndex n) i).all fun e => e.term == termAt st.log i) = true ∧
  (¬st.isRetiredCommitted self ∨ st.sentIndex n + 1 < i)

private abbrev grants (st : NodeState) (n : NodeID) (q : RequestVoteRequest) :=
  decide (q.term = st.currentTerm ∧ voteLogUpToDate st q ∧ (!st.primaryKnown) = true ∧
    (st.votedFor = none ∨ st.votedFor = some n))

def test (bump : Bool) (self : NodeID) (st : NodeState) (ev : Event) (_ : NodeState) : Bool :=
  let enabled := match ev with
    | .internal (.sendEntries n i) => decide (sendGuard self st n i)
    | .receive n (.requestVoteRequest q) => decide (q.term ≤ st.currentTerm ∧ ¬grants st n q = true)
    | .receive _ (.requestPreVoteRequest q) => decide (q.term ≤ st.currentTerm)
    | .internal .nominateSuccessor => !bump && decide (st.role = .primary)
    | .receive n (.appendEntriesResponse q) => !bump && decide (n ∉ eligiblePeers st self ∨
        st.role ≠ .primary ∨ q.term ≤ st.currentTerm ∧ (q.success ≠ true ∨ q.term ≠ st.currentTerm))
    | .receive n (.requestVoteResponse q) => !bump && decide (n ∉ eligiblePeers st self ∨
        q.term ≤ st.currentTerm ∧ ¬(st.role = .candidate ∧ q.term = st.currentTerm ∧ q.voteGranted = true))
    | .receive n (.requestPreVoteResponse q) => !bump && decide (n ∉ eligiblePeers st self ∨
        q.term ≤ st.currentTerm ∧ (¬(st.role = .preVoteCandidate ∧ q.term = st.currentTerm ∧ q.voteGranted = true) ∨
          ¬hasQuorum st.activeConfigurations (insert n st.preVotesGranted)))
    | .receive _ (.proposeRequestVoteRequest term) => !bump && decide (¬(term = st.currentTerm ∧ canStartElection st self))
    | _ => false
  enabled && (bump || decide (st.role ≠ .none ∧ ¬(st.role = .follower ∧ st.currentTerm = 0 ∧ st.log = [])))

def column (bump : Bool) : Classes.StepBranch := if bump then .quiet_summary_either_inr else .quiet_summary_either_inl

run_cmd liftTermElabM do
  HandReadersTrunkBFactor.query ``step_quiet_summary_either_inr `ConsensusCoverage.HandReadersTrunkB.QuietRows.QuietCall

open Elab.Term in
local elab "guard_of% " q:ident : term => do HandReadersTrunkBFactor.guardOf (←realizeGlobalConstNoOverloadWithInfo q)

private def localGuard : Bool → NodeID → NodeState → NodeState → Event → List Model.Envelope → Prop
  | true => guard_of% step_quiet_summary_either_inr
  | false => guard_of% step_quiet_summary_either_inl

private theorem query_eq [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t) (b : Bool) :
    sig c (column b) ↔ QuietCall f t c (localGuard b) := by cases b <;> rfl

private abbrev bumping (sent : List Model.Envelope) := ∃ e ∈ sent, Bumping e.payload
private abbrev activity (st post : NodeState) (ev : Event) (sent : List Model.Envelope) :=
  bumping sent → Engaged st ∨ 2 ≤ st.currentTerm ∨ (∃ n m, ev = .receive n m ∧ Bumping m ∧ m.term ≤ post.currentTerm) ∨
    ∃ entries, ev = .internal (.initAsBackup entries) ∧ 0 < entries.length ∧ isSignatureAt entries entries.length = true ∧
      post.currentTerm = termAt entries entries.length

private theorem accept (b : Bool) (self st post ev sent) (a : activity st post ev sent)
    (ok : ∀ e ∈ sent, SendOK self st ev post e) (role : post.role = st.role)
    (term : post.currentTerm = st.currentTerm) (log : post.log = st.log)
    (idx : post.commitIndex = st.commitIndex) (voted : post.votedFor = st.votedFor)
    (votes : post.votesGranted = st.votesGranted) (mi : post.matchIndex = st.matchIndex)
    (g : if b then bumping sent else Engaged post) : localGuard b self st post ev sent := by
  cases b
  · exact ⟨.inl g,g,role,term,log,idx,voted,votes,mi,a,ok⟩
  · exact ⟨.inr g,g,a,ok,role,term,log,idx,voted,votes,mi⟩

private theorem sourceGuard {self st post ev sent} (b : Bool) (p : localGuard b self st post ev sent) :
    if b then bumping sent else Engaged post := by cases b <;> exact p.2.1

private theorem impossible {self st post ev} (p : localGuard true self st post ev []) : False := by
  obtain ⟨e,h,_⟩ := sourceGuard true p
  exact List.not_mem_nil h

private def bumpSite (self : NodeID) (st : NodeState) (ev : Event) :=
  (∃ n i, ev = .internal (.sendEntries n i) ∧ sendGuard self st n i) ∨
  (∃ n q, ev = .receive n (.requestVoteRequest q) ∧ q.term ≤ st.currentTerm ∧ ¬grants st n q = true) ∨
  ∃ n q, ev = .receive n (.requestPreVoteRequest q) ∧ q.term ≤ st.currentTerm

private theorem bump_test (self st ev post) : bumpSite self st ev ↔ test true self st ev post = true := by
  cases ev with
  | internal i => cases i <;> simp [bumpSite,test] <;> grind
  | receive n m => cases m <;> simp [bumpSite,test] <;> grind

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)

private abbrev Tail (b : Bool) := HandReadersTrunkBFactor.Tail.QuietCall f t c (localGuard b)

private theorem bumpNecessary (h : Tail c true) : bumpSite c.actor c.pre c.event := by
  rcases h with h | h | h | h | h | h | h | h | h | h | h | h | h | h | h
  all_goals obtain ⟨_,_,_,_,sent,src,p⟩ := h
  case inl =>
    obtain ⟨n,i,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,g,_⟩ := src
    exact .inl ⟨n,i,ev,g⟩
  case inr.inl =>
    obtain ⟨_,_,pair,_⟩ := src
    obtain ⟨e,h,bump⟩ := sourceGuard true p
    rw [(pair.2 e h).2] at bump
    exact bump.elim
  all_goals obtain ⟨n,q,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,rest⟩ := src
  all_goals first
    | exact .inr (.inl ⟨n,q,ev,rest.1.1,rest.2.2.2.1⟩)
    | exact .inr (.inr ⟨n,q,ev,rest.1.1⟩)
    | have eq : sent = [] := by
        repeat' first | exact rest | obtain ⟨_,rest⟩ := rest
      exact (impossible (eq ▸ p)).elim

open Elab.Tactic in
local elab "choose_arm " n:num : tactic => do
  for _ in [:n.getNat] do evalTactic (←`(tactic| apply Or.inr))
  evalTactic (←`(tactic| try apply Or.inl))

private theorem supplyBumping (b : Bool) (entered : bumpSite c.actor c.pre c.event)
    (old : b = false → Engaged c.pre) : Tail c b := by
  rcases entered with ⟨n,i,ev,g⟩ | ⟨n,q,ev,le,no⟩ | ⟨n,q,ev,le⟩
  · choose_arm 0
    obtain ⟨leader,peer,lo,hi,allTerms,live⟩ := g
    have g : sendGuard c.actor c.pre n i := ⟨leader,peer,lo,hi,allTerms,live⟩
    refine ⟨_,_,_,_,_,⟨n,i,⟨c.event,⟨rfl,rfl,rfl⟩,_,ev,ev,rfl⟩,g,leader,peer,lo,hi,⟨allTerms,live⟩,
      g,rfl,rfl,rfl⟩,?_⟩
    refine accept b c.actor c.pre {c.pre with sentIndex := CCF.Function.update c.pre.sentIndex n i}
      _ _ ?_ ?_ rfl rfl rfl rfl rfl rfl rfl ?_
    · exact fun _ => .inl ⟨fun h => Role.noConfusion (leader.symm.trans h),fun h => Role.noConfusion (leader.symm.trans h.1)⟩
    · intro e member
      simp only [List.nil_append,List.append_nil,List.mem_singleton] at member
      subst e
      exact ⟨rfl,⟨(CCF.Finset.mem_erase.mp peer).1,rfl,Nat.le_trans lo hi,rfl,List.take_prefix _ _,Nat.le_refl _⟩,
        fun h => Role.noConfusion (leader.symm.trans h),.inl ⟨leader,rfl⟩⟩
    · cases b
      · exact old rfl
      · exact ⟨_,.head _,trivial⟩
  · choose_arm 6
    obtain higher | obs := observe_bumping c.pre (message := .requestVoteRequest q) trivial
    · exact (Nat.not_lt_of_ge le higher.1).elim
    let ev' := Event.receive n (.requestVoteRequest q)
    have active : ∃ source m, ev' = .receive source m ∧ Bumping m ∧ m.term ≤ c.pre.currentTerm :=
      ⟨n,_,rfl,trivial,le⟩
    refine ⟨_,_,_,_,_,⟨n,q,⟨c.event,⟨rfl,rfl,rfl⟩,_,ev,ev,rfl⟩,obs,obs.1,obs.2,no,active,rfl,rfl,rfl⟩,?_⟩
    refine accept b c.actor c.pre c.pre _ _ ?_ ?_ rfl rfl rfl rfl rfl rfl rfl ?_
    · exact fun _ => .inr (.inr (.inl active))
    · intro e member
      simp only [List.append_nil,List.mem_singleton] at member
      subst e
      exact ⟨rfl,rfl,fun h => (no h).elim⟩
    · cases b
      · exact old rfl
      · exact ⟨_,.head _,trivial⟩
  · choose_arm 9
    obtain higher | obs := observe_bumping c.pre (message := .requestPreVoteRequest q) trivial
    · exact (Nat.not_lt_of_ge le higher.1).elim
    refine ⟨_,_,_,_,_,⟨n,q,⟨c.event,⟨rfl,rfl,rfl⟩,_,ev,ev,rfl⟩,obs,obs.1,obs.2,rfl,rfl,rfl⟩,?_⟩
    refine accept b c.actor c.pre c.pre _ _ ?_ ?_ rfl rfl rfl rfl rfl rfl rfl ?_
    · exact fun _ => .inr (.inr (.inl ⟨n,_,rfl,trivial,le⟩))
    · intro e member
      simp only [List.append_nil,List.mem_singleton] at member
      subst e
      exact ⟨rfl,rfl⟩
    · cases b
      · exact old rfl
      · exact ⟨_,.head _,trivial⟩

end

def bumpReader : Exact (column true) where
  eval := SummaryRows.gated (test true)
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    let c := s.context
    apply Bool.eq_iff_iff.mpr
    rw [label_true,show holds s (.step (column true)) ↔ sig c (column true) from sig_iff _ _,query_eq,
      HandReadersTrunkBFactor.Exact.QuietCall _ _ _ _ (quiet s),SummaryRows.gated,Bool.and_eq_true,actorRead_at,
      live,and_comm,←bump_test]
    exact and_congr_left fun _ => ⟨bumpNecessary c,fun h => supplyBumping c true h (by simp)⟩

end ConsensusCoverage.HandReadersTrunkB.QuietRows
