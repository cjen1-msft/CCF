module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkBQuiet
import all ConsensusCoverage.HandReadersASummary
import all ConsensusCoverage.HandReadersTrunkBFactor
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import Lean

namespace ConsensusCoverage.HandReadersTrunkB.QuietRows

open Consensus Model Model.Node Proofs Safety ActionProfile HandReadersA HandReadersBGate SolvedWitnesses
open Lean

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxHeartbeats 500000
set_option maxRecDepth 16384

private def silent (self : NodeID) (st : NodeState) : Event → Prop
  | .internal .nominateSuccessor => st.role = .primary
  | .receive n (.appendEntriesResponse q) => n ∉ eligiblePeers st self ∨ st.role ≠ .primary ∨
      q.term ≤ st.currentTerm ∧ (q.success ≠ true ∨ q.term ≠ st.currentTerm)
  | .receive n (.requestVoteResponse q) => n ∉ eligiblePeers st self ∨ q.term ≤ st.currentTerm ∧
      ¬(st.role = .candidate ∧ q.term = st.currentTerm ∧ q.voteGranted = true)
  | .receive n (.requestPreVoteResponse q) => n ∉ eligiblePeers st self ∨ q.term ≤ st.currentTerm ∧
      (¬(st.role = .preVoteCandidate ∧ q.term = st.currentTerm ∧ q.voteGranted = true) ∨
        ¬hasQuorum st.activeConfigurations (insert n st.preVotesGranted))
  | .receive _ (.proposeRequestVoteRequest term) => ¬(term = st.currentTerm ∧ canStartElection st self)
  | _ => False

private theorem engaged_test (self st ev post) :
    ((bumpSite self st ev ∨ silent self st ev) ∧ Engaged st) ↔ test false self st ev post = true := by
  cases ev with
  | internal i => cases i <;> simp [test,bumpSite,silent,Engaged] <;> grind
  | receive n m => cases m <;> simp [test,bumpSite,silent,Engaged] <;> grind

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)

private theorem engagedNecessary (h : Tail c false) :
    (bumpSite c.actor c.pre c.event ∨ silent c.actor c.pre c.event) ∧ Engaged c.pre := by
  rcases h with h | h | h | h | h | h | h | h | h | h | h | h | h | h | h
  all_goals obtain ⟨_,_,_,_,_,src,p⟩ := h; have eng := sourceGuard false p
  case inl =>
    obtain ⟨n,i,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,g,_,_,_,_,_,_,rfl,_⟩ := src
    exact ⟨.inl (.inl ⟨n,i,ev,g⟩),eng⟩
  case inr.inl =>
    obtain ⟨_,⟨_,⟨rfl,rfl,rfl⟩,ev⟩,pair,_,_,_,_,_,rfl,rfl,_⟩ := src
    exact ⟨.inr (by change silent _ _ c.tr.event; rw [ev]; exact pair.1),eng⟩
  all_goals obtain ⟨n,q,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,rest⟩ := src
  all_goals first
    | obtain ⟨obs,_,_,no,_,rfl,_⟩ := rest
      exact ⟨.inl (.inr (.inl ⟨n,q,ev,obs.1,no⟩)),eng⟩
    | obtain ⟨obs,_,_,rfl,_⟩ := rest
      exact ⟨.inl (.inr (.inr ⟨n,q,ev,obs.1⟩)),eng⟩
    | refine ⟨.inr ?_,?_⟩
      · change silent _ _ c.tr.event; rw [ev]; unfold silent
        first
        | exact .inl rest.1
        | exact .inr (.inl (by simpa using rest.2.2.2.2.1))
        | exact .inr (.inr ⟨rest.2.1.1 (by grind),.inr rest.2.2.2.2.2.2.1⟩)
        | exact .inr (.inr ⟨rest.2.1.1 (by grind),.inl rest.2.2.2.2.2.1⟩)
        | exact .inr ⟨rest.2.1.1,rest.2.2.2.2.1⟩
        | exact .inr ⟨rest.2.1.1,.inr rest.2.2.2.2.2.1⟩
        | exact .inr ⟨rest.2.1.1,.inl rest.2.2.2.2.1⟩
        | exact Bool.noConfusion rest.1.1
        | exact rest.2.1
      · change Engaged _ at eng
        repeat' first | exact eng | (rw [rest.1] at eng; exact eng) | obtain ⟨_,rest⟩ := rest

open Elab.Tactic in
local elab "choose_arm " n:num : tactic => do
  for _ in [:n.getNat] do evalTactic (←`(tactic| apply Or.inr))
  evalTactic (←`(tactic| try apply Or.inl))

omit [Config.InitialConfiguration] in
private theorem emptyGuard {self st post ev} (eng : Engaged post) (role : post.role = st.role)
    (term : post.currentTerm = st.currentTerm) (log : post.log = st.log) (idx : post.commitIndex = st.commitIndex)
    (voted : post.votedFor = st.votedFor) (votes : post.votesGranted = st.votesGranted) (mi : post.matchIndex = st.matchIndex) :
    localGuard false self st post ev [] :=
  accept false _ _ _ _ [] (fun ⟨_,m,_⟩ => (List.not_mem_nil m).elim) (by simp) role term log idx voted votes mi eng

private theorem silentSupply (ev : Event) (he : c.event = ev) (atSite : silent c.actor c.pre ev) (eng : Engaged c.pre) :
    Tail c false := by
  cases ev with
  | internal i =>
    cases i <;> try exact atSite.elim
    choose_arm 1
    have pkts : ∀ e ∈ ([] : List Model.Envelope), e.source = c.actor ∧
        e.payload = .proposeRequestVoteRequest c.pre.currentTerm := by simp
    have role : c.pre.role = .primary := atSite
    exact ⟨_,_,_,_,[],⟨c.pre,⟨c.event,⟨rfl,rfl,rfl⟩,he⟩,⟨role,pkts⟩,role,pkts,⟨role,pkts⟩,role,pkts,
      rfl,rfl,rfl⟩,emptyGuard eng rfl rfl rfl rfl rfl rfl rfl⟩
  | receive n m =>
    cases m <;> try exact atSite.elim
    case appendEntriesResponse q =>
      by_cases peer : n ∈ eligiblePeers c.pre c.actor
      · have pass : ¬(True ∧ ¬n ∈ eligiblePeers c.pre c.actor) := fun h => h.2 peer
        obtain raised | obs := observe_response c.pre q
        · rcases atSite with np | nr | ⟨le,_⟩
          · exact (np peer).elim
          · exact (nr raised.1).elim
          · exact (Nat.not_lt_of_ge le raised.2.1).elim
        by_cases leader : c.pre.role = .primary
        · have nr : ¬(c.pre.role != .primary) = true := by simp [leader]
          by_cases ok : q.success = true
          · have older : q.term ≠ c.pre.currentTerm := by
              rcases atSite with np | nol | ⟨_,fails | old⟩
              · exact (np peer).elim
              · exact (nol leader).elim
              · exact (fails ok).elim
              · exact old
            choose_arm 4
            exact ⟨_,_,_,_,_,⟨n,q,⟨c.event,⟨rfl,rfl,rfl⟩,_,he,he,rfl⟩,pass,obs,obs.1,obs.2,nr,ok,older,
              rfl,rfl,rfl⟩,emptyGuard eng rfl rfl rfl rfl rfl rfl rfl⟩
          · choose_arm 5
            refine ⟨_,_,_,_,_,⟨n,q,⟨c.event,⟨rfl,rfl,rfl⟩,_,he,he,rfl⟩,pass,obs,obs.1,obs.2,nr,ok,
              rfl,rfl,rfl⟩,?_⟩
            apply emptyGuard <;> first | exact eng | rfl
        · choose_arm 3
          exact ⟨_,_,_,_,_,⟨n,q,⟨c.event,⟨rfl,rfl,rfl⟩,_,he,he,rfl⟩,pass,obs,obs.1,obs.2,
            by simpa using leader,rfl,rfl,rfl⟩,emptyGuard eng rfl rfl rfl rfl rfl rfl rfl⟩
      · choose_arm 2
        exact ⟨_,_,_,_,_,⟨n,q,⟨c.event,⟨rfl,rfl,rfl⟩,_,he,he,rfl⟩,peer,rfl,rfl,rfl⟩,
          emptyGuard eng rfl rfl rfl rfl rfl rfl rfl⟩
    case requestVoteResponse q =>
      rcases atSite with np | ⟨le,no⟩
      · choose_arm 7
        exact ⟨_,_,_,_,_,⟨n,q,⟨c.event,⟨rfl,rfl,rfl⟩,_,he,he,rfl⟩,np,rfl,rfl,rfl⟩,
          emptyGuard eng rfl rfl rfl rfl rfl rfl rfl⟩
      · by_cases peer : n ∈ eligiblePeers c.pre c.actor
        · obtain higher | obs := observe_bumping c.pre (message := .requestVoteResponse q) trivial
          · exact (Nat.not_lt_of_ge le higher.1).elim
          choose_arm 8
          exact ⟨_,_,_,_,_,⟨n,q,⟨c.event,⟨rfl,rfl,rfl⟩,_,he,he,rfl⟩,fun h => h.2 peer,obs,obs.1,obs.2,no,
            rfl,rfl,rfl⟩,emptyGuard eng rfl rfl rfl rfl rfl rfl rfl⟩
        · choose_arm 7
          exact ⟨_,_,_,_,_,⟨n,q,⟨c.event,⟨rfl,rfl,rfl⟩,_,he,he,rfl⟩,peer,rfl,rfl,rfl⟩,
            emptyGuard eng rfl rfl rfl rfl rfl rfl rfl⟩
    case requestPreVoteResponse q =>
      by_cases peer : n ∈ eligiblePeers c.pre c.actor
      · obtain ⟨le,silent⟩ := atSite.resolve_left (fun h => h peer)
        obtain higher | obs := observe_bumping c.pre (message := .requestPreVoteResponse q) trivial
        · exact (Nat.not_lt_of_ge le higher.1).elim
        by_cases granted : c.pre.role = .preVoteCandidate ∧ q.term = c.pre.currentTerm ∧ q.voteGranted = true
        · choose_arm 11
          have noQ := silent.resolve_left (fun h => h granted)
          refine ⟨_,_,_,_,_,⟨n,q,⟨c.event,⟨rfl,rfl,rfl⟩,_,he,he,rfl⟩,fun h => h.2 peer,obs,obs.1,obs.2,
            granted,noQ,eng,rfl,rfl,rfl⟩,?_⟩
          apply emptyGuard <;> first | exact eng | rfl
        · choose_arm 12
          exact ⟨_,_,_,_,_,⟨n,q,⟨c.event,⟨rfl,rfl,rfl⟩,_,he,he,rfl⟩,fun h => h.2 peer,obs,obs.1,obs.2,
            granted,rfl,rfl,rfl⟩,emptyGuard eng rfl rfl rfl rfl rfl rfl rfl⟩
      · choose_arm 10
        exact ⟨_,_,_,_,_,⟨n,q,⟨c.event,⟨rfl,rfl,rfl⟩,_,he,he,rfl⟩,peer,rfl,rfl,rfl⟩,
          emptyGuard eng rfl rfl rfl rfl rfl rfl rfl⟩
    case proposeRequestVoteRequest term =>
      choose_arm 14
      exact ⟨_,_,_,_,_,⟨n,term,⟨c.event,⟨rfl,rfl,rfl⟩,_,he,he,rfl⟩,fun h => Bool.noConfusion h.1,atSite,
        rfl,rfl,rfl⟩,emptyGuard eng rfl rfl rfl rfl rfl rfl rfl⟩
end

def engagedReader : Exact (column false) where
  eval := SummaryRows.gated (test false)
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    let c := s.context
    apply Bool.eq_iff_iff.mpr
    rw [label_true,show holds s (.step (column false)) ↔ sig c (column false) from sig_iff _ _,query_eq,
      HandReadersTrunkBFactor.Exact.QuietCall _ _ _ _ (quiet s),SummaryRows.gated,Bool.and_eq_true,actorRead_at,
      live,and_comm,←engaged_test]
    apply and_congr_left
    intro _
    exact ⟨engagedNecessary c,fun ⟨entered,eng⟩ => entered.elim
      (fun h => supplyBumping c false h (fun _ => eng)) (fun h => silentSupply c _ rfl h eng)⟩

end ConsensusCoverage.HandReadersTrunkB.QuietRows
