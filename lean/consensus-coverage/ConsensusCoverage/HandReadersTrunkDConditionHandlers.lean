module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkDConditionQueries
import all ConsensusCoverage.HandReadersTrunkDConditionProof
import all ConsensusCoverage.HandReadersOtherConditionBase
import all ConsensusCoverage.AssistReplyA
import all ConsensusCoverage.AssistReplyBranchesA
import all ConsensusCoverage.AssistConflictA
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersTrunkD.Condition

open CCF Consensus Model Model.Node Proofs Safety
open HandReadersOther.Condition (inner reject timeQuorum)
open AssistReplyA (prepared observed)
set_option maxRecDepth 8192
set_option maxHeartbeats 700000

private abbrev blocked (n : NodeID) (s : NodeState) (src : NodeID) := src ∉ eligiblePeers s n
private abbrev remote (b : Bool) (n : NodeID) (s : NodeState) (src : NodeID) (m : Message) :=
  if b then (blocked n s src ∨ inner n s m = true) else ¬blocked n s src

private theorem pickPeer (b : Bool) (n : NodeID) (s : NodeState) (src : NodeID) (m : Message)
    (h : Picks b (True ∧ blocked n s src)) : remote b n s src m := by
  cases b
  · exact fun block=>h ⟨trivial,block⟩
  · exact .inl h.2

private theorem ackQuiet (self : NodeID) (before : NodeState) (src : NodeID) (r : AppendEntriesResponse)
    (st : NodeState) (hr : st.role = before.role) (ht : st.currentTerm = before.currentTerm)
    (hl : st.log = before.log) (hc : st.commitIndex = before.commitIndex) (hv : st.votedFor = before.votedFor)
    (hvs : st.votesGranted = before.votesGranted) (hm : st.matchIndex = before.matchIndex) :
    Summary self before (.receive src (.appendEntriesResponse r)) st [] := quiet_summary
    (self := self) (before := before) (after := st) (event := .receive src (.appendEntriesResponse r))
    (sent := []) hr ht hl hc hv hvs hm no_bumping_sends (by simp)

theorem ackGuard (b : Bool) (n : NodeID) (s : NodeState) (src : NodeID) (r : AppendEntriesResponse) :
    Family.Ack.guard b n s src r ↔ remote b n s src (.appendEntriesResponse r) := by
  constructor
  · rintro (⟨pass,obs,_,_,_,_,pick⟩ | ⟨pass,obs,_,_,_,ok,_,_⟩ |
      ⟨pass,obs,_,_,_,_,pick⟩ | ⟨pass,obs,_,_,_,pick⟩ | pick)
    · cases b <;> simp_all [remote,blocked,inner,Picks,bumpedState]
    · cases b <;> simp_all [remote,blocked,inner]
    · cases b <;> simp_all [remote,blocked,inner,Picks]
    · cases b <;> simp_all [remote,blocked,inner,Picks]
    · exact pickPeer _ _ _ _ _ pick
  · intro yes
    by_cases block : blocked n s src
    · cases b
      · exact (yes block).elim
      · exact .inr (.inr (.inr (.inr ⟨trivial,block⟩)))
    have pass : ¬(True ∧ blocked n s src) := fun h=>block h.2
    cases b
    · exact .inr (.inr (.inr (.inr pass)))
    · have use : inner n s (.appendEntriesResponse r) := yes.resolve_left block
      obtain raised | obs := observe_response s r
      · exact .inl ⟨pass,raised,raised.1,raised.2,raised.2.1,raised.2.2,by simp [Picks,bumpedState]⟩
      · simp only [inner,obs.2,decide_eq_true_eq] at use
        have quiet := ackQuiet n s src r
        by_cases pr : s.role = .primary
        · exact .inr (.inr (.inl ⟨pass,obs,obs.1,obs.2,by simp [pr],quiet,use.resolve_left (not_not_intro pr)⟩))
        · exact .inr (.inr (.inr (.inl ⟨pass,obs,obs.1,obs.2,quiet,by simp [Picks,pr]⟩)))

theorem voteGuard (b : Bool) (n : NodeID) (s : NodeState) (src : NodeID) (r : RequestVoteResponse) :
    Family.Vote.guard b n s src r ↔ remote b n s src (.requestVoteResponse r) := by
  constructor
  · rintro (⟨pass,obs,_,_,pick⟩ | ⟨pass,obs,_,_,pick⟩ | pick)
    · cases b <;> simp_all [remote,blocked,Picks,bumpedState]
    · cases b <;> simp_all [remote,blocked,inner,Picks]
    · exact pickPeer _ _ _ _ _ pick
  · intro yes
    by_cases block : blocked n s src
    · cases b
      · exact (yes block).elim
      · exact .inr (.inr ⟨trivial,block⟩)
    have pass : ¬(True ∧ blocked n s src) := fun h=>block h.2
    cases b
    · exact .inr (.inr pass)
    · have use := yes.resolve_left block
      obtain rise | obs := observe_bumping s (message := .requestVoteResponse r) trivial
      · simp [inner,rise.2,bumpedState] at use
      · exact .inr (.inl ⟨pass,obs,obs.1,obs.2,by simpa [Picks,inner,obs.2] using use⟩)

theorem preVoteGuard (b : Bool) (n : NodeID) (s : NodeState) (src : NodeID) (r : RequestVoteResponse) :
    Family.PreVote.guard b n s src r ↔ remote b n s src (.requestPreVoteResponse r) := by
  constructor
  · rintro (⟨pass,obs,_,_,pick⟩ | ⟨pass,obs,_,_,win,_,_⟩ | ⟨pass,obs,_,_,pick⟩ | pick)
    · cases b <;> simp_all [remote,blocked,Picks,bumpedState]
    · cases b <;> simp_all [remote,blocked,inner]
    · cases b <;> simp_all [remote,blocked,inner,Picks]
    · exact pickPeer _ _ _ _ _ pick
  · intro yes
    by_cases block : blocked n s src
    · cases b
      · exact (yes block).elim
      · exact .inr (.inr (.inr ⟨trivial,block⟩))
    have pass : ¬(True ∧ blocked n s src) := fun h=>block h.2
    cases b
    · exact .inr (.inr (.inr pass))
    · have use := yes.resolve_left block
      obtain rise | obs := observe_bumping s (message := .requestPreVoteResponse r) trivial
      · simp [inner,rise.2,bumpedState] at use
      · exact .inr (.inr (.inl ⟨pass,obs,obs.1,obs.2,by simpa [Picks,inner,obs.2] using use⟩))

theorem proposalGuard (b : Bool) (n : NodeID) (s : NodeState) (src : NodeID) (k : Nat) :
    Family.Proposal.guard b n s src k ↔ (b = true → k = s.currentTerm ∧ canStartElection s n) := by
  cases b <;> simp [Family.Proposal.guard,Picks]

theorem timeoutGuard (b : Bool) (n : NodeID) (s : NodeState) :
    Family.Timeout.guard b n s ↔ canStartElection s n ∧ Picks b (timeQuorum n s) := by
  exact ⟨fun h=>⟨h.1,h.2.2.2.2⟩,fun ⟨can,q⟩=>⟨can,can,can,canStartElection_engaged can,q⟩⟩

private abbrev nack (z : NodeState) (r : AppendEntriesRequest) :=
  r.term < (prepared z r).currentTerm ∨ termAt (prepared z r).log r.prevLogIndex = 0
private abbrev req (b : Bool) (z : NodeState) (r : AppendEntriesRequest) :=
  if b then reject z r ∨ AssistConflictA.Bad z r else ¬reject z r ∨ ¬nack z r

private theorem sendNack (n src : NodeID) (z : NodeState) (r : AppendEntriesRequest)
    (payload : Message) (h : ∃ p, payload = .appendEntriesResponse p ∧ p.success = false) :
    Sends (AEReply n src z r) (do (Capabilities.record n).send payload src; pure (prepared z r) : NodeEffect _) := by
  have f := AssistReplyBranchesA.fields z r
  refine Sends.bind' (Sends.send _ _ _) fun _ sent eq=>Sends.pure' ?_
  subst sent
  refine AssistConflictA.common n src z r _ _ (.inl ⟨f.log,f.commit,?_⟩) rfl rfl rfl (.inl rfl) (fun _=>rfl)
  intro e mem
  simp at mem
  subst e
  exact ⟨rfl,h⟩

theorem requestGuard (b : Bool) (n src : NodeID) (z : NodeState) (r : AppendEntriesRequest) (lo : r.term ≤ z.currentTerm) :
    Family.Request.guard b n src z r ↔ req b z r := by
  have p := AssistReplyBranchesA.fields z r
  have com := AssistConflictA.common n src z r
  constructor
  · intro h
    rcases h with h | h | h
    all_goals
      have top := h.1
      repeat' (change _ ∧ _ at h; obtain ⟨_,h⟩ := h)
      cases b <;> first | exact .inl top | exact .inl h | exact .inr h
  · intro yes
    by_cases rejected : reject z r
    · cases b
      · exact .inl ⟨rejected,lo,p.term,p.log,p.commit,p.vote,p.match_,p.role,p.cand,p.stays,com,
          sendNack n src z r,yes.resolve_left (not_not_intro rejected)⟩
      · exact .inr (.inr ⟨lo,p.term,p.log,p.commit,p.vote,p.match_,p.role,p.cand,p.stays,com,rejected⟩)
    · cases b
      · exact .inr (.inr ⟨lo,p.term,p.log,p.commit,p.vote,p.match_,p.role,p.cand,p.stays,com,rejected⟩)
      · have same : r.term = z.currentTerm := Nat.le_antisymm lo (by rw [←p.term]; exact Nat.le_of_not_gt (fun lt=>rejected (.inl lt)))
        exact .inr (.inl ⟨rejected,lo,p.term,p.log,p.commit,p.vote,p.match_,p.role,p.cand,p.stays,com,
          same,p.stays same,yes.resolve_left rejected⟩)

end ConsensusCoverage.HandReadersTrunkD.Condition
