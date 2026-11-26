module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkCMatchRoute
import all ConsensusCoverage.HandReadersTrunkCExtension
import all ConsensusCoverage.HandReadersTrunkABatch
import all ConsensusCoverage.HandReadersTrunkAFactor
import all ConsensusCoverage.HandReadersASummary
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.AdvanceArmsB
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersTrunkC.Match

open CCF Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses
open HandReadersA ActionProfile

set_option maxRecDepth 16384
set_option maxHeartbeats 1400000

def ack (st : NodeState) (src : NodeID) (r : AppendEntriesResponse) :=
  {st with matchIndex := CCF.Function.update st.matchIndex src (max (st.matchIndex src) r.lastLogIndex)}

private abbrev Grow (k : Bool) (n : NodeID) (st : NodeState) :=
  k = true → st.commitIndex < highestCommittableIndex st n

def test (k : Bool) (n : NodeID) (st : NodeState) (ev : Event) (_ : NodeState) := match ev with
  | .internal (.append _) => decide (Grow k n (AdvanceArmsB.appended st))
  | .receive src (.appendEntriesResponse r) => decide (src ∈ eligiblePeers st n ∧ st.role = Role.primary ∧
      r.success = true ∧ r.term = st.currentTerm ∧ Grow k n (ack st src r))
  | _ => false

def column (k : Bool) : Classes.StepBranch := if k then .matchIndex_advance_inr else .matchIndex_advance_inl

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private abbrev Tail (k : Bool) := if k then HandReadersBFactor.Tail.step_matchIndex_advance_inr f t c
  else HandReadersBFactor.Tail.step_matchIndex_advance_inl f t c

private theorem upper (k : Bool) : Tail c k → test k c.actor c.pre c.event c.post := by
  cases k <;> rintro (batch | response)
  case false.inl =>
    obtain ⟨_,_,⟨_,xs,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,_⟩,_⟩ := batch
    rw [show c.event = .internal (.append xs) from ev]; simp [test,Grow]
  case true.inl =>
    obtain ⟨_,m,_,⟨_,xs,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,_,primary,_,_,app,_,batch,_,_,_,_,_,_,_,_,_,_,_,_,
      _,_,_,_,_,_,_,_,eq⟩,strict,_⟩ := batch
    subst m
    rw [show c.event = .internal (.append xs) from ev]
    obtain ⟨⟨es,si,eq,_⟩,_⟩ := batch
    exact decide_eq_true fun _ => Extension.normalize c primary es si app eq (strict.2.2.2.2.2.2.2.1 ▸ strict.2.2.2.2.2.2.1)
  case false.inr =>
    obtain ⟨_,_,⟨_,src,r,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,pass,_,_,_,_,yes,stamp,_,_,_,_,_,primary,_⟩,_⟩ := response
    rw [show c.event = .receive src (.appendEntriesResponse r) from ev]
    exact decide_eq_true ⟨Classical.byContradiction (fun no => pass ⟨trivial,no⟩),primary,yes,stamp,by simp [Grow]⟩
  case true.inr =>
    obtain ⟨_,m,_,⟨_,src,r,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,pass,_,_,_,_,yes,stamp,_,_,_,_,_,primary,_,_,_,eq⟩,strict,_⟩ := response
    subst m
    rw [show c.event = .receive src (.appendEntriesResponse r) from ev]
    exact decide_eq_true ⟨Classical.byContradiction (fun no => pass ⟨trivial,no⟩),primary,yes,stamp,
      fun _ => strict.2.2.2.2.2.2.2.1 ▸ strict.2.2.2.2.2.2.1⟩

private theorem batchSite {xs} (ev : c.event = .internal (.append xs)) (k : Bool)
    (grow : Grow k c.actor (AdvanceArmsB.appended c.pre)) : Tail c k := by
  let m := AdvanceArmsB.appended c.pre
  let s := HandReadersTrunkA.Batch.seed c ev
  let es : List Entry := [⟨c.pre.currentTerm,.signature⟩]
  have terms : ∀ x ∈ es, x.term = c.pre.currentTerm := by simp [es]
  have batch : BatchState c.actor c.pre m [] := ⟨⟨es,c.pre.sentIndex,rfl,terms⟩,by simp⟩
  have empty : ∀ a ∈ ([] : List Model.Envelope), a.source = c.actor ∧ a.payload = .proposeRequestVoteRequest m.currentTerm := by simp
  let bumped := {m with commitIndex := highestCommittableIndex m c.actor}
  cases k
  · have a : Advance c.actor m m := .inl rfl
    left
    refine ⟨c.actor,m,⟨c.pre,xs,⟨c.event,⟨rfl,rfl,rfl⟩,_,ev,ev,rfl⟩,s.guards,s.guards.1,s.guards.2,s.guards,
      m,[],batch,[],⟨a,empty⟩,a,empty,batch.1,batch.2,es,⟨_,rfl,terms⟩,_,⟨rfl,terms⟩,rfl,terms,
      s.guards.1,s.guards.1,rfl,BatchArmsB.start s,rfl,rfl,.inl s.guards.1,Nat.le_refl _,rfl⟩,a⟩
  · have a : Advance c.actor m bumped := .inr ⟨rfl,rfl,rfl,rfl,rfl,rfl,grow rfl,rfl,.inl rfl⟩
    left
    refine ⟨c.actor,m,bumped,⟨c.pre,xs,⟨c.event,⟨rfl,rfl,rfl⟩,_,ev,ev,rfl⟩,s.guards,s.guards.1,s.guards.2,s.guards,
      m,[],batch,[],⟨a,empty⟩,a,empty,batch.1,batch.2,es,⟨_,rfl,terms⟩,_,⟨rfl,terms⟩,rfl,terms,
      s.guards.1,s.guards.1,rfl,BatchArmsB.start s,rfl,rfl,.inl s.guards.1,Nat.le_of_lt (grow rfl),rfl⟩,
      ⟨rfl,rfl,rfl,rfl,rfl,rfl,grow rfl,rfl,.inl rfl⟩,a⟩

private theorem ackSite {src r} (ev : c.event = .receive src (.appendEntriesResponse r)) (k : Bool)
    (peer : src ∈ eligiblePeers c.pre c.actor) (leader : c.pre.role = .primary)
    (yes : r.success = true) (stamp : r.term = c.pre.currentTerm) (grow : Grow k c.actor (ack c.pre src r)) : Tail c k := by
  let m := ack c.pre src r
  let bumped := {m with commitIndex := highestCommittableIndex m c.actor}
  have stable := (observe_response c.pre r).resolve_left (fun h => (Nat.lt_irrefl _ (stamp ▸ h.2.1)))
  have pass : ¬(True ∧ ¬src ∈ eligiblePeers c.pre c.actor) := fun h => h.2 peer
  have primary : ¬(c.pre.role != Role.primary) = true := by simp [leader]
  have empty : ∀ a ∈ ([] : List Model.Envelope), a.source = c.actor ∧ a.payload = .proposeRequestVoteRequest m.currentTerm := by simp
  have no : c.pre.role ≠ .candidate := by simp [leader]
  have quiet := fun (st : NodeState) hr ht hl hc hv hvs hm => quiet_summary
    (self := c.actor) (before := c.pre) (after := st) (event := .receive src (.appendEntriesResponse r))
    (sent := []) hr ht hl hc hv hvs hm no_bumping_sends (by simp)
  cases k
  · have a : Advance c.actor m m := .inl rfl
    right
    exact ⟨c.actor,m,⟨c.pre,src,r,⟨c.event,⟨rfl,rfl,rfl⟩,_,ev,ev,rfl⟩,pass,stable,stable.1,stable.2,
      primary,yes,stamp,[],⟨a,empty⟩,a,empty,leader,leader,rfl,quiet,no,rfl⟩,a⟩
  · have a : Advance c.actor m bumped := .inr ⟨rfl,rfl,rfl,rfl,rfl,rfl,grow rfl,rfl,.inl rfl⟩
    right
    exact ⟨c.actor,m,bumped,⟨c.pre,src,r,⟨c.event,⟨rfl,rfl,rfl⟩,_,ev,ev,rfl⟩,pass,stable,stable.1,stable.2,
      primary,yes,stamp,[],⟨a,empty⟩,a,empty,leader,leader,rfl,quiet,no,rfl⟩,
      ⟨rfl,rfl,rfl,rfl,rfl,rfl,grow rfl,rfl,.inl rfl⟩,a⟩

private theorem tail_iff (k : Bool) : Tail c k ↔ test k c.actor c.pre c.event c.post := by
  refine ⟨upper c k,?_⟩
  intro h
  unfold test at h
  split at h
  · exact batchSite c (by assumption) k (of_decide_eq_true h)
  · obtain ⟨p,r,s,t,g⟩ := of_decide_eq_true h
    exact ackSite c (by assumption) k p r s t g
  · contradiction
end

def reader (k : Bool) : Exact (column k) where
  eval := SummaryRows.gated (test k)
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff,SummaryRows.gated,Bool.and_eq_true,actorRead_at,HandReadersBGate.live,and_comm,←tail_iff]
    cases k
    · change step_matchIndex_advance_inl _ _ _ ↔ _
      rw [HandReadersTrunkA.Factor.Split.step_matchIndex_advance_inl_iff]
      exact HandReadersBFactor.Exact.step_matchIndex_advance_inl _ _ _ (HandReadersBGate.quiet s)
    · change step_matchIndex_advance_inr _ _ _ ↔ _
      rw [HandReadersTrunkA.Factor.Split.step_matchIndex_advance_inr_iff]
      exact HandReadersBFactor.Exact.step_matchIndex_advance_inr _ _ _ (HandReadersBGate.quiet s)

end ConsensusCoverage.HandReadersTrunkC.Match
