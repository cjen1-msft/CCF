module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkBPrimary
import all ConsensusCoverage.HandReadersTrunkBCandidate
import all ConsensusCoverage.HandReadersTrunkBElect
import all ConsensusCoverage.HandReadersASummary
import all ConsensusCoverage.HandReadersTrunkBFactor
import all ConsensusCoverage.SelfQuorumCasesB
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersTrunkBFactor

namespace ConsensusCoverage.HandReadersTrunkB.Loops

open Consensus Model Model.Node Proofs Safety ActionProfile HandReadersA HandReadersBGate SolvedWitnesses
open Lean Elab Command

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxHeartbeats 3000000
set_option maxRecDepth 16384

inductive Kind where | nil | cons | done_ | yield_ | head | tail

def column : Kind → Classes.StepBranch
  | .nil => .forIn__items_nil
  | .cons => .forIn__items_cons
  | .done_ => .forIn__step_done
  | .yield_ => .forIn__step_yield
  | .head => .forIn__mem_append_inl
  | .tail => .forIn__mem_append_inr

run_cmd liftTermElabM do
  HandReadersTrunkBFactor.query ``step_forIn__items_nil `ConsensusCoverage.HandReadersTrunkB.Loops.SendLoop

open Elab.Term in
local elab "guard_of% " q:ident : term => do HandReadersTrunkBFactor.guardOf (←realizeGlobalConstNoOverloadWithInfo q)

abbrev Body := NodeID → PUnit → NodeEffect (ForInStep PUnit)
abbrev Packet := Model.Envelope → Prop
abbrev Check := List NodeID → Body → Packet → Prop

private def localGuard : Kind → Check
  | .nil => guard_of% step_forIn__items_nil
  | .cons => guard_of% step_forIn__items_cons
  | .done_ => guard_of% step_forIn__step_done
  | .yield_ => guard_of% step_forIn__step_yield
  | .head => guard_of% step_forIn__mem_append_inl
  | .tail => guard_of% step_forIn__mem_append_inr

private theorem query_eq [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t) (k : Kind) :
    sig c (column k) ↔ SendLoop f t c (localGuard k) := by cases k <;> rfl

private theorem supply (k : Kind) {self : NodeID} {items : List NodeID} {f : Body} {p : Packet}
    (other : ∀ n ∈ items, n ≠ self) (one : ∀ n (v : PUnit), n ≠ self →
      Sends (fun _ sent => ∀ e ∈ sent, p e) (f n v)) (member : ∃ e, p e) : localGuard k items f p := by
  have each n v (m : n ∈ items) := one n v (other n m)
  let n := self + 1
  have empty : ∀ e ∈ [], p e := by simp
  obtain ⟨e,h⟩ := member
  have singleton : ∀ a ∈ [e], p a := SelfQuorumCasesB.singleton h
  cases k
  · exact ⟨by simp,each⟩
  all_goals refine ⟨n,[],fun h => Sends.forIn' h,?_,?_⟩
  all_goals first | exact fun i v h => (List.mem_singleton.mp h) ▸ one n v (Nat.succ_ne_self _) | skip
  · exact each
  · exact ⟨[],empty,each⟩
  · exact ⟨[],empty,each⟩
  · exact ⟨[e],singleton,[],empty,e,.head _,.head _,each⟩
  · exact ⟨[],empty,[e],singleton,e,.head _,.head _,each⟩

private theorem broadcast (k : Kind) (self : NodeID) (st : NodeState) (msg : Node.Message) :
    localGuard k (st.activeMembers.erase self).sort (fun n _ => do
      (CCF.Capabilities.record self : Caps).send msg n
      pure (.yield .unit)) (fun e => e.source = self ∧ e.target ≠ self ∧ e.payload = msg) := by
  apply supply (self := self)
  · exact fun _ h => (CCF.Finset.mem_erase.mp (CCF.Finset.mem_sort.mp h)).1
  · intro n v other
    refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' ?_
    simp [eq,other]
  · exact ⟨⟨self,self+1,msg⟩,rfl,Nat.succ_ne_self _,rfl⟩

private theorem heartbeats (k : Kind) (self : NodeID) (st : NodeState) (items : List NodeID)
    (other : ∀ n ∈ items, n ≠ self) (atEnd : ∀ n, st.sentIndex n = st.log.length) :
    localGuard k items (fun n _ => do
      (CCF.Capabilities.record self : Caps).send (.appendEntriesRequest (makeAppendEntriesRequest st n st.log.length)) n
      pure (.yield .unit)) (AEFrom self st.currentTerm st.commitIndex st.log) := by
  apply supply k other
  · intro n v other
    refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' ?_
    intro e member
    simp only [eq,List.append_nil,List.mem_singleton] at member
    subst e
    refine ⟨rfl,other,_,rfl,rfl,?_,rfl,?_,Nat.le_refl _⟩ <;> simp [makeAppendEntriesRequest,atEnd,messageEntries]
  · exact ⟨_,SelfQuorumCasesB.beat self st⟩

private def append (self : NodeID) (st : NodeState) (ev : Event) :=
  ∃ xs, ev = .internal (.append xs) ∧ st.role = .primary ∧ ¬st.isRetiredCommitted self ∧ xs ≠ []

private def minority (self : NodeID) (st : NodeState) (ev : Event) :=
  ev = .internal (.timeout .election) ∧ canStartElection st self ∧ ¬hasQuorum st.activeConfigurations {self}

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)

private abbrev Fresh := HandReadersTrunkBFactor.Tail.ResultCall f t c (fun _ _ _ => True)
private abbrev Promoted := HandReadersTrunkBFactor.Tail.Promotion f t c (Primary.localGuard false)
private abbrev Gate := append c.actor c.pre c.event ∨ minority c.actor c.pre c.event ∨ Fresh c ∨ Promoted c

open Elab.Tactic in
local elab "pick " n:num : tactic => do
  for _ in [:n.getNat] do evalTactic (←`(tactic| apply Or.inr))
  evalTactic (←`(tactic| try apply Or.inl))

private theorem necessary (k : Kind) (h : HandReadersTrunkBFactor.Tail.SendLoop f t c (localGuard k)) : Gate c := by
  rcases h with h | h | h | h | h | h | h | h | h | h | h | h
  all_goals obtain ⟨_,_,_,entered,_⟩ := h
  all_goals first
    | obtain ⟨_,_,_,_,_,⟨xs,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,guard,_⟩,_⟩ := entered
      exact .inl ⟨xs,ev,guard⟩
    | obtain ⟨_,_,_,⟨_,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,can,_,_,q,_⟩,_⟩ := entered
      exact .inr (.inl ⟨ev,can,q⟩)
    | obtain ⟨self,_,_,⟨st,⟨before,src,_⟩,_⟩,_⟩ := entered
      apply Or.inr; apply Or.inr; apply Or.inl
      first | exact .inl ⟨self,st,before,src,trivial⟩ | exact .inr (.inl ⟨self,st,before,src,trivial⟩)
            | exact .inr (.inr ⟨self,st,before,src,trivial⟩)
    | obtain ⟨self,cand,src,_⟩ := entered
      apply Or.inr; apply Or.inr; apply Or.inr
      first | exact .inl ⟨self,cand,src,Primary.always ..⟩ | exact .inr (.inl ⟨self,cand,src,Primary.always ..⟩)
            | exact .inr (.inr (.inl ⟨self,cand,src,Primary.always ..⟩))
            | exact .inr (.inr (.inr ⟨self,cand,src,Primary.always ..⟩))

local macro "promotion " i:num k:ident self:ident cand:ident src:ident : tactic => `(tactic| {
  pick $i
  let leader := primaryState $cand
  have adv : Advance $self leader leader := .inl rfl
  have noneSent : ∀ e ∈ ([] : List Model.Envelope), e.source = $self ∧ e.payload =
      .proposeRequestVoteRequest leader.currentTerm := by simp
  refine ⟨_,_,_,⟨$self,$cand,$src,leader,[],⟨adv,noneSent⟩,adv,noneSent,rfl,rfl,rfl⟩,?_⟩
  exact heartbeats $k $self leader _ (fun _ h => (CCF.Finset.mem_erase.mp (CCF.Finset.mem_sort.mp h)).1) (fun _ => rfl) })

private theorem sufficient (k : Kind) (gate : Gate c) : HandReadersTrunkBFactor.Tail.SendLoop f t c (localGuard k) := by
  rcases gate with ⟨xs,ev,valid⟩ | ⟨ev,can,q⟩ | fresh | promote
  · pick 3
    let idx := fun (_ : NodeID) => c.pre.log.length
    let middle := {c.pre with log := c.pre.log ++ [], sentIndex := idx}
    let last := latestConfigurationMembers (configurationHistory middle.log)
    let nodes : CCF.Finset NodeID := if last = {0} then {1} else {0}
    have newNodes : nodes.Nonempty ∧ nodes ≠ last := by
      unfold nodes
      split
      · rename_i h; rw [h]; decide
      · rename_i h; exact ⟨by decide,Ne.symm h⟩
    let content := EntryContent.transaction 0 {configuration := some nodes}
    have terms : ∀ e ∈ ([] : List Entry), e.term = c.pre.currentTerm := by simp
    have beats : ∀ e ∈ ([] : List Model.Envelope), AEFrom c.actor c.pre.currentTerm c.pre.commitIndex middle.log e := by simp
    have batch : BatchState c.actor c.pre middle [] := ⟨⟨[],idx,rfl,terms⟩,beats⟩
    have start : BatchState c.actor c.pre c.pre [] := ⟨⟨[],c.pre.sentIndex,by simp,terms⟩,by simp⟩
    refine ⟨_,_,_,⟨c.actor,c.pre,middle,[],content,⟨xs,⟨c.event,⟨rfl,rfl,rfl⟩,_,ev,ev,rfl⟩,valid,valid.1,
      valid.2,valid,{content},batch,start,rfl⟩,Bool.noConfusion,by change ¬(∅ : CCF.Finset NodeID).Nonempty; decide,nodes,
      rfl,rfl,newNodes,batch.1,beats,[],⟨idx,rfl,terms⟩,idx,⟨rfl,terms⟩,rfl,terms,newNodes,beats,batch,rfl,rfl,rfl⟩,?_⟩
    apply heartbeats k c.actor
      {middle with sentIndex := fun peer => if peer ∈ (nodes \ eligiblePeers middle c.actor).erase c.actor
        then middle.log.length else idx peer}
    · exact fun _ h => (CCF.Finset.mem_erase.mp (CCF.Finset.mem_sort.mp h)).1
    · intro n; simp [middle,idx]
  · pick 4
    exact ⟨_,_,_,⟨c.actor,_,_,⟨c.pre,⟨c.event,⟨rfl,rfl,rfl⟩,_,ev,ev,rfl⟩,can,can,can,q,
      canStartElection_engaged can,rfl,rfl⟩,rfl,rfl,rfl⟩,broadcast ..⟩
  · rcases fresh with ⟨self,st,before,src,_⟩ | ⟨self,st,before,src,_⟩ | ⟨self,st,before,src,_⟩
    · pick 5
      have term : st.currentTerm = before.currentTerm := by obtain ⟨_,_,_,_,_,_,rfl⟩ := src; rfl
      exact ⟨_,_,_,⟨self,_,_,⟨st,⟨before,src,term⟩,_,[],Or.inl ⟨rfl,rfl⟩,rfl,rfl⟩,rfl,rfl,rfl⟩,broadcast ..⟩
    · pick 6
      have term : st.currentTerm = before.currentTerm := by obtain ⟨_,_,_,_,_,_,_,_,_,_,rfl⟩ := src; rfl
      exact ⟨_,_,_,⟨self,_,_,⟨st,⟨before,src,term⟩,_,[],Or.inl ⟨rfl,rfl⟩,rfl,rfl⟩,rfl,rfl,rfl⟩,broadcast ..⟩
    · pick 7
      have term : st.currentTerm = before.currentTerm := by obtain ⟨_,_,_,_,_,rfl⟩ := src; rfl
      exact ⟨_,_,_,⟨self,_,_,⟨st,⟨before,src,term⟩,_,[],Or.inl ⟨rfl,rfl⟩,rfl,rfl⟩,rfl,rfl,rfl⟩,broadcast ..⟩
  · rcases promote with ⟨self,cand,src,_⟩ | ⟨self,cand,src,_⟩ | ⟨self,cand,src,_⟩ | ⟨self,cand,src,_⟩
    · promotion 8 k self cand src
    · promotion 9 k self cand src
    · promotion 10 k self cand src
    · promotion 11 k self cand src

private def direct (self : NodeID) (st : NodeState) : Event → Bool
  | .internal (.append xs) => decide (st.role = .primary ∧ ¬st.isRetiredCommitted self ∧ xs ≠ [])
  | .internal (.timeout .election) => decide (canStartElection st self ∧ ¬hasQuorum st.activeConfigurations {self})
  | _ => false

omit [Config.InitialConfiguration] in
private theorem direct_iff (self st ev) : (append self st ev ∨ minority self st ev) ↔ direct self st ev = true := by
  cases ev with
  | receive _ _ => simp [append,minority,direct]
  | internal i =>
    cases i
    case timeout k => cases k <;> simp [append,minority,direct,canStartElection,hasQuorum] <;> grind
    all_goals simp [append,minority,direct]

def test (self : NodeID) (st : NodeState) (ev : Event) (post : NodeState) :=
  direct self st ev || (Candidate.test false self st ev post || Primary.test self st ev post)

private theorem gate_iff : Gate c ↔ test c.actor c.pre c.event c.post = true := by
  have fresh : Fresh c ↔ Candidate.test false c.actor c.pre c.event c.post = true :=
    (Candidate.interpret c false (fun _ _ _ => True) (by simp)).trans (Candidate.guard_iff ..)
  have promoted : Promoted c ↔ Primary.test c.actor c.pre c.event c.post = true := by
    rw [Promoted,Primary.tail_iff,Primary.test,Bool.and_eq_true,Bool.or_eq_true,decide_eq_true_eq,
      ←Elect.guard_iff,←Candidate.guard_iff]
  rw [Gate,test,Bool.or_eq_true,Bool.or_eq_true,←direct_iff,←fresh,←promoted,or_assoc]
end

def exactReader (k : Kind) : Exact (column k) where
  eval := SummaryRows.gated test
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    let c := s.context
    apply Bool.eq_iff_iff.mpr
    rw [label_true,show holds s (.step (column k)) ↔ sig c (column k) from sig_iff _ _,query_eq,
      HandReadersTrunkBFactor.Exact.SendLoop _ _ _ _ (quiet s),
      show HandReadersTrunkBFactor.Tail.SendLoop _ _ c (localGuard k) ↔ Gate c from ⟨necessary c k,sufficient c k⟩,
      gate_iff,SummaryRows.gated,Bool.and_eq_true,actorRead_at,live,and_comm]

end ConsensusCoverage.HandReadersTrunkB.Loops
