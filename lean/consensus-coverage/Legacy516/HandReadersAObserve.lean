module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersABase
import all ConsensusCoverage.DeepObserveCases
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.ReadersAtoms
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersA.Observe

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses ActionProfile

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192

inductive Branch where | call | primary | backup | higher | stable | other

def eligible (self : NodeID) (pre : NodeState) (n : NodeID) : Message → Bool
  | .appendEntriesResponse _ | .requestVoteResponse _ | .requestPreVoteResponse _ =>
    decide (n ∈ eligiblePeers pre self)
  | _ => true

def test (k : Branch) (self : NodeID) (pre : NodeState) (event : Event) : Bool :=
  match event with
  | .internal _ => false
  | .receive n m =>
    eligible self pre n m && match k with
      | .call => true
      | .primary => decide (pre.role = .primary)
      | .backup => decide (pre.role ≠ .primary)
      | .other => match m with
        | .proposeRequestVoteRequest _ | .appendEntriesResponse _ => false
        | _ => true
      | .higher | .stable =>
        let compares := match m with
          | .proposeRequestVoteRequest _ => false
          | .appendEntriesResponse _ => decide (pre.role = .primary)
          | _ => true
        compares && (decide (pre.currentTerm < m.term) == (match k with | .higher => true | _ => false))

def reader (k : Branch) : Reader := fun cfg before act after past =>
  (GuardedDomain.ofAction cfg before after past act).any fun v =>
    v.changed && test k v.actor v.pre (ReadersAtoms.eventOf act)

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

abbrev Receive (self : NodeID) (st : NodeState) (n : NodeID) (m : Message) :=
  (reach% step_observeTerm_log_message_other[0,0]) f t c self st n m

theorem receive_iff {self st n m} : Receive c self st n m ↔
    ¬ Now f c.actor c.post ∧ self = c.actor ∧ st = c.pre ∧ c.event = .receive n m := by
  constructor
  · rintro ⟨e,_,_,⟨_,_,_,fresh,hs,ht,he,_,_⟩,ev,_⟩
    exact ⟨fresh,hs,ht,he.symm.trans ev⟩
  · rintro ⟨fresh,rfl,rfl,ev⟩
    exact ⟨c.event,c.post,c.tr.outputs,⟨c.post_now,c.post_now,c.post_now,fresh,rfl,rfl,rfl,rfl,rfl⟩,
      ev,ev ▸ c.tr.ran,c.inv.frontier _ _ c.pre_now,c.tr.ran⟩

private theorem recv4 {src msg} (ev : c.event = .receive src msg)
    (P : NodeID → NodeState → NodeID → Message → Prop) :
    (∃ a st n m, Receive c a st n m ∧ P a st n m) ↔
      ¬ Now f c.actor c.post ∧ P c.actor c.pre src msg := by
  constructor
  · rintro ⟨a,st,n,m,rec,h⟩
    obtain ⟨fresh,rfl,rfl,e⟩ := (receive_iff c).mp rec
    cases ev.symm.trans e
    exact ⟨fresh,h⟩
  · rintro ⟨fresh,h⟩
    exact ⟨_,_,_,_,(receive_iff c).mpr ⟨fresh,rfl,rfl,ev⟩,h⟩

private theorem recv3 {src msg} (ev : c.event = .receive src msg) (st : NodeState)
    (P : NodeID → NodeID → Message → Prop) :
    (∃ a n m, Receive c a st n m ∧ P a n m) ↔
      ¬ Now f c.actor c.post ∧ st = c.pre ∧ P c.actor src msg := by
  constructor
  · rintro ⟨a,n,m,rec,h⟩
    obtain ⟨fresh,rfl,eq,e⟩ := (receive_iff c).mp rec
    cases ev.symm.trans e
    exact ⟨fresh,eq,h⟩
  · rintro ⟨fresh,rfl,h⟩
    exact ⟨_,_,_,(receive_iff c).mpr ⟨fresh,rfl,rfl,ev⟩,h⟩

private theorem not_recv {i} (ev : c.event = .internal i) {a st n m} : ¬Receive c a st n m := by
  intro h
  cases ev.symm.trans ((receive_iff c).mp h).2.2.2

private abbrev Calls :=
  (reach% step_observeTerm_log_message_proposeRequestVoteRequest[0]) f t c ∨
    (reach% step_observeTerm_log_message_proposeRequestVoteRequest[1]) f t c

private theorem calls_iff : Calls c ↔
    ¬ Now f c.actor c.post ∧ test .call c.actor c.pre c.event = true := by
  unfold Calls
  reach_unfold step_observeTerm_log_message_proposeRequestVoteRequest[0]
  reach_unfold step_observeTerm_log_message_proposeRequestVoteRequest[1]
  cases ev : c.event with
  | internal i => simp [not_recv c ev, test]
  | receive n m =>
    simp only [recv4 c ev]
    have fr := c.inv.frontier _ _ c.pre_now
    by_cases fresh : Now f c.actor c.post
    · simp [fresh]
    · cases m <;> simp [fresh,fr,test,eligible] <;> grind (splits := 12)

private abbrev StateCalls (st : NodeState) :=
  (reach% step_observeTerm_log_primary_pos[0]) f t c st ∨
    (reach% step_observeTerm_log_primary_pos[1]) f t c st

private abbrev MsgCalls (m : Message) :=
  (reach% step_observeTerm_log_message_other[0]) f t c m ∨
    (reach% step_observeTerm_log_message_other[1]) f t c m

private abbrev BothCalls (st : NodeState) (m : Message) :=
  (reach% step_observeTerm_log_newer_pos[0]) f t c st m ∨
    (reach% step_observeTerm_log_newer_pos[1]) f t c st m

private theorem state_iff (st : NodeState) : StateCalls c st ↔ st = c.pre ∧ Calls c := by
  rw [calls_iff]
  unfold StateCalls
  reach_unfold step_observeTerm_log_primary_pos[0]
  reach_unfold step_observeTerm_log_primary_pos[1]
  cases ev : c.event with
  | internal i => simp [not_recv c ev,test]
  | receive n m =>
    simp only [recv3 c ev]
    by_cases hs : st = c.pre <;> simp [hs]
    have fr := c.inv.frontier _ _ c.pre_now
    by_cases fresh : Now f c.actor c.post
    · simp [fresh]
    · cases m <;> simp [fresh,fr,test,eligible] <;> grind (splits := 12)

private theorem msg_iff (msg : Message) :
    MsgCalls c msg ↔ (∃ n, c.event = .receive n msg) ∧ Calls c := by
  rw [calls_iff]
  unfold MsgCalls
  reach_unfold step_observeTerm_log_message_other[0]
  reach_unfold step_observeTerm_log_message_other[1]
  cases ev : c.event with
  | internal i => simp [not_recv c ev,test]
  | receive n m =>
    simp only [recv4 c ev]
    have fr := c.inv.frontier _ _ c.pre_now
    by_cases fresh : Now f c.actor c.post
    · simp [fresh]
    · by_cases hm : msg = m <;> cases m <;> simp [fresh,fr,test,eligible,hm] <;>
        grind (splits := 12)

private theorem both_iff (st : NodeState) (msg : Message) :
    BothCalls c st msg ↔ st = c.pre ∧ (∃ n, c.event = .receive n msg) ∧ Calls c := by
  rw [calls_iff]
  unfold BothCalls
  reach_unfold step_observeTerm_log_newer_pos[0]
  reach_unfold step_observeTerm_log_newer_pos[1]
  cases ev : c.event with
  | internal i => simp [not_recv c ev,test]
  | receive n m =>
    simp only [recv3 c ev]
    by_cases hs : st = c.pre <;> simp [hs]
    have fr := c.inv.frontier _ _ c.pre_now
    by_cases fresh : Now f c.actor c.post
    · simp [fresh]
    · by_cases hm : msg = m <;> cases m <;> simp [fresh,fr,test,eligible,hm] <;>
        grind (splits := 12)

private theorem state_pick (P : NodeState → Prop) :
    (∃ st, StateCalls c st ∧ P st) ↔ Calls c ∧ P c.pre := by
  simp only [state_iff]; grind

private theorem msg_pick (P : Message → Prop) :
    (∃ msg, MsgCalls c msg ∧ P msg) ↔ Calls c ∧ ∃ n m, c.event = .receive n m ∧ P m := by
  simp only [msg_iff]; grind

private theorem both_pick (P : NodeState → Message → Prop) :
    (∃ st msg, BothCalls c st msg ∧ P st msg) ↔
      Calls c ∧ ∃ n m, c.event = .receive n m ∧ P c.pre m := by
  simp only [both_iff]; grind

omit [Config.InitialConfiguration] in
private theorem join1 {α : Type} {a b p : α → Prop} :
    ((∃ x, a x ∧ p x) ∨ ∃ x, b x ∧ p x) ↔ ∃ x, (a x ∨ b x) ∧ p x := by
  simp only [or_and_right, exists_or]

omit [Config.InitialConfiguration] in
private theorem join2 {α β : Type} {a b p q : α → β → Prop} :
    ((∃ x y, a x y ∧ p x y) ∨ (∃ x y, b x y ∧ p x y) ∨
      (∃ x y, a x y ∧ q x y) ∨ ∃ x y, b x y ∧ q x y) ↔
      ∃ x y, (a x y ∨ b x y) ∧ (p x y ∨ q x y) := by
  simp only [and_or_left, or_and_right, exists_or]; grind

def column (log : Bool) (k : Branch) : Classes.StepBranch :=
  match log,k with
  | true,.call => .observeTerm_log_message_proposeRequestVoteRequest
  | false,.call => .observeTerm_commitIndex_message_proposeRequestVoteRequest
  | true,.primary => .observeTerm_log_primary_pos
  | true,.backup => .observeTerm_log_primary_neg
  | true,.higher => .observeTerm_log_newer_pos
  | true,.stable => .observeTerm_log_newer_neg
  | true,.other => .observeTerm_log_message_other
  | false,.primary => .observeTerm_commitIndex_primary_pos
  | false,.backup => .observeTerm_commitIndex_primary_neg
  | false,.higher => .observeTerm_commitIndex_newer_pos
  | false,.stable => .observeTerm_commitIndex_newer_neg
  | false,.other => .observeTerm_commitIndex_message_other

local macro "test_event" : tactic => `(tactic|
  (rw [calls_iff]; cases ev : Ctx.event _ with
   | internal i => simp [test]
   | receive n m => cases m <;> simp [test, Message.term] <;> grind))

private theorem sig_iff_test (log : Bool) (k : Branch) :
    sig c (column log k) ↔ ¬Now f c.actor c.post ∧ test k c.actor c.pre c.event = true := by
  cases k
  case call => cases log <;> exact calls_iff c
  case primary =>
    cases log <;> change step_observeTerm_log_primary_pos f t c ↔ _
    all_goals unfold step_observeTerm_log_primary_pos; rw [join1, state_pick]; test_event
  case backup =>
    cases log <;> change step_observeTerm_log_primary_neg f t c ↔ _
    all_goals unfold step_observeTerm_log_primary_neg; rw [join1, state_pick]; test_event
  case other =>
    cases log <;> change step_observeTerm_log_message_other f t c ↔ _
    all_goals unfold step_observeTerm_log_message_other; rw [join1, msg_pick]; test_event
  case higher =>
    cases log <;> change step_observeTerm_log_newer_pos f t c ↔ _
    all_goals unfold step_observeTerm_log_newer_pos; rw [join2, both_pick]; test_event
  case stable =>
    cases log <;> change step_observeTerm_log_newer_neg f t c ↔ _
    all_goals unfold step_observeTerm_log_newer_neg; rw [join2, both_pick]; test_event
end

private theorem correct_at (s : Step) (log : Bool) (k : Branch) :
    label s (.step (column log k)) = reader k s.cfg s.before s.act s.after s.past := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨v,made,ok⟩ := GuardedDomain.ofAction_matches s
  have action := (s.context_eq s.context).mpr rfl
  have ev : ReadersAtoms.eventOf s.act = s.context.event := by
    rw [← action]
    change ReadersAtoms.eventOf (ActionContext.encode s.context.tr.actor s.context.tr.event) = s.context.tr.event
    cases s.context.tr.event <;> rfl
  apply Bool.eq_iff_iff.mpr
  rw [label_true, show holds s (.step (column log k)) ↔ sig s.context (column log k) from sig_iff _ _,
    sig_iff_test, reader, made, Option.any_some, Bool.and_eq_true, GuardedDomain.View.old_post ok,
    Bool.not_eq_false, ev, GuardedDomain.View.actor_eq ok, GuardedDomain.View.pre_eq ok]

def exactReader (log : Bool) (k : Branch) : Exact (column log k) := ⟨reader k,(correct_at · log k)⟩

def ackAlias (log : Bool) :
    Exact (if log then .observeTerm_log_message_appendEntriesResponse else
      .observeTerm_commitIndex_message_appendEntriesResponse) where
  eval := reader .call
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    rw [← correct_at s log .call]
    apply Bool.eq_iff_iff.mpr
    rw [label_true, label_true]
    exact (sig_iff _ _).trans (by cases log <;> exact (sig_iff _ _).symm)

end ConsensusCoverage.HandReadersA.Observe
