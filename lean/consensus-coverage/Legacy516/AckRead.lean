module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

meta import ConsensusCoverage.ReachPath
public import ConsensusCoverage.AckAdvance
public import ConsensusCoverage.AckFamily
import all ConsensusCoverage.AckAdvance
import all ConsensusCoverage.ActionContext
import all ConsensusCoverage.EvidenceSupport
import all ConsensusCoverage.EventSupport
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.AckRead

open ActionProfile Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open CCF CCF.MultiNodeTransitionSystem

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxHeartbeats 0

/-- Successful, same-term acknowledgment accepted by a primary; the answer
distinguishes changing the commit index from just changing replication state. -/
@[expose] public def success? (cfg : FullProfile.Configuration) (before : Model.State)
    (act : Model.Action) (after : Model.State) (past : List Model.State) : Option Bool :=
  if AckFamily.test cfg before act after past then AckAdvance.read? before act after else none

public theorem success_sound (s : Step) {advanced : Bool}
    (h : success? s.cfg s.before s.act s.after s.past = some advanced) :
    label s (.step .advance_backed_advance_inr) = advanced := by
  unfold success? at h
  split at h
  · exact AckAdvance.read?_correct s h
  · contradiction

private theorem event (s : Step) (h : EventSupport.actionTag s.act = .appendEntriesResponse) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    ∃ src r, s.context.event = .receive src (.appendEntriesResponse r) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  rw [← (s.context_eq s.context).mpr rfl, EventSupport.actionTag_eq] at h
  cases he : s.context.event with
  | internal i =>
    change EventSupport.eventTag s.context.event = _ at h
    rw [he] at h
    cases i <;> contradiction
  | receive src m =>
    change EventSupport.eventTag s.context.event = _ at h
    rw [he] at h
    cases m <;> first | exact ⟨_, _, rfl⟩ | contradiction

private def retry (pre : NodeState) (src : NodeID) (r : AppendEntriesResponse) : NodeState :=
  let i := findHighestPossibleMatch pre.log r.lastLogIndex r.term
  {pre with sentIndex := Function.update pre.sentIndex src (max (min i (pre.sentIndex src)) (pre.matchIndex src))}

private inductive Effect (src : NodeID) (r : AppendEntriesResponse) (actor : NodeID)
    (pre post : NodeState) : Prop
  | ignored : post = pre → Effect src r actor pre post
  | higherTerm : pre.role = .primary → pre.currentTerm < r.term → post = bumpedState pre r.term →
      Effect src r actor pre post
  | retry : pre.role = .primary → r.term ≤ pre.currentTerm → r.success = false →
      post = AckRead.retry pre src r → Effect src r actor pre post
  | accepted : AckAdvance.accepts src r pre actor → Effect src r actor pre post

private theorem kind (s : Step) (h : EventSupport.actionTag s.act = .appendEntriesResponse) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    ∃ src r, s.context.event = .receive src (.appendEntriesResponse r) ∧
      Effect src r s.context.actor s.context.pre s.context.post := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨src, r, ev⟩ := event s h
  have ran := s.context.tr.ran
  change ((Node.step (Capabilities.record s.context.actor) s.context.actor s.context.pre s.context.event).run {}) = _ at ran
  rw [ev] at ran
  simp only [Node.step, receive] at ran
  refine ⟨src, r, ev, ?_⟩
  split at ran
  · exact .ignored (Prod.mk.inj (Option.some.inj ran)).1.symm
  rename_i peer
  rcases observe_response s.context.pre r with ⟨role, lt, eq⟩ | ⟨le, eq⟩
  · rw [eq] at ran
    simp only [handleAppendEntriesResponse, bumpedState, ↓reduceIte] at ran
    exact .higherTerm role lt (Prod.mk.inj (Option.some.inj ran)).1.symm
  · rw [eq] at ran
    simp only [handleAppendEntriesResponse] at ran
    split at ran
    · exact .ignored (Prod.mk.inj (Option.some.inj ran)).1.symm
    rename_i leader
    have role : s.context.pre.role = .primary := by simpa using leader
    split at ran
    · rename_i ok
      split at ran
      · rename_i same
        have eligible : src ∈ eligiblePeers s.context.pre s.context.actor := by simpa using peer
        exact .accepted ⟨role, ok, same, eligible⟩
      · exact .ignored (Prod.mk.inj (Option.some.inj ran)).1.symm
    · rename_i no
      exact .retry role (le role) (Bool.eq_false_iff.mpr no) (Prod.mk.inj (Option.some.inj ran)).1.symm

private theorem tag_of_test (s : Step) (h : AckFamily.test s.cfg s.before s.act s.after s.past = true) :
    EventSupport.actionTag s.act = .appendEntriesResponse := by
  have kind := (Bool.and_eq_true_iff.mp h).1
  exact beq_iff_eq.mp kind

private theorem new_post (s : Step) (h : AckFamily.test s.cfg s.before s.act s.after s.past = true) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    ¬Now s.frame s.context.actor s.context.post := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have now : EvidenceSupport.fresh s.cfg s.before s.act s.after s.past .now = true :=
    (Bool.and_eq_true_iff.mp (Bool.and_eq_true_iff.mp h).2).1
  intro old
  have stable : EvidenceSupport.Stable s.frame s.after .now := by
    intro n st post
    rcases s.context.now_after post with ⟨rfl, rfl⟩ | ⟨_, was⟩
    · exact old
    · exact was
  exact Bool.noConfusion (now.symm.trans ((EvidenceSupport.fresh_iff s _).mpr stable))

private theorem same_term (s : Step) (h : AckFamily.test s.cfg s.before s.act s.after s.past = true) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    s.context.post.currentTerm = s.context.pre.currentTerm := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have bits := (Bool.and_eq_true_iff.mp (Bool.and_eq_true_iff.mp h).2).2
  have seen : EvidenceSupport.fresh s.cfg s.before s.act s.after s.past .seen = false := by
    have old := (List.all_eq_true.mp bits) .seen (by decide)
    simpa only [EvidenceSupport.fresh, Bool.not_eq_true'] using old
  have stable := (EvidenceSupport.fresh_iff s .seen).mp seen
  have past := stable _ _ s.context.post_seen
  exact Nat.le_antisymm (s.context.inv.term_mono _ _ _ s.context.pre_now past) s.context.term_le

private theorem raw_read (s : Step) {src r}
    (event : letI : Config.InitialConfiguration := ⟨s.cfg⟩
      s.context.event = .receive src (.appendEntriesResponse r)) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    AckAdvance.read? s.before s.act s.after =
      if AckAdvance.accepts src r s.context.pre s.context.actor then
        some (decide (s.context.pre.commitIndex < s.context.post.commitIndex))
      else none := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have action : ActionContext.action s.context = s.act := (s.context_eq s.context).mpr rfl
  have before : nodeState (FullProfile.current s.frame) s.context.actor = some s.context.pre :=
    s.context.tr.found
  have after := Direct.nodeState_of_mem s.context.keys_after s.context.post_now
  rw [← s.current_eq, ← action]
  change AckAdvance.read? (FullProfile.current s.frame)
    (ActionContext.encode s.context.actor s.context.event) s.after = _
  simp only [event, AckAdvance.read?, ActionContext.encode, before, after, Option.bind_eq_bind, Option.bind_some]

public inductive Mode
  | higherTerm | retry | accepted (advanced : Bool)
  deriving DecidableEq, Repr

/-- Split the node-only response family by the handler effect. On initialized
steps passing `AckFamily.test` the lookups cannot fail. -/
@[expose] public def mode? (cfg : FullProfile.Configuration) (before : Model.State)
    (act : Model.Action) (after : Model.State) (past : List Model.State) : Option Mode := do
  if !AckFamily.test cfg before act after past then none else
    match AckAdvance.read? before act after with
    | some advanced => some (.accepted advanced)
    | none =>
      let v ← GuardedDomain.ofAction cfg before after past act
      return if v.pre.currentTerm < v.post.currentTerm then .higherTerm else .retry

private def Mode.fits (mode : Mode) (src : NodeID) (r : AppendEntriesResponse)
    (actor : NodeID) (pre post : NodeState) : Prop :=
  match mode with
  | .higherTerm => pre.role = .primary ∧ pre.currentTerm < r.term ∧ post = bumpedState pre r.term
  | .retry => pre.role = .primary ∧ r.term ≤ pre.currentTerm ∧ r.success = false ∧ post = AckRead.retry pre src r
  | .accepted adv => AckAdvance.accepts src r pre actor ∧ decide (pre.commitIndex < post.commitIndex) = adv

/-- The executable partition agrees with the actual response handler. Ignored
responses cannot pass the fresh-node test. -/
private theorem mode_spec (s : Step) (h : AckFamily.test s.cfg s.before s.act s.after s.past = true) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    ∃ src r mode, s.context.event = .receive src (.appendEntriesResponse r) ∧
      mode? s.cfg s.before s.act s.after s.past = some mode ∧
      mode.fits src r s.context.actor s.context.pre s.context.post := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨src, r, ev, eff⟩ := kind s (tag_of_test s h)
  obtain ⟨v, made, ok⟩ := GuardedDomain.ofAction_matches s
  have pre : v.pre = s.context.pre := congrArg GuardedDomain.View.pre ok.1
  have post : v.post = s.context.post := congrArg GuardedDomain.View.post ok.1
  have raw := raw_read s ev
  cases eff with
  | ignored eq => exact (new_post s h (eq.symm ▸ s.context.pre_now)).elim
  | higherTerm role lt eq =>
    refine ⟨_, _, .higherTerm, ev, ?_, role, lt, eq⟩
    have no : ¬AckAdvance.accepts src r s.context.pre s.context.actor :=
      fun yes => (Nat.ne_of_gt lt) yes.2.2.1
    have higher : s.context.pre.currentTerm < s.context.post.currentTerm := by
      rw [eq]
      exact lt
    simp only [mode?, h, Bool.not_true, Bool.false_eq_true, ite_false, raw, ite_eq_right no,
      made, Option.bind_eq_bind, Option.bind_some, pre, post, ite_eq_left higher, pure]
  | retry role le no eq =>
    refine ⟨_, _, .retry, ev, ?_, role, le, no, eq⟩
    have refused : ¬AckAdvance.accepts src r s.context.pre s.context.actor :=
      fun yes => Bool.noConfusion (no.symm.trans yes.2.1)
    have same : s.context.post.currentTerm = s.context.pre.currentTerm :=
      (congrArg NodeState.currentTerm eq).trans rfl
    simp only [mode?, h, Bool.not_true, Bool.false_eq_true, ite_false, raw, ite_eq_right refused,
      made, Option.bind_eq_bind, Option.bind_some, pre, post, same, Nat.lt_irrefl, ite_false, pure]
  | accepted guard =>
    refine ⟨_, _, .accepted _, ev, ?_, guard, rfl⟩
    simp only [mode?, h, Bool.not_true, Bool.false_eq_true, ite_false, raw, ite_eq_left guard]

public theorem mode_total (s : Step) (h : AckFamily.test s.cfg s.before s.act s.after s.past = true) :
    ∃ mode, mode? s.cfg s.before s.act s.after s.past = some mode := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨_, _, mode, _, got, _⟩ := mode_spec s h
  exact ⟨mode, got⟩

/-- Raising the term makes a new `Seen` fact, even when the log is unchanged. -/
public theorem no_higher_term (s : Step) (h : AckFamily.test s.cfg s.before s.act s.after s.past = true) :
    mode? s.cfg s.before s.act s.after s.past ≠ some .higherTerm := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  intro bump
  obtain ⟨_, r, mode, _, got, fits⟩ := mode_spec s h
  have eq := Option.some.inj (got.symm.trans bump)
  subst mode
  obtain ⟨_, lt, set⟩ := fits
  have term : s.context.post.currentTerm = r.term := (congrArg NodeState.currentTerm set).trans rfl
  exact Nat.ne_of_gt lt (term.symm.trans (same_term s h))

/-- The only possible modes of the node-only response family. -/
public theorem replay_cases (s : Step) (h : AckFamily.test s.cfg s.before s.act s.after s.past = true) :
    let m := mode? s.cfg s.before s.act s.after s.past
    m = some .retry ∨ m = some (.accepted false) ∨ m = some (.accepted true) := by
  obtain ⟨m, got⟩ := mode_total s h
  cases m with
  | higherTerm => exact (no_higher_term s h got).elim
  | retry => exact .inl got
  | accepted advanced =>
    cases advanced with
    | false => exact .inr (.inl got)
    | true => exact .inr (.inr got)

/-- The proof's acknowledgment summary arm is true exactly when the
handler accepted a successful reply, whether or not its commit advanced. -/
public theorem ack_kind_eq (s : Step) (h : AckFamily.test s.cfg s.before s.act s.after s.past = true) :
    label s (.step .post_log_kind_ack) = (success? s.cfg s.before s.act s.after s.past).isSome := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  obtain ⟨src, r, m, ev, got, facts⟩ := mode_spec s h
  cases m with
  | higherTerm => exact (no_higher_term s h got).elim
  | retry =>
    have no : ¬AckAdvance.accepts src r s.context.pre s.context.actor :=
      fun yes => Bool.noConfusion (facts.2.2.1.symm.trans yes.2.1)
    have answer : (success? s.cfg s.before s.act s.after s.past).isSome = false := by
      simp [success?, h, raw_read s ev, no]
    rw [answer]
    apply Bool.eq_false_iff.mpr
    intro yes
    have yes := (SolvedWitnesses.sig_iff c _).mp ((label_true s _).mp yes)
    change SolvedWitnesses.step_post_log_kind_ack _ _ c at yes
    rcases yes with ⟨_, _, msg, event, _, ok, _, _, _⟩ | ⟨_, _, msg, event, _, ok, _, _, _⟩ |
        ⟨_, _, msg, event, _, ok, _, _, _⟩ | ⟨_, _, msg, event, _, ok, _, _, _⟩ |
        ⟨_, _, msg, event, _, ok, _, _, _⟩ | ⟨_, _, msg, event, _, ok, _, _, _⟩ |
        ⟨_, _, msg, event, _, ok, _, _, _⟩
    all_goals
      have eq := (Message.appendEntriesResponse.inj (Event.receive.inj (ev.symm.trans event)).2)
      exact Bool.noConfusion (facts.2.2.1.symm.trans (eq ▸ ok))
  | accepted _ =>
    have accepted := facts.1
    have answer : (success? s.cfg s.before s.act s.after s.past).isSome = true := by
      simp [success?, h, raw_read s ev, accepted]
    rw [answer]
    apply (label_true s _).mpr
    change PinnedClasses.sig c .post_log_kind_ack
    rw [SolvedWitnesses.sig_iff]
    change SolvedWitnesses.step_post_log_kind_ack _ _ c
    have adv := AckAdvance.actual_advance c ev accepted
    obtain ⟨x, mem⟩ := List.exists_mem_of_ne_nil _ (c.inv.leader_logs c.actor c.pre c.pre_now accepted.1)
    have postMem : x ∈ c.post.log := adv.log.symm ▸ mem
    have reach : (reach% SolvedWitnesses.step_post_log_kind_ack[0]) s.frame s.after c c :=
      ⟨⟨c.actor, c.post, c.post_now, new_post s h, rfl⟩, c.post_now, x, postMem, c.post_now, postMem,
        c.post_now, c.term_le, c.inv.terms c.actor c.pre c.pre_now, rfl⟩
    exact .inl ⟨reach, src, r, ev, accepted.1, accepted.2.1, accepted.2.2.1, adv, rfl⟩

/-- A response delivery never changes the actor's log. -/
private theorem log_eq (s : Step) (isAck : EventSupport.actionTag s.act = .appendEntriesResponse) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    s.context.post.log = s.context.pre.log := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨_, _, ev, eff⟩ := kind s isAck
  cases eff with
  | ignored eq | higherTerm _ _ eq | retry _ _ _ eq =>
    exact (congrArg NodeState.log eq).trans rfl
  | accepted guard => exact (AckAdvance.actual_advance s.context ev guard).log

private theorem roles (s : Step) (h : AckFamily.test s.cfg s.before s.act s.after s.past = true) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    s.context.pre.role = .primary ∧ s.context.post.role ≠ .candidate := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨_, _, m, ev, got, facts⟩ := mode_spec s h
  cases m with
  | higherTerm => exact (no_higher_term s h got).elim
  | retry =>
    refine ⟨facts.1, ?_⟩
    rw [facts.2.2.2]
    change s.context.pre.role ≠ _
    rw [facts.1]
    decide
  | accepted _ =>
    have adv := AckAdvance.actual_advance s.context ev facts.1
    refine ⟨facts.1.1, ?_⟩
    rcases adv.role with eq | eq
    · rw [eq]
      change s.context.pre.role ≠ _
      rw [facts.1.1]
      decide
    · rw [eq]
      decide

/-- This family keeps its nonempty primary log. The normalized append path
can take the empty suffix, but the new-entry path cannot. -/
public theorem terms_answers (s : Step) (h : AckFamily.test s.cfg s.before s.act s.after s.past = true) :
    label s (.step .terms_post_log_inr_inl) = true ∧
    label s (.step .terms_mem_append_inl) = true ∧
    label s (.step .terms_mem_append_inr) = false ∧
    label s (.step .terms_post_log_inr_inr) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have log := log_eq s (tag_of_test s h)
  have term := same_term s h
  obtain ⟨role, candidate⟩ := roles s h
  have nonempty := c.inv.leader_logs c.actor c.pre c.pre_now role
  have ⟨entry, ent⟩ : ∃ e, e ∈ c.pre.log := List.exists_mem_of_ne_nil _ nonempty
  have now := c.post_now
  have newNode : (reach% SolvedWitnesses.step_terms_mem_append_inl[0]) s.frame s.after c c :=
    ⟨c.actor, c.post, now, new_post s h, rfl⟩
  have append : c.post.log = c.pre.log ++ [] ∧
      (∀ e : Entry, e ∈ ([] : List Entry) → e.term = c.pre.currentTerm) ∧
      c.pre.role = .primary ∧ c.post.currentTerm = c.pre.currentTerm ∧ c.post.role ≠ .candidate :=
    ⟨log.trans (List.append_nil _).symm, by simp, role, term, candidate⟩
  have terms := c.inv.terms c.actor c.pre c.pre_now
  have postEnt : entry ∈ c.post.log := log.symm ▸ ent
  have copyLog := currentCopyLog c.inv.rooted c.inv.terms c.inv.sorted c.inv.anchor c.actor c.pre c.pre_now
  rw [← log, ← term] at copyLog
  have copy : ∃ l n, CopyLog s.frame.logs c.post.currentTerm l ∧
      n ≤ l.length ∧ c.post.log = l.take n :=
    ⟨c.post.log, c.post.log.length, copyLog, Nat.le_refl _, List.take_length.symm⟩
  refine ⟨?_, ?_, ?_, ?_⟩
  · apply (label_true s _).mpr
    change PinnedClasses.sig c .terms_post_log_inr_inl
    rw [SolvedWitnesses.sig_iff]
    change SolvedWitnesses.step_terms_post_log_inr_inl s.frame s.after c
    exact .inl ⟨newNode, now, entry, postEnt, now, postEnt, now, .inl ⟨[], append⟩, ⟨[], append⟩,
      [], append, append.1, append.2, append.2.1, ⟨role, term, candidate⟩, role, ⟨term, candidate⟩,
      term, candidate, c.term_le, terms⟩
  · apply (label_true s _).mpr
    change PinnedClasses.sig c .terms_mem_append_inl
    rw [SolvedWitnesses.sig_iff]
    change SolvedWitnesses.step_terms_mem_append_inl s.frame s.after c
    exact .inl ⟨newNode, now, entry, postEnt, now, postEnt, now, .inl ⟨[], append⟩, ⟨[], append⟩,
      [], append, append.1, append.2, append.2.1, ⟨role, term, candidate⟩, role, ⟨term, candidate⟩,
      term, candidate, ent, c.term_le, terms⟩
  · apply Bool.eq_false_iff.mpr
    intro yes
    have yes := (SolvedWitnesses.sig_iff c _).mp ((label_true s _).mp yes)
    change SolvedWitnesses.step_terms_mem_append_inr s.frame s.after c at yes
    rcases yes with ⟨_, _, e, _, _, _, _, _, _, es, app, _, _, _, _, _, _, _, _, mem, _, _⟩ |
                    ⟨_, _, e, _, _, _, _, _, _, es, app, _, _, _, _, _, _, _, _, mem, _, _⟩
    all_goals
      have len : c.pre.log.length = c.pre.log.length + es.length :=
        (congrArg List.length (log.symm.trans app.1)).trans List.length_append
      have empty : es = [] := List.eq_nil_of_length_eq_zero (by omega)
      subst es
      exact List.not_mem_nil mem
  · apply (label_true s _).mpr
    change PinnedClasses.sig c .terms_post_log_inr_inr
    rw [SolvedWitnesses.sig_iff]
    change SolvedWitnesses.step_terms_post_log_inr_inr s.frame s.after c
    exact .inl ⟨newNode, now, entry, postEnt, now, postEnt, now, .inr copy, copy,
      c.post.log, ⟨_, copyLog, Nat.le_refl _, List.take_length.symm⟩,
      c.post.log.length, ⟨copyLog, Nat.le_refl _, List.take_length.symm⟩,
      copyLog, ⟨Nat.le_refl _, List.take_length.symm⟩,
      Nat.le_refl _, List.take_length.symm, c.term_le, terms⟩

/-- On this family the partial ack reader can be made total for the
advancement arm: unaccepted replies cannot increase the commit index. -/
public theorem advance_eq (s : Step) (pass : AckFamily.test s.cfg s.before s.act s.after s.past = true) :
    label s (.step .advance_backed_advance_inr) =
      (success? s.cfg s.before s.act s.after s.past).getD false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  simp only [success?, pass, ite_true]
  cases read : AckAdvance.read? s.before s.act s.after with
  | some b => exact AckAdvance.read?_correct s read
  | none =>
    obtain ⟨_, _, ev, eff⟩ := kind s (tag_of_test s pass)
    have keep : s.context.post.commitIndex = s.context.pre.commitIndex := by
      cases eff with
      | ignored eq | higherTerm _ _ eq | retry _ _ _ eq =>
        exact (congrArg NodeState.commitIndex eq).trans rfl
      | accepted guard => rw [raw_read s ev, ite_eq_left guard] at read; contradiction
    apply Bool.eq_false_iff.mpr
    intro yes
    have inc := AckAdvance.necessary s.context
      ((SolvedWitnesses.sig_iff s.context _).mp ((label_true s _).mp yes))
    rw [keep] at inc
    exact (Nat.lt_irrefl _ inc)

end ConsensusCoverage.AckRead
