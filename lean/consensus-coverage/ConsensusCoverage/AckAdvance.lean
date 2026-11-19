module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ActionProfile
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.ActionContext
import all ConsensusCoverage.FullProfile
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

/-! Exact `advance_backed.advance.inr` answers on same-term successful
AppendEntriesResponse deliveries to a primary from an eligible peer. -/

namespace ConsensusCoverage.AckAdvance

open CCF CCF.MultiNodeTransitionSystem
open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxHeartbeats 0

private def middle (pre : NodeState) (source : NodeID) (response : AppendEntriesResponse) : NodeState :=
  {pre with matchIndex := Function.update pre.matchIndex source (max (pre.matchIndex source) response.lastLogIndex)}

private def accepts (source : NodeID) (response : AppendEntriesResponse) (pre : NodeState) (self : NodeID) : Prop :=
  pre.role = .primary ∧ response.success = true ∧ response.term = pre.currentTerm ∧ source ∈ eligiblePeers pre self

private instance (self source : NodeID) (r : AppendEntriesResponse) (pre : NodeState) :
    Decidable (accepts source r pre self) := by unfold accepts; infer_instance

/-- This reader supplies only `.advance_backed_advance_inr`. Other deliveries and
missing snapshot lookups are unknown, not negative answers. -/
@[expose] public def read? (before : Model.State) (act : Model.Action) (after : Model.State) : Option Bool := do
  let .deliver e := act | none
  let .appendEntriesResponse response := e.payload | none
  let pre ← nodeState before e.target
  let post ← nodeState after e.target
  if accepts e.source response pre e.target then
    some (decide (pre.commitIndex < post.commitIndex))
  else none

private theorem actual_advance [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) {src r}
    (event : c.event = .receive src (.appendEntriesResponse r))
    (guard : accepts src r c.pre c.actor) : Advance c.actor (middle c.pre src r) c.post := by
  obtain ⟨role, success, term, peer⟩ := guard
  have ran := c.tr.ran
  change ((Model.Node.step (Capabilities.record c.actor) c.actor c.pre c.event).run {}) = _ at ran
  rw [event] at ran
  simp only [Model.Node.step, receive, peer, not_true_eq_false, and_false, ↓reduceIte,
    observeTerm, role, updateTerm, term, Nat.lt_irrefl, handleAppendEntriesResponse,
    bne_self_eq_false, Bool.false_eq_true, success] at ran
  rw [← role] at ran
  obtain ⟨_, _, advance, _⟩ := advanceCommit_sends c.actor (middle c.pre src r) _ _ _ ran
  exact advance

private theorem ack_premises [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) {src r}
    (event : c.event = .receive src (.appendEntriesResponse r))
    (leader : c.pre.role = .primary) (success : r.success = true) (term : r.term = c.pre.currentTerm)
    (advance : Advance c.actor (middle c.pre src r) c.post) :
    ∀ voter, voter ≠ c.actor → 0 < (middle c.pre src r).matchIndex voter →
      ∃ acker, Seen (f.advance t) voter acker ∧ acker.currentTerm = c.post.currentTerm ∧
        c.post.log.take ((middle c.pre src r).matchIndex voter) <+: acker.log := by
  intro voter different positive
  have log : c.post.log = c.pre.log := advance.log
  have sameTerm : c.post.currentTerm = c.pre.currentTerm := advance.term
  rw [log, sameTerm]
  change 0 < Function.update c.pre.matchIndex src (max (c.pre.matchIndex src) r.lastLogIndex) voter at positive
  change ∃ acker, Seen (f.advance t) voter acker ∧ acker.currentTerm = c.pre.currentTerm ∧
    c.pre.log.take (Function.update c.pre.matchIndex src
      (max (c.pre.matchIndex src) r.lastLogIndex) voter) <+: acker.log
  by_cases same : voter = src
  · subst src
    rw [Function.update_self] at positive ⊢
    rcases Std.max_eq_or (a := c.pre.matchIndex voter) (b := r.lastLogIndex) with keep | response
    · rw [keep] at positive ⊢
      obtain ⟨a, seen, k, _, sub⟩ := c.match_pre leader different positive
      exact ⟨a, seen, k, sub⟩
    · rw [response]
      obtain ⟨e, ok, source, _, payload⟩ := c.received_ok event
      simp only [MessageOK, payload] at ok
      have ack := ok success
      rw [source, term] at ack
      obtain ⟨a, seen, k, _, sub⟩ := c.acked_pre leader ack
      exact ⟨a, seen, k, sub⟩
  · rw [Function.update_of_ne same] at positive ⊢
    obtain ⟨a, seen, k, _, sub⟩ := c.match_pre leader different positive
    exact ⟨a, seen, k, sub⟩

private theorem necessary [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) (h : SolvedWitnesses.sig c .advance_backed_advance_inr) :
    c.pre.commitIndex < c.post.commitIndex := by
  change SolvedWitnesses.step_advance_backed_advance_inr f t c at h
  rcases h with ⟨m, reach, fields, _⟩ | ⟨m, reach, fields, _⟩ |
    ⟨m, reach, fields, _⟩ | ⟨m, reach, fields, _⟩
  all_goals
    have lt := fields.2.2.2.2.2.2.1
    suffices eq : m.commitIndex = c.pre.commitIndex by exact eq ▸ lt
  -- The eight append/ack arms retain the old commit index in the middle
  -- state. So do the four election arms, through the campaign candidate.
  · simp only [SolvedWitnesses.reach_689] at reach
    rcases reach with h | h | h | h <;> grind
  · simp only [SolvedWitnesses.reach_690] at reach
    rcases reach with h | h | h | h <;> grind
  · simp only [SolvedWitnesses.reach_691] at reach
    rcases reach with h | h <;> grind [primaryState, Campaign]
  · simp only [SolvedWitnesses.reach_692] at reach
    rcases reach with h | h <;> grind [primaryState, Campaign]

private theorem sufficient [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) {src r}
    (event : c.event = .receive src (.appendEntriesResponse r))
    (guard : accepts src r c.pre c.actor)
    (lt : c.pre.commitIndex < c.post.commitIndex) :
    SolvedWitnesses.sig c .advance_backed_advance_inr := by
  let m := middle c.pre src r
  have advance : Advance c.actor m c.post := actual_advance c event guard
  have fields : _ := advance
  change c.post = m ∨ _ at fields
  rcases fields with same | fields
  · have eq := congrArg NodeState.commitIndex same
    exact (Nat.ne_of_gt lt eq).elim
  have fresh : ¬ Now f c.actor c.post := by
    intro old
    exact Nat.ne_of_gt lt (congrArg NodeState.commitIndex (c.now_pre old))
  have newState : SolvedWitnesses.reach_27 f t c c c.actor c.post := ⟨c.post_now, fresh, rfl⟩
  obtain ⟨leader, success, term, _⟩ := guard
  have log : c.post.log = c.pre.log := advance.log
  have sameTerm : c.post.currentTerm = c.pre.currentTerm := advance.term
  have led : Led (f.advance t) c.actor c.post.currentTerm := by
    rw [sameTerm]
    exact (c.pre_led leader).mono t
  have backed : Backed f c.post.log m.commitIndex c.post.currentTerm := by
    apply c.pre_backed (by rw [log]) (by simp [leader]) (c.pre_led leader)
  have acks := ack_premises c event leader success term advance
  have reach : SolvedWitnesses.reach_689 f t c c m := by
    -- Fresh-node, then ack. The equality to `Summary.kind c.sum` in
    -- this arm is reflexive by proof irrelevance once its fields are supplied.
    exact .inr (.inr (.inl ⟨newState, c.post_now, c.post_now, src, r, event, leader,
      success, term, advance, rfl, c.post_now, log, sameTerm, rfl, rfl⟩))
  change SolvedWitnesses.step_advance_backed_advance_inr f t c
  apply Or.inl
  refine ⟨m, reach, fields, ?_⟩
  obtain ⟨log, curr, vote, matched, sent, votes, inc, high, role⟩ := fields
  repeat' first | assumption | apply And.intro

/-- Any emitted answer is the generated label of the initialized recorded step.
The commit-index comparison is justified using the actual ack origin, including
freshness, prior backing and acknowledgements from the safety invariant. -/
public theorem read?_correct (s : ActionProfile.Step) {b : Bool}
    (read : read? s.before s.act s.after = some b) :
    ActionProfile.label s (.step .advance_backed_advance_inr) = b := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have action : ActionContext.action c = s.act := (s.context_eq c).mpr rfl
  have preMem : nodeState (FullProfile.current s.frame) c.actor = some c.pre := c.tr.found
  have postMem := Direct.nodeState_of_mem c.keys_after c.post_now
  rw [← s.current_eq, ← action] at read
  change read? (FullProfile.current s.frame) (ActionContext.encode c.actor c.event) s.after = some b at read
  cases event : c.event with
  | internal a => simp [read?, event, ActionContext.encode] at read
  | receive src msg =>
    cases msg <;> simp only [read?, event, ActionContext.encode, preMem, postMem,
      Option.bind_eq_bind, Option.bind_some] at read <;> try contradiction
    rename_i r
    split at read
    · rename_i guard
      rw [← Option.some.inj read]
      apply Bool.eq_iff_iff.mpr
      rw [ActionProfile.label_true, decide_eq_true_eq]
      change PinnedClasses.sig c .advance_backed_advance_inr ↔ _
      rw [SolvedWitnesses.sig_iff]
      exact ⟨necessary c, sufficient c event guard⟩
    · contradiction

end ConsensusCoverage.AckAdvance
