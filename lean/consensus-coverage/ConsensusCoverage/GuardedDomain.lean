module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ActionProfile
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.ActionContext
import all ConsensusCoverage.LeaderEffect
import all ConsensusCoverage.StateCoverage
import all ConsensusCoverage.CommitMonitor
import all ConsensusCoverage.Historical
import all Consensus.Proofs.SafetyInvariant

/-! Finite domains for guarded questions on an actual protocol step. -/

namespace ConsensusCoverage.GuardedDomain

open CCF CCF.MultiNodeTransitionSystem
open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open Consensus.Proofs.Ledger

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxHeartbeats 0
set_option linter.unusedSectionVars false

private def IndexSame (pre post : NodeState) : Prop :=
  post.sentIndex = pre.sentIndex ∧ post.matchIndex = pre.matchIndex

private theorem IndexSame.refl (s : NodeState) : IndexSame s s := ⟨rfl, rfl⟩

private theorem IndexSame.trans {x y z : NodeState}
    (h : IndexSame x y) (g : IndexSame y z) : IndexSame x z :=
  ⟨g.1.trans h.1, g.2.trans h.2⟩

private theorem ae_indices (self source : NodeID) (s : NodeState) (r : AppendEntriesRequest) :
    Sends (fun post _ => IndexSame s post)
      (handleAppendEntriesRequest (Capabilities.record self) self source s r) := by
  unfold handleAppendEntriesRequest
  dsimp only
  generalize hw : (if r.term = s.currentTerm
      ∧ (s.role = .candidate ∨ s.role = .preVoteCandidate) then
    becomeAwareOfNewTerm s r.term else s) = w
  have preserved : IndexSame s w := by rw [← hw]; split <;> exact ⟨rfl, rfl⟩
  refine Sends.ite' (fun _ => ?_) (fun _ => ?_)
  · refine Sends.ite' (fun _ => ?_) (fun _ => ?_)
    all_goals exact Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' preserved
  · refine Sends.ite' (fun _ => Sends.pure' preserved) (fun _ => ?_)
    split
    all_goals
      refine Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' ?_
      obtain ⟨_, _, _, eq, _⟩ := handleAppendEntiresFromPrimary_eq self _ r
      rw [eq]
      exact preserved

private theorem observe_indices (s : NodeState) (m : Message) : IndexSame s (observeTerm s m) := by
  have update (k : Nat) : IndexSame s (updateTerm s k) := by
    unfold updateTerm
    split <;> exact ⟨rfl, rfl⟩
  cases m <;> simp only [observeTerm]
  all_goals first | exact update _ | exact IndexSame.refl _ | split <;> first | exact update _ | exact IndexSame.refl _

private theorem observe_same_term (s : NodeState) (m : Message)
    (eq : (observeTerm s m).currentTerm = s.currentTerm) : observeTerm s m = s := by
  have update (k : Nat) (eq : (updateTerm s k).currentTerm = s.currentTerm) : updateTerm s k = s := by
    by_cases bump : s.currentTerm < k <;> simp [updateTerm, becomeAwareOfNewTerm, bump] at eq ⊢
    omega
  cases m <;> simp only [observeTerm] at eq ⊢
  all_goals first | rfl | exact update _ eq | by_cases h : s.role = .primary <;> simp [h] at eq ⊢ <;> exact update _ eq

private theorem observe_term_le (s : NodeState) (m : Message) :
    s.currentTerm ≤ (observeTerm s m).currentTerm := by
  have update (k : Nat) : s.currentTerm ≤ (updateTerm s k).currentTerm := by
    unfold updateTerm
    split <;> grind [becomeAwareOfNewTerm]
  cases m <;> simp only [observeTerm]
  all_goals first | exact Nat.le_refl _ | exact update _ | split <;> first | exact update _ | exact Nat.le_refl _

private theorem becomeCandidate_indices (self : NodeID) (s : NodeState) :
    Sends (fun post _ => s.currentTerm < post.currentTerm)
      (becomeCandidate (Capabilities.record self) s self) :=
  (becomeCandidate_sends self s).mono fun _ _ result => by
    rcases result with ⟨rfl, _⟩ | ⟨_, advance, _⟩
    · exact Nat.lt_succ_self _
    · rw [advance.term]
      exact Nat.lt_succ_self _

private theorem preVote_indices (self : NodeID) (s : NodeState) :
    Sends (fun post _ => post.currentTerm = s.currentTerm → IndexSame s post)
      (becomePreVoteCandidate (Capabilities.record self) s self) := by
  unfold becomePreVoteCandidate
  refine Sends.ite' (fun _ => ?_) (fun _ => ?_)
  · exact (becomeCandidate_indices self _).mono fun _ _ lt eq => (Nat.ne_of_gt lt eq).elim
  · refine Sends.bind' (broadcast_sends self _ _) fun _ _ _ =>
      Sends.pure' fun _ => ⟨rfl, rfl⟩

private theorem receive_indices (self source : NodeID) (s : NodeState) (m : Message)
    (notPrimary : s.role ≠ .primary) :
    Sends (fun post _ => post.role = s.role → post.currentTerm = s.currentTerm → IndexSame s post)
      (receive (Capabilities.record self) self source s m) := by
  have preserved := observe_indices s m
  have mono := observe_term_le s m
  have observed : (observeTerm s m).role ≠ .primary := by
    rcases (LeaderEffect.observe_progress s m).2 with eq | eq <;> simp [eq, notPrimary]
  cases m <;> simp only [receive]
  all_goals refine Sends.ite' (fun _ => Sends.pure' (fun _ _ => IndexSame.refl s)) (fun _ => ?_)
  · exact (ae_indices self source _ _).mono fun _ _ hp _ _ => preserved.trans hp
  · unfold handleAppendEntriesResponse
    refine Sends.ite' (fun _ => Sends.pure' (fun _ _ => preserved)) (fun no => ?_)
    exact (no (by simpa using observed)).elim
  · unfold handleRequestVoteRequest
    refine Sends.bind' (Sends.send _ _ _) fun _ _ _ => ?_
    split <;> exact Sends.pure' (fun _ _ => preserved)
  · unfold handleRequestVoteResponse
    refine Sends.ite' (fun yes => ?_) (fun _ => Sends.pure' (fun _ _ => preserved))
    refine (electIfQuorum_sends self _).mono fun _ _ result role term => ?_
    rcases result with ⟨rfl, _⟩ | ⟨_, _, won, _⟩
    · exact preserved
    · have eq := observe_same_term s _ (won.term.symm.trans term)
      have wasCandidate : s.role = .candidate := eq ▸ yes.1
      rcases won.facts.2.2 with same | none
      · rw [role, wasCandidate] at same
        contradiction
      · grind
  · unfold handleRequestPreVoteRequest
    exact Sends.bind' (Sends.send _ _ _) fun _ _ _ => Sends.pure' fun _ _ => preserved
  · unfold handleRequestPreVoteResponse
    refine Sends.ite' (fun _ => ?_) (fun _ => Sends.pure' (fun _ _ => preserved))
    refine Sends.ite' (fun _ => ?_) (fun _ => Sends.pure' (fun _ _ => preserved))
    exact (becomeCandidate_indices self _).mono fun _ _ lt _ eq =>
      (Nat.ne_of_gt (Nat.lt_of_le_of_lt mono lt) eq).elim
  · unfold handleProposeRequestVoteRequest
    refine Sends.ite' (fun _ => ?_) (fun _ => Sends.pure' (fun _ _ => preserved))
    exact (becomeCandidate_indices self _).mono fun _ _ lt _ eq =>
      (Nat.ne_of_gt (Nat.lt_of_le_of_lt mono lt) eq).elim

private theorem step_indices (self : NodeID) (s : NodeState) (event : Event)
    (notPrimary : s.role ≠ .primary) :
    Sends (fun post _ => post.role = s.role → post.currentTerm = s.currentTerm → IndexSame s post)
      (Model.Node.step (Capabilities.record self) self s event) := by
  cases event with
  | receive source m => exact receive_indices self source s m notPrimary
  | internal input =>
    cases input with
    | append entries =>
      simp only [Model.Node.step, act, appendBatch]
      exact Sends.guard_bind fun guard => (notPrimary guard.1).elim
    | sendEntries target endIndex =>
      simp only [Model.Node.step, act, sendEntries]
      exact Sends.guard_bind fun guard => (notPrimary guard.1).elim
    | timeout kind =>
      cases kind
      · simp only [Model.Node.step, act, startElection]
        exact Sends.guard_bind fun _ =>
          (preVote_indices self s).mono fun _ _ ih _ => ih
      · simp only [Model.Node.step, act, checkQuorum]
        exact Sends.guard_bind fun guard => (notPrimary guard.1).elim
    | nominateSuccessor =>
      exact (nominate_sends self s).mono fun _ _ h _ _ => (notPrimary h.2.1).elim
    | initAsBackup entries =>
      simp only [Model.Node.step, act, initAsBackup]
      exact Sends.guard_bind fun _ => Sends.pure' fun _ _ => ⟨rfl, rfl⟩

/-- The progress functions need no arbitrary index cutoff. For a primary,
the existing network probes are complete; with unchanged nonprimary role
and term the progress functions are unchanged. -/
private theorem same_actor [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) :
    LeaderEffect.sameNode (LeaderEffect.probes f.current t) c.pre c.post = true ↔ c.pre = c.post := by
  by_cases primary : c.post.role = .primary
  · exact LeaderEffect.sameNode_actor_iff c primary
  constructor
  · intro test
    have fields := (LeaderEffect.and_true.mp test).1
    have ⟨role, term, _⟩ := LeaderEffect.ordinaryEq_fields fields
    have notPrimary : c.pre.role ≠ .primary := fun h => primary (role.symm.trans h)
    obtain ⟨_, _, unchanged⟩ := step_indices c.actor c.pre c.event notPrimary _ _ _ c.tr.ran
    have eq := unchanged role.symm term.symm
    exact LeaderEffect.eq_of_fields fields eq.1.symm eq.2.symm
  · intro eq
    rw [eq]
    exact LeaderEffect.sameNode_refl _ _

private def actionActor : Model.Action → NodeID
  | .local n _ => n
  | .deliver e => e.target

private theorem actionActor_eq [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) : actionActor (ActionContext.action c) = c.actor := by
  change actionActor (ActionContext.encode c.tr.actor c.tr.event) = c.tr.actor
  cases c.tr.event <;> rfl

/-- Snapshot data for the recorded actor, computed once for a batch of questions. -/
public structure View where
  bootstrap : NodeID
  before : Model.State
  after : Model.State
  past : List Model.State
  actor : NodeID
  pre : NodeState
  post : NodeState
  changed : Bool

private def pack (bootstrap : NodeID) (before after : Model.State) (past : List Model.State)
    (n : NodeID) (pre post : NodeState) : View :=
  ⟨bootstrap, before, after, past, n, pre, post,
    !(LeaderEffect.sameNode (LeaderEffect.probes before after) pre post)⟩

/-- Failure of either lookup is reported explicitly. It cannot happen on a
validated step, but callers may pass raw snapshots to the executable reader. -/
public def ofAction (cfg : FullProfile.Configuration) (before after : Model.State)
    (past : List Model.State) (act : Model.Action) : Option View := do
  let actor := actionActor act
  let pre ← nodeState before actor
  let post ← nodeState after actor
  return pack (cfg.min?.getD 0) before after past actor pre post

private def View.Matches [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (v : View) (c : Ctx f t) : Prop :=
  v = pack Config.INITIAL_PRIMARY f.current t v.past c.actor c.pre c.post ∧
    f.logs = Historical.logFacts (f.current :: v.past)

private theorem ofAction_matches (s : ActionProfile.Step) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    ∃ v, ofAction s.cfg s.before s.after s.past s.act = some v ∧ v.Matches s.context := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  let v := pack Config.INITIAL_PRIMARY s.frame.current s.after s.past c.actor c.pre c.post
  have action := (s.context_eq c).mpr rfl
  have pre : nodeState (FullProfile.current s.frame) c.actor = some c.pre := c.tr.found
  have post := Direct.nodeState_of_mem c.keys_after c.post_now
  refine ⟨v, ?_, rfl, ?_⟩
  · rw [← s.current_eq, ← action]
    simp [ofAction, actionActor_eq, pre, post, v, Config.INITIAL_PRIMARY]
    rfl
  · change (StateCoverage.frame s.before s.past).logs = _
    rw [StateCoverage.frame_logs]
    change Historical.logFacts (s.before :: s.past) =
      Historical.logFacts (FullProfile.current s.frame :: s.past)
    rw [s.current_eq]

private theorem next_now [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) {n : NodeID} {st : NodeState} (mem : Now (f.advance t) n st) :
    Now f n st ↔ n ≠ c.actor ∨ c.pre = c.post := by
  rcases c.now_after mem with ⟨rfl, rfl⟩ | ⟨other, old⟩
  · simpa only [ne_eq, not_true_eq_false, false_or] using
      (show Now f c.actor c.post ↔ c.pre = c.post from
        ⟨fun h => (c.now_pre h).symm, fun h => h ▸ c.pre_now⟩)
  · exact ⟨fun _ => .inl other, fun _ => old⟩

private theorem any_fresh_now [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) : (∃ n st, Now (f.advance t) n st ∧ ¬ Now f n st) ↔ ¬ Now f c.actor c.post := by
  constructor
  · rintro ⟨n, st, now, fresh⟩
    rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, old⟩
    · exact fresh
    · exact (fresh old).elim
  · intro fresh
    exact ⟨c.actor, c.post, c.post_now, fresh⟩

private def observations (hist : List Model.State) (n : NodeID) : List Observation :=
  hist.flatMap fun s => (s.nodes.filter fun pair => pair.1 == n).map fun pair => observe pair.2

private instance : DecidableEq Observation := fun a b =>
  decidable_of_iff (a.currentTerm = b.currentTerm ∧ a.log = b.log) (by cases a; cases b; simp)

private def signatureIndices (l : List Entry) : List Nat :=
  (List.range (l.length + 1)).filter (isSignatureAt l)

private theorem sig_index {l : List Entry} {i : Nat} :
    isSignatureAt l i = true ↔ i ∈ signatureIndices l := by
  simp only [signatureIndices, List.mem_filter, List.mem_range, Nat.lt_succ_iff]
  exact ⟨fun h => ⟨signature_bound h, h⟩, And.right⟩

private theorem seen_mem [Config.InitialConfiguration] (hist : List Model.State)
    (n : NodeID) (o : Observation) :
    (Historical.logFacts hist).seen n o.currentTerm o.log ↔ o ∈ observations hist n := by
  rw [(Historical.logFacts_correct hist).seen]
  simp only [Historical.Seen, observations, List.mem_flatMap, List.mem_map, List.mem_filter,
    Prod.exists, beq_iff_eq]
  constructor
  · rintro ⟨st, ⟨s, hs, mem⟩, term, log⟩
    exact ⟨s, hs, n, st, ⟨mem, rfl⟩, by
      change Observation.mk st.currentTerm st.log = o
      rw [term, log]⟩
  · rintro ⟨s, hs, _, st, ⟨mem, rfl⟩, eq⟩
    exact ⟨st, ⟨s, hs, mem⟩, congrArg Observation.currentTerm eq, congrArg Observation.log eq⟩

private def ledAt (bootstrap : NodeID) (hist : List Model.State) (n k : Nat) : Bool :=
  (k == BOOTSTRAP_TERM && n == bootstrap) || CommitMonitor.elected n k hist

private theorem ledAt_true [Config.InitialConfiguration] (hist : List Model.State)
    (n k : Nat) :
    ledAt Config.INITIAL_PRIMARY hist n k = true ↔ (Historical.logFacts hist).led Config.INITIAL_PRIMARY n k := by
  simp only [ledAt, Bool.or_eq_true, LeaderEffect.and_true, beq_iff_eq, CommitMonitor.elected_iff,
    LogFacts.Ghost.led, (Historical.logFacts_correct hist).elected]

private def ledTerms (bootstrap : NodeID) (hist : List Model.State) (n : NodeID) : List Nat :=
  (BOOTSTRAP_TERM :: hist.flatMap fun s => s.nodes.map fun p => p.2.currentTerm).filter
    (ledAt bootstrap hist n)

private theorem led_mem [Config.InitialConfiguration] (hist : List Model.State) (n k : Nat) :
    (Historical.logFacts hist).led Config.INITIAL_PRIMARY n k ↔
      k ∈ ledTerms Config.INITIAL_PRIMARY hist n := by
  simp only [ledTerms, List.mem_filter, ledAt_true]
  refine ⟨fun h => ⟨?_, h⟩, And.right⟩
  rcases h with ⟨rfl, _⟩ | ⟨l, i, vote⟩
  · exact List.mem_cons_self ..
  · have ⟨a, b, r, suffix, elect⟩ := (Historical.logFacts_correct hist).elected n k l i |>.mp vote
    obtain ⟨x, y, _, mem, _, _, _, _, eq, _⟩ := elect
    exact List.mem_cons_of_mem _ (List.mem_flatMap.mpr
      ⟨a, List.IsSuffix.subset suffix (List.mem_cons_self ..), List.mem_map.mpr ⟨(n, y), mem, eq⟩⟩)

private def canonAt (bootstrap : NodeID) (term : Nat) (log : List Entry) : List Model.State → Bool
  | [] => false
  | s :: h => (s.nodes.any fun (n, st) =>
      decide (st.role ≠ .candidate ∧ st.currentTerm = term ∧ st.log = log) &&
      ledAt bootstrap (s :: h) n term) || canonAt bootstrap term log h

private theorem canonAt_true [Config.InitialConfiguration] (hist : List Model.State)
    (term : Nat) (log : List Entry) :
    canonAt Config.INITIAL_PRIMARY term log hist = true ↔ (Historical.logFacts hist).canon term log := by
  rw [(Historical.logFacts_correct hist).canon]
  induction hist with
  | nil => simp [canonAt, Historical.Canon, Historical.CanonNow, Historical.Now]
  | cons s h ih =>
    simp only [canonAt, Bool.or_eq_true, ih, List.any_eq_true, Prod.exists, LeaderEffect.and_true,
      decide_eq_true_eq, ledAt_true, LogFacts.Ghost.led, (Historical.logFacts_correct (s :: h)).elected]
    unfold Historical.Canon
    constructor
    · rintro (⟨n, st, mem, ⟨role, eq, logeq⟩, led⟩ | ⟨g, suf, witnesses⟩)
      · exact ⟨s :: h, List.suffix_refl _, n, st, ⟨mem, eq, role, led⟩, logeq⟩
      · exact ⟨g, List.suffix_cons_iff.mpr (.inr suf), witnesses⟩
    · rintro ⟨g, suf, n, st, now, eq⟩
      rcases List.suffix_cons_iff.mp suf with rfl | old
      · exact .inl ⟨n, st, now.1, ⟨now.2.2.1, now.2.1, eq⟩, now.2.2.2⟩
      · exact .inr ⟨g, old, n, st, now, eq⟩

private theorem fresh_canon [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) (past : List Model.State)
    (logs : f.logs = Historical.logFacts (f.current :: past)) :
    (∃ k log, Canon (f.advance t) k log ∧ ¬ Canon f k log) ↔
      c.post.role ≠ .candidate ∧ Led (f.advance t) c.actor c.post.currentTerm ∧
        ¬ Canon f c.post.currentTerm c.post.log := by
  constructor
  · rintro ⟨k, log, now, fresh⟩
    rcases c.canon_after now with old | ⟨n, st, ⟨mem, term, role, led⟩, logEq⟩
    · exact (fresh old).elim
    rcases c.now_after mem with ⟨rfl, rfl⟩ | ⟨other, was⟩
    · exact ⟨role, term ▸ led, fun h => fresh (term ▸ logEq ▸ h)⟩
    · apply (fresh ?_).elim
      have pastLed := c.led_other other led
      change f.logs.led Config.INITIAL_PRIMARY n k at pastLed
      change f.logs.canon k log
      rw [logs] at pastLed ⊢
      exact .inr ⟨n, st, ⟨was, term, role, pastLed⟩, logEq⟩
  · rintro ⟨role, led, fresh⟩
    exact ⟨_, _, Or.inr ⟨_, _, ⟨c.post_now, rfl, role, led⟩, rfl⟩, fresh⟩

section Rules
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State}
  {v : View} {c : Ctx f t} (ok : v.Matches c)
include ok

private theorem View.before_eq : f.current = v.before := (congrArg View.before ok.1).symm
private theorem View.after_eq : t = v.after := (congrArg View.after ok.1).symm
private theorem View.actor_eq : c.actor = v.actor := (congrArg View.actor ok.1).symm
private theorem View.pre_eq : c.pre = v.pre := (congrArg View.pre ok.1).symm
private theorem View.post_eq : c.post = v.post := (congrArg View.post ok.1).symm

private theorem View.old_post : Now f c.actor c.post ↔ v.changed = false := by
  have eq : v.changed = !(LeaderEffect.sameNode (LeaderEffect.probes f.current t) c.pre c.post) :=
    congrArg View.changed ok.1
  rw [eq, Bool.not_eq_false', same_actor c]
  exact ⟨fun h => (c.now_pre h).symm, fun h => h ▸ c.pre_now⟩

private theorem View.led_before (n k : Nat) :
    Led f n k ↔ k ∈ ledTerms v.bootstrap (v.before :: v.past) n := by
  change f.logs.led Config.INITIAL_PRIMARY n k ↔ _
  rw [ok.2, led_mem, ← View.before_eq ok]
  have bootstrap : v.bootstrap = Config.INITIAL_PRIMARY := congrArg View.bootstrap ok.1
  rw [bootstrap]

private theorem View.led_after (n k : Nat) :
    Led (f.advance t) n k ↔ k ∈ ledTerms v.bootstrap (v.after :: v.before :: v.past) n := by
  have logs : (f.advance t).logs = Historical.logFacts (t :: f.current :: v.past) := by
    change LogFacts.advance _ f.logs _ _ = _
    rw [ok.2]
    rfl
  change (f.advance t).logs.led Config.INITIAL_PRIMARY n k ↔ _
  rw [logs, led_mem, ← View.before_eq ok, ← View.after_eq ok]
  have bootstrap : v.bootstrap = Config.INITIAL_PRIMARY := congrArg View.bootstrap ok.1
  rw [bootstrap]

private theorem View.seen_before (n : NodeID) (o : Observation) :
    Seen f n o ↔ o ∈ observations (v.before :: v.past) n := by
  change f.logs.seen n _ _ ↔ _
  rw [ok.2, seen_mem, View.before_eq ok]

private theorem View.seen_after (n : NodeID) (o : Observation) :
    Seen (f.advance t) n o ↔ o ∈ observations (v.after :: v.before :: v.past) n := by
  have logs : (f.advance t).logs = Historical.logFacts (t :: f.current :: v.past) := by
    change LogFacts.advance _ f.logs _ _ = _
    rw [ok.2]
    rfl
  change (f.advance t).logs.seen n _ _ ↔ _
  rw [logs, seen_mem, View.before_eq ok, View.after_eq ok]

private theorem View.canon_before (k : Nat) (l : List Entry) :
    Canon f k l ↔ canonAt v.bootstrap k l (v.before :: v.past) = true := by
  change f.logs.canon k l ↔ _
  rw [ok.2, ← canonAt_true, View.before_eq ok]
  have bootstrap : v.bootstrap = Config.INITIAL_PRIMARY := congrArg View.bootstrap ok.1
  rw [bootstrap]

private theorem View.any_fresh_canon :
    (∃ k log, (f.advance t).logs.canon k log ∧ ¬ f.logs.canon k log) ↔
      c.post.role ≠ .candidate ∧ Led (f.advance t) c.actor c.post.currentTerm ∧
        ¬ Canon f c.post.currentTerm c.post.log :=
  fresh_canon c v.past ok.2

private theorem View.other_log :
    (∃ n st, Now (f.advance t) n st ∧ ∃ e, e ∈ st.log ∧ n ≠ c.actor ∧ Now f n st) ↔
      (∃ p ∈ v.after.nodes, p.2.log ≠ [] ∧ p.1 ≠ v.actor) := by
  rw [← View.after_eq ok, ← View.actor_eq ok]
  constructor
  · rintro ⟨n, st, now, e, mem, other, _⟩
    exact ⟨(n, st), now, List.ne_nil_of_mem mem, other⟩
  · rintro ⟨⟨n, st⟩, now, log, other⟩
    obtain ⟨e, mem⟩ := List.exists_mem_of_ne_nil st.log log
    exact ⟨n, st, now, e, mem, other, (next_now c now).mpr (.inl other)⟩

end Rules

end ConsensusCoverage.GuardedDomain
