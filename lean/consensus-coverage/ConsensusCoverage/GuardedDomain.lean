module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ActionProfile
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.ActionContext
import all ConsensusCoverage.LeaderEffect
import all ConsensusCoverage.StateCoverage
import all ConsensusCoverage.CommitKeys
import all ConsensusCoverage.GrantMonitor
import all ConsensusCoverage.Historical
import all Consensus.Proofs.SafetyInvariant

/-!
Finite domains for guarded questions on an actual protocol step.
Each domain is justified by a specific predicate (such as `Pending`, `Seen`,
or `Committed`); there is no uniform cutoff for unrestricted quantifiers.
-/

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
  (becomeCandidate_result self s s rfl).mono fun _ _ result => by
    obtain ⟨_, _, _, _, outcome⟩ := result
    rcases outcome with ⟨rfl, _⟩ | ⟨_, advance, _⟩
    · simp [freshCandidate]
    · simp [advance.term, primaryState, freshCandidate]

private theorem preVote_indices (self : NodeID) (s : NodeState) :
    Sends (fun post _ => post.currentTerm = s.currentTerm → IndexSame s post)
      (becomePreVoteCandidate (Capabilities.record self) s self) := by
  unfold becomePreVoteCandidate
  refine Sends.ite' (fun _ => ?_) (fun _ => ?_)
  · exact (becomeCandidate_indices self _).mono fun _ _ lt eq => (Nat.ne_of_gt lt eq).elim
  · refine Sends.bind' (broadcast_sends self _ _) fun _ _ _ =>
      Sends.pure' fun _ => ⟨rfl, rfl⟩

private theorem receive_indices [Config.InitialConfiguration]
    (self source : NodeID) (s : NodeState) (m : Message)
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
    rcases result with ⟨rfl, _⟩ | ⟨_, won, _⟩
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

private theorem step_indices [Config.InitialConfiguration]
    (self : NodeID) (s : NodeState) (event : Event)
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
  cfg : FullProfile.Configuration
  before : Model.State
  after : Model.State
  past : List Model.State
  actor : NodeID
  pre : NodeState
  post : NodeState
  changed : Bool

private def pack (cfg : FullProfile.Configuration) (before after : Model.State) (past : List Model.State)
    (n : NodeID) (pre post : NodeState) : View :=
  ⟨cfg, before, after, past, n, pre, post,
    !(LeaderEffect.sameNode (LeaderEffect.probes before after) pre post)⟩

/-- Failure of either lookup is reported explicitly. It cannot happen on a
validated step, but callers may pass raw snapshots to the executable reader. -/
@[expose] public def ofAction (cfg : FullProfile.Configuration) (before after : Model.State)
    (past : List Model.State) (act : Model.Action) : Option View := do
  let actor := actionActor act
  let pre ← nodeState before actor
  let post ← nodeState after actor
  return pack cfg before after past actor pre post

private def View.Matches [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (v : View) (c : Ctx f t) : Prop :=
  v = pack Config.INITIAL_CONFIGURATION f.current t v.past c.actor c.pre c.post ∧
    f = StateCoverage.frame v.before v.past

private theorem ofAction_matches (s : ActionProfile.Step) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    ∃ v, ofAction s.cfg s.before s.after s.past s.act = some v ∧ v.Matches s.context := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  let v := pack s.cfg s.frame.current s.after s.past c.actor c.pre c.post
  have action := (s.context_eq c).mpr rfl
  have pre : nodeState (FullProfile.current s.frame) c.actor = some c.pre := c.tr.found
  have post : nodeState s.after c.actor = some c.post := by
    unfold nodeState
    cases h : s.after.nodes.find? (fun entry => entry.1 == c.actor) with
    | none =>
      have missing := List.find?_eq_none.mp h _ c.post_now
      simp at missing
    | some entry =>
      obtain ⟨key, state⟩ := entry
      have hit := List.find?_some h
      have same : key = c.actor := by simpa using hit
      subst key
      exact congrArg some (c.now_post (List.mem_of_find?_eq_some h))
  refine ⟨v, ?_, rfl, ?_⟩
  · rw [← s.current_eq, ← action]
    change (do
      let pre ← nodeState (FullProfile.current s.frame) (actionActor (ActionContext.action c))
      let post ← nodeState s.after (actionActor (ActionContext.action c))
      some (pack s.cfg (FullProfile.current s.frame) s.after s.past
        (actionActor (ActionContext.action c)) pre post)) = some v
    simp only [actionActor_eq, pre, post]
    rfl
  · change s.frame = StateCoverage.frame (FullProfile.current s.frame) s.past
    rw [s.current_eq]
    rfl

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

/-- The node IDs and records available in a snapshot. `Now` guards justify
using these finite lists even though node records contain functions. -/
@[expose] public def nodeIds (s : Model.State) : List NodeID := s.nodes.map Prod.fst

@[expose] public def recordsAt (s : Model.State) (n : NodeID) : List NodeState :=
  (s.nodes.filter fun p => p.1 == n).map Prod.snd

private theorem mem_nodeIds {s : Model.State} {n : NodeID} {st : NodeState}
    (mem : (n, st) ∈ s.nodes) : n ∈ nodeIds s :=
  List.mem_map.mpr ⟨(n, st), mem, rfl⟩

private theorem mem_recordsAt {s : Model.State} {n : NodeID} {st : NodeState} :
    st ∈ recordsAt s n ↔ (n, st) ∈ s.nodes := by
  simp only [recordsAt, List.mem_map, List.mem_filter, Prod.exists, beq_iff_eq]
  grind

private theorem mem_node_domain {s : Model.State} {n : NodeID} {st : NodeState} :
    (n, st) ∈ s.nodes ↔ n ∈ nodeIds s ∧ st ∈ recordsAt s n :=
  ⟨fun mem => ⟨mem_nodeIds mem, mem_recordsAt.mpr mem⟩,
    fun ⟨_, mem⟩ => mem_recordsAt.mp mem⟩

/-- Every prefix of a known log, including the empty and full prefixes. -/
@[expose] public def logPrefixes (l : List Entry) : List (List Entry) :=
  (List.range (l.length + 1)).map fun i => l.take i

private theorem mem_logPrefixes (l p : List Entry) :
    p <+: l ↔ p ∈ logPrefixes l := by
  constructor
  · intro sub
    exact List.mem_map.mpr ⟨p.length, List.mem_range.mpr (Nat.lt_succ_of_le sub.length_le),
      (List.prefix_iff_eq_take.mp sub).symm⟩
  · intro mem
    obtain ⟨i, _, rfl⟩ := List.mem_map.mp mem
    exact List.take_prefix i l

private def keyTerms (keys : List CommitKeys.Key) : List Nat := keys.map Prod.fst

private def keyPrefixes (keys : List CommitKeys.Key) (k : Nat) : List (List Entry) :=
  (keys.filter fun key => key.1 == k).map Prod.snd

private theorem mem_key_domain (keys : List CommitKeys.Key) (k : Nat) (p : List Entry) :
    (k, p) ∈ keys ↔ k ∈ keyTerms keys ∧ p ∈ keyPrefixes keys k := by
  simp only [keyTerms, keyPrefixes, List.mem_map, List.mem_filter, Prod.exists, beq_iff_eq]
  grind

private def observations (hist : List Model.State) (n : NodeID) : List Observation :=
  hist.flatMap fun s => (s.nodes.filter fun pair => pair.1 == n).map fun pair => observe pair.2

private instance : DecidableEq Observation := fun a b =>
  decidable_of_iff (a.currentTerm = b.currentTerm ∧ a.log = b.log) (by cases a; cases b; simp)

private def signatureIndices (l : List Entry) : List Nat :=
  (List.range (l.length + 1)).filter (isSignatureAt l)

private theorem sig_index [Config.InitialConfiguration] {l : List Entry} {i : Nat} :
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

private def ledTerms (cfg : FullProfile.Configuration) (hist : List Model.State) (n : NodeID) : List Nat :=
  (BOOTSTRAP_TERM :: hist.flatMap fun s => s.nodes.map fun p => p.2.currentTerm).filter
    (fun k => GrantMonitor.led cfg hist n k)

private theorem led_mem [Config.InitialConfiguration] (s : Model.State) (h : List Model.State)
    (n : NodeID) (k : Nat) :
    Led (StateCoverage.frame s h) n k ↔ k ∈ ledTerms Config.INITIAL_CONFIGURATION (s :: h) n := by
  simp only [ledTerms, List.mem_filter, GrantMonitor.led_iff]
  change (StateCoverage.frame s h).logs.led Config.INITIAL_PRIMARY n k ↔ _
  refine ⟨fun led => ⟨?_, led⟩, And.right⟩
  rcases led with ⟨rfl, _⟩ | ⟨l, i, vote⟩
  · exact List.mem_cons_self ..
  · have ⟨a, b, r, suffix, elect⟩ := (Historical.frame_correct s h).elected n k l i |>.mp vote
    obtain ⟨x, y, _, mem, _, _, _, _, eq, _⟩ := elect
    exact List.mem_cons_of_mem _ (List.mem_flatMap.mpr
      ⟨a, List.IsSuffix.subset suffix (List.mem_cons_self ..), List.mem_map.mpr ⟨(n, y), mem, eq⟩⟩)

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
      have pastLed := c.led_after led id fun _ _ won => (other (c.electStep won).1).elim
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
private theorem View.cfg_eq : Config.INITIAL_CONFIGURATION = v.cfg := (congrArg View.cfg ok.1).symm

private theorem View.frame_after : f.advance t = StateCoverage.frame v.after (v.before :: v.past) := by
  rw [ok.2, View.after_eq ok]
  rfl

private theorem View.logs_folded : f.logs = Historical.logFacts (f.current :: v.past) := by
  rw [View.before_eq ok]
  exact (congrArg Frame.logs ok.2).trans (Historical.frame_logs ..)

private theorem View.old_post : Now f c.actor c.post ↔ v.changed = false := by
  have eq : v.changed = !(LeaderEffect.sameNode (LeaderEffect.probes f.current t) c.pre c.post) :=
    congrArg View.changed ok.1
  rw [eq, Bool.not_eq_false', same_actor c]
  exact ⟨fun h => (c.now_pre h).symm, fun h => h ▸ c.pre_now⟩

private theorem View.now_before (n : NodeID) (st : NodeState) :
    Now f n st ↔ (n, st) ∈ v.before.nodes := by
  unfold Now
  rw [View.before_eq ok]

private theorem View.now_after (n : NodeID) (st : NodeState) :
    Now (f.advance t) n st ↔ (n, st) ∈ v.after.nodes := by
  change (n, st) ∈ t.nodes ↔ _
  rw [View.after_eq ok]

private theorem View.record_before (n : NodeID) (st : NodeState) :
    Now f n st ↔ st ∈ recordsAt v.before n :=
  (View.now_before ok n st).trans mem_recordsAt.symm

private theorem View.record_after (n : NodeID) (st : NodeState) :
    Now (f.advance t) n st ↔ st ∈ recordsAt v.after n :=
  (View.now_after ok n st).trans mem_recordsAt.symm

private theorem View.node_domain_before (n : NodeID) (st : NodeState) :
    Now f n st ↔ n ∈ nodeIds v.before ∧ st ∈ recordsAt v.before n :=
  (View.now_before ok n st).trans mem_node_domain

private theorem View.node_domain_after (n : NodeID) (st : NodeState) :
    Now (f.advance t) n st ↔ n ∈ nodeIds v.after ∧ st ∈ recordsAt v.after n :=
  (View.now_after ok n st).trans mem_node_domain

private theorem View.pending_before (e : Model.Envelope) :
    Pending f e ↔ e ∈ v.before.network := by
  unfold Pending
  rw [View.before_eq ok]

private theorem View.pending_after (e : Model.Envelope) :
    Pending (f.advance t) e ↔ e ∈ v.after.network := by
  change e ∈ t.network ↔ _
  rw [View.after_eq ok]

private theorem View.led_before (n k : Nat) :
    Led f n k ↔ k ∈ ledTerms v.cfg (v.before :: v.past) n := by
  rw [ok.2, led_mem, View.cfg_eq ok]

private theorem View.led_after (n k : Nat) :
    Led (f.advance t) n k ↔ k ∈ ledTerms v.cfg (v.after :: v.before :: v.past) n := by
  rw [View.frame_after ok, led_mem, View.cfg_eq ok]

private theorem View.seen_before (n : NodeID) (o : Observation) :
    Seen f n o ↔ o ∈ observations (v.before :: v.past) n := by
  change f.logs.seen n _ _ ↔ _
  rw [View.logs_folded ok, seen_mem, View.before_eq ok]

private theorem View.seen_after (n : NodeID) (o : Observation) :
    Seen (f.advance t) n o ↔ o ∈ observations (v.after :: v.before :: v.past) n := by
  rw [View.frame_after ok]
  change (StateCoverage.frame v.after (v.before :: v.past)).logs.seen n _ _ ↔ _
  rw [Historical.frame_logs, seen_mem]

private def canonAt (cfg : FullProfile.Configuration) (term : Nat) (log : List Entry)
    (hist : List Model.State) : Bool :=
  (CommitKeys.canonical cfg hist).contains (term, log)

private theorem View.canon_before (k : Nat) (l : List Entry) :
    Canon f k l ↔ canonAt v.cfg k l (v.before :: v.past) = true := by
  rw [ok.2, canonAt, List.contains_iff_mem, ← View.cfg_eq ok, CommitKeys.mem_canonical]
  exact (Historical.frame_correct ..).canon k l

private theorem View.keys_before (k : Nat) (l : List Entry) :
    Committed f k l ↔ (k, l) ∈ CommitKeys.keys v.cfg (v.before :: v.past) := by
  rw [← View.cfg_eq ok, CommitKeys.mem_iff, ← ok.2]

private theorem View.keys_after (k : Nat) (l : List Entry) :
    Committed (f.advance t) k l ↔ (k, l) ∈ CommitKeys.keys v.cfg (v.after :: v.before :: v.past) := by
  rw [← View.cfg_eq ok, CommitKeys.mem_iff, ← View.frame_after ok]

private theorem View.key_domain_before (k : Nat) (l : List Entry) :
    let keys := CommitKeys.keys v.cfg (v.before :: v.past)
    Committed f k l ↔ k ∈ keyTerms keys ∧ l ∈ keyPrefixes keys k :=
  (View.keys_before ok k l).trans (mem_key_domain _ k l)

private theorem View.key_domain_after (k : Nat) (l : List Entry) :
    let keys := CommitKeys.keys v.cfg (v.after :: v.before :: v.past)
    Committed (f.advance t) k l ↔ k ∈ keyTerms keys ∧ l ∈ keyPrefixes keys k :=
  (View.keys_after ok k l).trans (mem_key_domain _ k l)

private theorem View.backed_before (l : List Entry) (i k : Nat) :
    Backed f l i k ↔ CommitKeys.backed v.cfg (v.before :: v.past) l i k = true := by
  rw [← View.cfg_eq ok, CommitKeys.backed_iff, ← ok.2]

private theorem View.backed_after (l : List Entry) (i k : Nat) :
    Backed (f.advance t) l i k ↔ CommitKeys.backed v.cfg (v.after :: v.before :: v.past) l i k = true := by
  rw [← View.cfg_eq ok, CommitKeys.backed_iff, ← View.frame_after ok]

private theorem View.fresh_commit (k : Nat) (l : List Entry) :
    (Committed (f.advance t) k l ∧ ¬ Committed f k l) ↔
      CommitKeys.fresh v.cfg v.after (v.before :: v.past) k l = true := by
  rw [← View.cfg_eq ok, CommitKeys.fresh_iff, ← ok.2, ← View.frame_after ok]

private theorem View.any_fresh_commit :
    (∃ k l, Committed (f.advance t) k l ∧ ¬ Committed f k l) ↔
      CommitKeys.anyFresh v.cfg v.after (v.before :: v.past) = true := by
  rw [← View.cfg_eq ok, CommitKeys.anyFresh_iff, ← ok.2, ← View.frame_after ok]

private theorem View.any_fresh_canon :
    (∃ k log, (f.advance t).logs.canon k log ∧ ¬ f.logs.canon k log) ↔
      c.post.role ≠ .candidate ∧ Led (f.advance t) c.actor c.post.currentTerm ∧
        ¬ Canon f c.post.currentTerm c.post.log :=
  fresh_canon c v.past (View.logs_folded ok)

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

private def actorReplay : Option (Bool × Bool) := do
  let cfg : FullProfile.Configuration := {0, 1}
  let before : Model.State := {nodes := [0, 1, 2].map fun n => (n, initialNodeState cfg n)}
  let heartbeat : Model.Action := .local 0 (.sendEntries 1 0)
  let install : Model.Action := .local 2 (.initAsBackup [])
  let sent ← networkStep cfg before heartbeat
  let joined ← networkStep cfg sent install
  let unchanged ← ofAction cfg before sent [] heartbeat
  let changed ← ofAction cfg sent joined [before] install
  return (unchanged.changed, changed.changed)

private theorem actorReplay_check : actorReplay = some (false, true) := by
  decide +kernel

end ConsensusCoverage.GuardedDomain
