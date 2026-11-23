module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public meta import Lean
public import ConsensusCoverage.DelayedNominationRead
import all ConsensusCoverage.ActionContext
import all ConsensusCoverage.CommitKeys
import all ConsensusCoverage.DelayedNominationRead
import all ConsensusCoverage.DelayedNominationPrune
import all ConsensusCoverage.DelayedNominationSingleton
import all ConsensusCoverage.NoBackingWitness
import all ConsensusCoverage.NominationArms
import all ConsensusCoverage.ReducedQuestions
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.DelayedNomination

open CCF CCF.MultiNodeTransitionSystem
open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open ActionProfile SolvedWitnesses

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192
set_option maxHeartbeats 0

private abbrev Fresh [Config.InitialConfiguration] (f : Frame) (t : Model.State) : Prop :=
  ∃ k p, Committed (f.advance t) k p ∧ ¬ Committed f k p

private theorem newKey (s : Step) (h : test s.cfg s.before s.act s.after s.past = true) :
    @Fresh ⟨s.cfg⟩ s.frame s.after := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  exact (CommitKeys.fresh_iff s.context).mp ((label_true s _).mp ((test_iff s).mp h).2.1)

private theorem recordedInput (s : Step) (st : @Stable ⟨s.cfg⟩ s.frame s.after s.context) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    s.act = .local s.context.actor .nominateSuccessor := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  rw [← (s.context_eq s.context).mpr rfl]
  change ActionContext.encode s.context.actor s.context.event = _
  rw [st.event]
  rfl

private theorem lookup_eq (table : List (NodeID × NodeState)) (key : NodeID) :
    table.lookup key = (table.find? fun p => p.1 == key).map Prod.snd := by
  induction table with
  | nil => rfl
  | cons p rest ih =>
    obtain ⟨n, x⟩ := p
    by_cases h : n = key
    · subst n
      simp [List.lookup, List.find?]
    · have a : (key == n) = false := by simpa using Ne.symm h
      have b : (n == key) = false := by simpa using h
      simp [List.lookup, List.find?, a, b, ih]

private theorem sends_iff (s : Step) (st : @Stable ⟨s.cfg⟩ s.frame s.after s.context) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    sends s.before s.act = true ↔ ∃ target,
      findSuccessor s.context.pre s.context.actor = some target := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have current : s.frame.current = s.before := s.current_eq
  have found : nodeState s.before s.context.actor = some s.context.pre :=
    (congrArg (fun snap : Model.State => nodeState snap s.context.actor) current).symm.trans s.context.tr.found
  simp only [sends, recordedInput s st, lookup_eq]
  change (nodeState s.before s.context.actor).any (fun n => (findSuccessor n s.context.actor).isSome) = true ↔ _
  rw [found]
  cases eq : findSuccessor s.context.pre s.context.actor <;> simp [eq]

private theorem another (s : Step) (h : test s.cfg s.before s.act s.after s.past = true) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    ∃ n st, n ≠ s.context.actor ∧ Now s.frame n st := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have current : s.frame.current = s.before := s.current_eq
  classical
  by_cases yes : ∃ n st, n ≠ s.context.actor ∧ Now s.frame n st
  · exact yes
  have all : ∀ n ∈ s.nodes, n = s.context.actor := by
    intro n mem
    rw [← NoBackingWitness.run_keys s.run s.before List.mem_cons_self] at mem
    obtain ⟨⟨v, st⟩, member, rfl⟩ := List.mem_map.mp mem
    by_cases eq : v = s.context.actor
    · exact eq
    exact (yes ⟨v, st, eq, show (v, st) ∈ s.frame.current.nodes from current.symm ▸ member⟩).elim
  have has : s.context.actor ∈ s.nodes := by
    rw [← NoBackingWitness.run_keys s.run s.before List.mem_cons_self]
    have pre : (s.context.actor, s.context.pre) ∈ s.frame.current.nodes := s.context.pre_now
    exact List.mem_map_of_mem (f := Prod.fst) (current ▸ pre)
  have distinct := s.context.inv.distinct
  change (s.frame.current.nodes.map Prod.fst).Nodup at distinct
  rw [current, NoBackingWitness.run_keys s.run s.before List.mem_cons_self] at distinct
  have singleton : s.nodes = [s.context.actor] := by
    cases eq : s.nodes with
    | nil => simp [eq] at has
    | cons hd tl =>
      have hdEq := all hd (eq ▸ List.mem_cons_self)
      have noMem : s.context.actor ∉ tl :=
        hdEq ▸ (List.nodup_cons.mp (eq ▸ distinct)).1
      cases ht : tl with
      | nil => simp [hdEq]
      | cons x xs =>
        have hx := all x (eq.symm ▸ List.mem_cons_of_mem _ (ht.symm ▸ List.mem_cons_self))
        have mem : x ∈ tl := ht.symm ▸ List.mem_cons_self
        exact (noMem (hx ▸ mem)).elim
  have noNew := singleton_noNew s s.context.actor singleton (before_nodes s ((test_iff s).mp h).1)
  have fresh := ((test_iff s).mp h).2.1
  simp only [← CommitKeys.fresh_answer, noNew] at fresh
  cases fresh

public theorem other_answer (s : Step) (h : test s.cfg s.before s.act s.after s.past = true) :
    other s.before s.act = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨n, st, ne, mem⟩ := another s h
  rw [recordedInput s (stable s h)]
  have hn : (n, st) ∈ s.frame.current.nodes := mem
  have current : s.frame.current = s.before := s.current_eq
  exact List.any_eq_true.mpr ⟨(n, st), current ▸ hn, by simpa using ne⟩

variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}

private theorem r45 (key : Fresh f t) : reach_45 f t c c :=
  let ⟨k, p, a, b⟩ := key; ⟨k, p, a, b, rfl⟩

private theorem r6 (key : Fresh f t) : reach_6 f t c c :=
  let ⟨k, p, a, b⟩ := key; ⟨k, p, a, b, rfl⟩

private theorem r57 (key : Fresh f t) : reach_57 f t c c :=
  .inl ⟨r6 key, c.post_now, c.post_now, c.post_now, c.inv.terms c.actor c.pre c.pre_now, rfl⟩

private theorem r427 (key : Fresh f t) : reach_427 f t c t c.tr :=
  .inr (.inr ⟨⟨r57 key, rfl⟩, rfl, HEq.rfl⟩)

private theorem r2289 (st : Stable f t c) (key : Fresh f t) : reach_2289 f t c c.actor c.pre :=
  ⟨c.event, ⟨t, c.tr, r427 key, rfl, rfl, rfl⟩, st.event⟩

private theorem r1009 (st : Stable f t c) (key : Fresh f t) :
    reach_1009 f t c c.post.log c.pre.log :=
  .inl ⟨r45 key, c.post_now, c.post_now, c.post_now,
    st.post ▸ List.prefix_refl c.pre.log, c.inv.rooted c.actor c.pre c.pre_now, rfl, rfl⟩

private theorem rootPositive (st : Stable f t c) (key : Fresh f t) :
    sig c .rooted_now_after_inl ∧ sig c .rooted_post_log_inl := by
  refine ⟨Or.inr (Or.inl ⟨r45 key, c.post_now⟩), Or.inr (Or.inl ⟨r45 key, ?_⟩)⟩
  exact ⟨c.post_now, c.post_now, c.post_now, st.post ▸ List.prefix_refl c.pre.log,
    c.inv.rooted c.actor c.pre c.pre_now⟩

private theorem sortedPositive (st : Stable f t c) (key : Fresh f t) :
    sig c .sorted_now_after_inl ∧ sig c .sorted_post_log_inl := by
  refine ⟨Or.inr (Or.inl ⟨r6 key, c.post_now⟩), Or.inr (Or.inl ⟨r6 key, ?_⟩)⟩
  exact ⟨c.post_now, c.post_now, c.post_now, st.post ▸ List.prefix_refl c.pre.log,
    c.inv.terms c.actor c.pre c.pre_now⟩

private theorem otherPositive (st : Stable f t c) (key : Fresh f t)
    {n x} (ne : n ≠ c.actor) (now : Now f n x) :
    sig c .rooted_now_after_inr ∧ sig c .sorted_now_after_inr := by
  have next : Now (f.advance t) n x := stNow st ▸ now
  exact ⟨.inl ⟨r45 key, n, x, next, ne, now⟩, .inl ⟨r6 key, n, x, next, ne, now⟩⟩

private theorem appTerms (st : Stable f t c) :
    c.post.log = c.pre.log ++ [] ∧
      (∀ e ∈ ([] : List Entry), e.term = c.pre.currentTerm) ∧ c.pre.role = .primary ∧
      c.post.currentTerm = c.pre.currentTerm ∧ c.post.role ≠ .candidate :=
  ⟨by simp [st.post], by simp, stRole st, congrArg NodeState.currentTerm st.post,
    by simp [st.post, stRole st]⟩

set_option hygiene false in
local macro "fill_log" : tactic => `(tactic| (repeat' first
  | exact c.post_now
  | exact appTerms st
  | exact (appTerms st).1
  | exact (appTerms st).2.1
  | exact (appTerms st).2.2.1
  | exact (appTerms st).2.2.2.1
  | exact (appTerms st).2.2.2.2
  | exact c.inv.rooted c.actor c.pre c.pre_now
  | exact c.inv.terms c.actor c.pre c.pre_now
  | apply And.intro))

private theorem rootAppend (st : Stable f t c) (key : Fresh f t) :
    sig c .rooted_post_log_inr_inl := by
  reach_arm reach_45
  refine ⟨r45 key, c.post_now, c.post_now, c.post_now, Or.inl ⟨[], appTerms st⟩,
    ⟨[], appTerms st⟩, [], ?_⟩
  fill_log

private theorem sortedAppend (st : Stable f t c) (key : Fresh f t) :
    sig c .sorted_post_log_inr_inl := by
  reach_arm reach_6
  refine ⟨r6 key, c.post_now, c.post_now, c.post_now, Or.inl ⟨[], appTerms st⟩,
    ⟨[], appTerms st⟩, [], ?_⟩
  fill_log

private theorem copyProof (st : Stable f t c) :
    CopyLog f.logs c.post.currentTerm c.pre.log ∧ c.pre.log.length ≤ c.pre.log.length ∧
      c.post.log = c.pre.log.take c.pre.log.length := by
  rw [st.post, List.take_length]
  exact ⟨currentCopyLog c.inv.rooted c.inv.terms c.inv.sorted c.inv.anchor c.actor c.pre c.pre_now,
    Nat.le_refl _, rfl⟩

set_option hygiene false in
local macro "fill_copy" : tactic => `(tactic| (repeat' first
  | exact copyProof st
  | exact (copyProof st).1
  | exact (copyProof st).2
  | exact (copyProof st).2.1
  | exact (copyProof st).2.2
  | exact c.inv.rooted c.actor c.pre c.pre_now
  | exact c.inv.terms c.actor c.pre c.pre_now
  | apply And.intro))

private theorem rootCopy (st : Stable f t c) (key : Fresh f t) :
    sig c .rooted_post_log_inr_inr := by
  reach_arm reach_45
  have p : ∃ log i, CopyLog f.logs c.post.currentTerm log ∧ i ≤ log.length ∧ c.post.log = log.take i :=
    ⟨c.pre.log, c.pre.log.length, copyProof st⟩
  refine ⟨r45 key, c.post_now, c.post_now, c.post_now, Or.inr p, p, c.pre.log,
    ⟨_, copyProof st⟩, c.pre.log.length, ?_⟩
  fill_copy

private theorem sortedCopy (st : Stable f t c) (key : Fresh f t) :
    sig c .sorted_post_log_inr_inr := by
  reach_arm reach_6
  have p : ∃ log i, CopyLog f.logs c.post.currentTerm log ∧ i ≤ log.length ∧ c.post.log = log.take i :=
    ⟨c.pre.log, c.pre.log.length, copyProof st⟩
  refine ⟨r6 key, c.post_now, c.post_now, c.post_now, Or.inr p, p, c.pre.log,
    ⟨_, copyProof st⟩, c.pre.log.length, ?_⟩
  fill_copy

private theorem appendKind (st : Stable f t c) :
    Advance c.actor {c.pre with log := c.pre.log ++ [], sentIndex := c.pre.sentIndex} c.post := by
  left
  cases eq : c.pre
  simpa only [eq, List.append_nil] using st.post

private theorem kindSame (st : Stable f t c) (key : Fresh f t) : sig c .post_log_kind_same := by
  reach_arm reach_57
  exact ⟨r57 key, congrArg NodeState.log st.post, congrArg NodeState.commitIndex st.post, rfl⟩

private theorem kindAppend (st : Stable f t c) (key : Fresh f t) : sig c .post_log_kind_append := by
  reach_arm reach_57
  exact ⟨r57 key, [], c.pre.sentIndex, stRole st, by simp, appendKind st, rfl⟩

private theorem advancePositive (st : Stable f t c) (key : Fresh f t) : sig c .facts_advance_inl := by
  reach_arm reach_680
  refine ⟨c.actor, c.post, Or.inl ⟨r57 key, [], c.pre.sentIndex, stRole st,
    by simp, appendKind st, rfl, rfl, ?_, rfl⟩, Or.inl rfl⟩
  exact (appendKind st).resolve_right (fun h => by
    have a := h.2.2.2.2.2.2.1
    change c.pre.commitIndex < c.post.commitIndex at a
    simp [st.post] at a)

private theorem prefixPositive (st : Stable f t c) (key : Fresh f t) :
    sig c .prefix_small_inl ∧ sig c .prefix_small_inr := by
  have root := c.inv.rooted c.actor c.pre c.pre_now
  have sub : c.post.log <+: c.pre.log := st.post ▸ List.prefix_refl c.pre.log
  refine ⟨Or.inr (Or.inl ⟨c.post.log, c.pre.log, r1009 st key, List.nil_prefix, root, sub⟩),
    Or.inr (Or.inl ⟨c.post.log, c.pre.log, r1009 st key, ?_⟩)⟩
  have live := c.inv.leader_logs c.actor c.pre c.pre_now (stRole st)
  cases h : c.pre.log with
  | nil => exact (live h).elim
  | cons hd tl => exact ⟨hd, tl, List.prefix_refl _, h ▸ root, h ▸ sub⟩

private theorem summaryPositive (st : Stable f t c) (key : Fresh f t) :
    sig c .summary_event_internal ∧ sig c .summary_input_nominateSuccessor := by
  have portal : reach_1300 f t c c.event := ⟨t, c.tr, r427 key, rfl⟩
  constructor
  · reach_arm reach_1300
    exact ⟨c.event, portal, .nominateSuccessor, st.event⟩
  · reach_arm reach_1300
    exact ⟨c.event, portal, st.event⟩

private theorem quietPositive (st : Stable f t c) (key : Fresh f t) : sig c .quiet_summary_either_inl := by
  have ran := c.tr.ran
  change (Node.step (Capabilities.record c.actor) c.actor c.pre c.event).run {} =
    some (c.post, c.tr.outputs) at ran
  rw [st.event] at ran
  obtain ⟨sent, eq, _, role, nominated⟩ := nominate_sends c.actor c.pre {} _ _ ran
  have packets : ∀ e ∈ c.sent, e.source = c.actor ∧ e.payload = .proposeRequestVoteRequest c.pre.currentTerm := by
    rw [← List.nil_append sent, ← eq] at nominated
    exact nominated
  have engaged : Engaged c.pre := by simp [Engaged, role]
  have path : reach_2347 f t c c.actor c.pre c.pre c.event c.sent := by
    reach_arm reach_2289
    exact ⟨c.pre, r2289 st key, ⟨role, packets⟩, role, packets, ⟨role, packets⟩, role, packets,
      rfl, rfl, st.event⟩
  reach_arm reach_2347
  refine ⟨c.actor, c.pre, c.pre, c.event, c.sent, path, Or.inl engaged, engaged,
    rfl, rfl, rfl, rfl, rfl, rfl, rfl, fun _ => Or.inl engaged, ?_⟩
  simpa only [st.post] using (Summary.sends c.sum)

private theorem successorSome (st : Stable f t c) (key : Fresh f t)
    (someTarget : ∃ n, findSuccessor c.pre c.actor = some n) : sig c .nominate_sends_successor_some := by
  reach_arm reach_2444
  exact ⟨c.actor, c.pre, Or.inl (r2289 st key), stRole st, stRole st, stRole st, someTarget⟩

private theorem successorNone (st : Stable f t c) (key : Fresh f t)
    (noTarget : ¬ ∃ n, findSuccessor c.pre c.actor = some n) : sig c .nominate_sends_successor_none := by
  reach_arm reach_2444
  exact ⟨c.actor, c.pre, Or.inl (r2289 st key), stRole st, stRole st, stRole st, fun n eq => noTarget ⟨n, eq⟩⟩

private theorem r1233 (key : Fresh f t) {n x} (now : Now (f.advance t) n x) :
    reach_1233 f t c c.actor n c.post x :=
  ⟨t, c.tr, .inl ⟨.inl ⟨r6 key, now, rfl⟩, now, rfl, HEq.rfl⟩, now, rfl, rfl⟩

private theorem replacePositive (key : Fresh f t) : sig c .mem_replaceNode_here_pos := by
  have mem : (c.actor, c.post) ∈ Concrete.replaceNode f.current.nodes c.actor c.post :=
    c.tr.nodesEq ▸ c.post_now
  reach_arm reach_1233
  exact ⟨c.actor, c.actor, c.post, c.post, r1233 key c.post_now, (c.actor, c.pre),
    ⟨c.pre_now, by simp⟩, c.pre, ⟨c.pre_now, by simp⟩, c.pre_now, by simp, mem⟩

private theorem replaceOther (st : Stable f t c) (key : Fresh f t) {n x}
    (ne : n ≠ c.actor) (now : Now f n x) : sig c .mem_replaceNode_here_neg := by
  have next : Now (f.advance t) n x := stNow st ▸ now
  have mem : (n, x) ∈ Concrete.replaceNode f.current.nodes c.actor c.post := c.tr.nodesEq ▸ next
  have eq : (if (n == c.actor) = true then (c.actor, c.post) else (n, x)) = (n, x) := by
    simp [ne]
  reach_arm reach_1233
  exact ⟨c.actor, n, c.post, x, r1233 key next, (n, x), ⟨now, eq⟩, n, x, ⟨now, eq⟩, now, eq, ne, mem⟩

omit [Config.InitialConfiguration] in
private theorem proposal_answer (s : Step) (st : @Stable ⟨s.cfg⟩ s.frame s.after s.context) :
    label s (.step .new_message_h_proposeRequestVoteRequest) =
      ReducedQuestions.answer s.before s.after .message := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  apply Bool.eq_iff_iff.mpr
  rw [label_true]
  change PinnedClasses.sig c _ ↔ _
  have msg := (ReducedQuestions.answer_iff s .message).trans (ReducedQuestions.messages_iff c)
  have proposal := ReducedQuestions.sent_iff c .proposeRequestVoteRequest
  change PinnedClasses.sig c .new_message_h_proposeRequestVoteRequest ↔ _ at proposal
  rw [msg, proposal, ReducedQuestions.freshSend_iff, ReducedQuestions.freshSend_iff]
  refine ⟨fun ⟨e, sent, fresh, _⟩ => ⟨e, sent, fresh, rfl⟩, ?_⟩
  rintro ⟨e, sent, fresh, _⟩
  have hp := st.proposal e sent
  refine ⟨e, sent, fresh, ?_⟩
  cases eq : e.payload <;> simp [eq, NominationRows.proposal] at hp <;> rfl

omit [Config.InitialConfiguration] in
private theorem no_queue_without_successor (s : Step) (st : @Stable ⟨s.cfg⟩ s.frame s.after s.context)
    (no : sends s.before s.act = false) :
    ReducedQuestions.answer s.before s.after .message = false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  apply Bool.eq_false_iff.mpr
  have msg := (ReducedQuestions.answer_iff s .message).trans (ReducedQuestions.messages_iff s.context)
  change ¬ (ReducedQuestions.answer s.before s.after .message = true)
  rw [msg, ReducedQuestions.freshSend_iff]
  rintro ⟨e, sent, _, _⟩
  have target := (NominationArms.actual st.event sent).2.2.2
  have yes := (sends_iff s st).mpr target
  simp [no] at yes

-- Each successor disjunct pins the arguments to the very same recorded
-- nomination. Reuse those certificates to rule out `.some` with no target.
private theorem noTargetConflict {self state}
    (args : NominationArms.Arguments c self state)
    (no : ¬ ∃ n, findSuccessor c.pre c.actor = some n)
    (yes : ∃ n, findSuccessor state self = some n) : False := by
  obtain ⟨rfl, rfl⟩ := args
  exact no yes

meta section
open Lean Meta Elab Command

private partial def noTargetProof (p h nom no : Expr) : MetaM Expr := do
  if p.isAppOfArity ``Or 2 then
    return ← NominationArms.splitOr p h fun p h => noTargetProof p h nom no
  NominationArms.openExist p h fun p h =>
    NominationArms.openExist p h fun p h => do
      let a := p.getArg! 0
      let n := a.getAppFn.constName!
      let ha ← mkAppM ``And.left #[h]
      let args := mkAppN (mkConst (NominationArms.certName n)) (a.getAppArgs ++ #[nom, ha])
      if (← inferType args).isConstOf ``False then return args
      let mut rest := h
      for _ in [:4] do rest ← mkAppM ``And.right #[rest]
      mkAppM ``noTargetConflict #[args, no, rest]

run_cmd liftTermElabM do
  let n := ``step_nominate_sends_successor_some
  let ci ← getConstInfo n
  lambdaTelescope ci.value! fun xs p => do
    let c := xs[3]!
    let pred := mkAppN (mkConst n) xs
    withLocalDeclD `nom (← mkAppM ``NominationArms.IsNomination #[c]) fun nom => do
      withLocalDeclD `no (mkNot (← mkAppM ``NominationArms.HasSuccessor #[c])) fun no =>
        withLocalDeclD `h pred fun h => do
          let pf ← noTargetProof p h nom no
          let vars := xs ++ #[nom, no, h]
          addDecl (.thmDecl {
            name := `ConsensusCoverage.DelayedNomination.no_successor_some, levelParams := [],
            type := ← mkForallFVars vars (mkConst ``False), value := ← mkLambdaFVars vars pf })

end

end ConsensusCoverage.DelayedNomination
