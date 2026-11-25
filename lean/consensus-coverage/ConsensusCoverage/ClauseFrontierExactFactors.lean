module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseFrontierExact
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.BackingStutter
import all ConsensusCoverage.ClauseExactTables
import all ConsensusCoverage.EventSupport
import all ConsensusCoverage.HandReadersAAppend
import all ConsensusCoverage.HandReadersAObserve
import all ConsensusCoverage.HandReadersElectionBBoundRows
import all ConsensusCoverage.HandReadersOtherConditionBuild
import all ConsensusCoverage.HandReadersOtherFoldDirect
import all ConsensusCoverage.HandReadersOtherFold
import all ConsensusCoverage.HandReadersOtherFoldNil
import all ConsensusCoverage.HandReadersOtherPromotion
import all ConsensusCoverage.InertProfile
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.ClauseFrontierExact

open Consensus Model Model.Node Proofs Safety ActionProfile SolvedWitnesses
open HandReadersA.Observe HandReadersOther

set_option maxHeartbeats 0
set_option maxRecDepth 8192

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

theorem changed_iff : sig c .inv_step_frontier_now_inl ↔ ¬Now f c.actor c.post := by
  change (_ ∧ _ ∧ _ ∧ _) ↔ _
  simp only [c.post_now, true_and]

private abbrev InvCall (self : NodeID) (st : NodeState) (e : Event)
    (post : NodeState) (out : CCF.Outputs NodeID Message Notification) :=
  (reach% step_commitFrontier_invariant_event_internal[0]) f t c self st e post out

private theorem call_iff {self st e post out} :
    InvCall c self st e post out ↔
      ¬ Now f c.actor c.post ∧ self = c.actor ∧ st = c.pre ∧ e = c.event ∧
      post = c.post ∧ out = c.tr.outputs := by
  unfold InvCall
  reach_unfold step_commitFrontier_invariant_event_internal[0]
  constructor
  · rintro ⟨_,_,_,fresh,hs,hp,he,hq,ho⟩
    exact ⟨fresh,hs,hp,he,hq,ho⟩
  · rintro ⟨fresh,rfl,rfl,rfl,rfl,rfl⟩
    exact ⟨c.post_now,c.post_now,c.post_now,fresh,rfl,rfl,rfl,rfl,rfl⟩

theorem internal_iff :
    sig c .commitFrontier_invariant_event_internal ↔
      ¬ Now f c.actor c.post ∧ ∃ i, c.event = .internal i := by
  change (∃ self st e post out, InvCall c self st e post out ∧ _) ↔ _
  constructor
  · rintro ⟨_,_,_,_,_,call,i,ev,_⟩
    obtain ⟨fresh,_,_,eq,_,_⟩ := (call_iff c).mp call
    exact ⟨fresh,i,eq.symm.trans ev⟩
  · rintro ⟨fresh,i,ev⟩
    exact ⟨_,_,_,_,_,(call_iff c).mpr ⟨fresh,rfl,rfl,rfl,rfl,rfl⟩,
      i,ev,ev ▸ c.tr.ran,c.inv.frontier _ _ c.pre_now,c.tr.ran⟩

theorem received_iff :
    sig c .commitFrontier_invariant_event_receive ↔
      ¬ Now f c.actor c.post ∧ ∃ n m, c.event = .receive n m := by
  change (∃ self st e post out, InvCall c self st e post out ∧ _) ↔ _
  constructor
  · rintro ⟨_,_,_,_,_,call,n,m,ev,_⟩
    obtain ⟨fresh,_,_,eq,_,_⟩ := (call_iff c).mp call
    exact ⟨fresh,n,m,eq.symm.trans ev⟩
  · rintro ⟨fresh,n,m,ev⟩
    exact ⟨_,_,_,_,_,(call_iff c).mpr ⟨fresh,rfl,rfl,rfl,rfl,rfl⟩,
      n,m,ev,ev ▸ c.tr.ran,c.inv.frontier _ _ c.pre_now,c.tr.ran⟩

theorem input_pick (P : Input → Prop) :
    (∃ i, (reach% step_act_input_append[0]) f t c i ∧ P i) ↔
      ¬Now f c.actor c.post ∧ ∃ i, c.event = .internal i ∧ P i := by
  reach_unfold step_act_input_append[0]
  constructor
  · rintro ⟨i,⟨self,st,e,post,out,site,ev,_⟩,h⟩
    obtain ⟨fresh,_,_,eq,_,_⟩ := (call_iff c).mp site
    exact ⟨fresh,i,eq.symm.trans ev,h⟩
  · rintro ⟨fresh,i,ev,h⟩
    exact ⟨i,⟨_,_,_,_,_,(call_iff c).mpr ⟨fresh,rfl,rfl,rfl,rfl,rfl⟩,
      ev,ev ▸ c.tr.ran,c.inv.frontier _ _ c.pre_now,c.tr.ran⟩,h⟩

theorem receive_pick (P : NodeID → NodeState → NodeID → Message → Prop) :
    (∃ a st n m, Receive c a st n m ∧ P a st n m) ↔
      ¬Now f c.actor c.post ∧ ∃ n m, c.event = .receive n m ∧ P c.actor c.pre n m := by
  simp only [receive_iff]
  grind

theorem local_dispatch :
    (sig c .act_input_append ↔ ¬Now f c.actor c.post ∧ ∃ es, c.event = .internal (.append es)) ∧
    (sig c .act_input_sendEntries ↔ ¬Now f c.actor c.post ∧ ∃ n i, c.event = .internal (.sendEntries n i)) ∧
    (sig c .act_input_timeout ↔ ¬Now f c.actor c.post ∧ ∃ k, c.event = .internal (.timeout k)) ∧
    (sig c .act_input_initAsBackup ↔ ¬Now f c.actor c.post ∧ ∃ es, c.event = .internal (.initAsBackup es)) ∧
    (sig c .act_kind_election ↔ ¬Now f c.actor c.post ∧ c.event = .internal (.timeout .election)) ∧
    (sig c .act_kind_checkQuorum ↔ ¬Now f c.actor c.post ∧ c.event = .internal (.timeout .checkQuorum)) := by
  refine ⟨?_,?_,?_,?_,?_,?_⟩
  all_goals
    change (∃ i, (reach% step_act_input_append[0]) f t c i ∧ _) ↔ _
    rw [input_pick]
    grind

theorem remote_dispatch :
    (sig c .receive_message_appendEntriesRequest ↔ Calls c ∧ ∃ n q, c.event = .receive n (.appendEntriesRequest q)) ∧
    (sig c .receive_message_appendEntriesResponse ↔ Calls c ∧ ∃ n q, c.event = .receive n (.appendEntriesResponse q)) ∧
    (sig c .receive_message_requestVoteRequest ↔ Calls c ∧ ∃ n q, c.event = .receive n (.requestVoteRequest q)) ∧
    (sig c .receive_message_requestVoteResponse ↔ Calls c ∧ ∃ n q, c.event = .receive n (.requestVoteResponse q)) ∧
    (sig c .receive_message_requestPreVoteRequest ↔ Calls c ∧ ∃ n q, c.event = .receive n (.requestPreVoteRequest q)) ∧
    (sig c .receive_message_requestPreVoteResponse ↔ Calls c ∧ ∃ n q, c.event = .receive n (.requestPreVoteResponse q)) ∧
    (sig c .receive_message_proposeRequestVoteRequest ↔ Calls c ∧ ∃ n k, c.event = .receive n (.proposeRequestVoteRequest k)) := by
  refine ⟨?_,?_,?_,?_,?_,?_,?_⟩
  all_goals
    change (∃ a st n m, Receive c a st n m ∧ _) ↔ _
    rw [receive_pick,calls_iff]
    have fr := c.inv.frontier _ _ c.pre_now
    have seen (m : Message) : Direct.CommitFrontier (observeTerm c.pre m) :=
      fr.of_log (Concrete.observeTerm_log ..) (Concrete.observeTerm_commitIndex ..)
    cases ev : c.event with
    | internal i => simp [test]
    | receive n msg => cases msg <;> simp [test,eligible,fr,seen] <;> grind

end

/-- The seven nonempty probes range over the same existential pool in the
maximum proof. The empty-list probe also has routes to calls before growth. -/
theorem fold_eq (s : Step) (k : Fold.Kind) :
    label s (.step (Fold.column k)) = label s (.step .foldl_select_max_values_cons) :=
  (Fold.exactReader k).eq_label s |>.trans ((Fold.exactReader .cons).eq_label s).symm

/-- Both `observeTerm` preservation proofs consult identical branches. -/
theorem observe_eq (s : Step) (k : Branch) :
    label s (.step (column true k)) = label s (.step (column false k)) :=
  (exactReader true k).eq_label s |>.trans ((exactReader false k).eq_label s).symm

theorem ack_observe_eq (s : Step) (log : Bool) :
    label s (.step (if log then .observeTerm_log_message_appendEntriesResponse else
      .observeTerm_commitIndex_message_appendEntriesResponse)) =
      label s (.step (column log .call)) :=
  (ackAlias log).eq_label s |>.trans ((exactReader log .call).eq_label s).symm

def compares (tag : EventSupport.Tag) (primary : Bool) : Bool :=
  tag != .proposeRequestVoteRequest && (tag != .appendEntriesResponse || primary)

def otherMessage (tag : EventSupport.Tag) : Bool :=
  tag != .proposeRequestVoteRequest && tag != .appendEntriesResponse

theorem observe_shape (s : Step) :
    let tag := EventSupport.actionTag s.act
    let call := label s (.step (column true .call))
    let primary := label s (.step (column true .primary))
    let higher := label s (.step (column true .higher))
    label s (.step (column true .backup)) = (call && !primary) ∧
    label s (.step (column true .other)) = (call && otherMessage tag) ∧
    label s (.step (column true .stable)) = (call && compares tag primary && !higher) := by
  have readEq (k : Branch) : label s (.step (column true k)) =
      reader k s.cfg s.before s.act s.after s.past := (exactReader true k).eq_label s
  simp only [readEq, reader]
  cases made : GuardedDomain.ofAction s.cfg s.before s.after s.past s.act with
  | none => simp
  | some v =>
    simp only [Option.any_some]
    cases act : s.act with
    | «local» n i => simp [ReadersAtoms.eventOf, test]
    | deliver e =>
      cases msg : e.payload <;>
        simp only [ReadersAtoms.eventOf, test, msg, EventSupport.actionTag, EventSupport.messageTag,
          compares, otherMessage] <;>
        grind

theorem unchanged_endpoints (s : Step) (h : label s (.step .inv_step_frontier_now_inl) = false) :
    (ClauseExactTables.endpoints s).1 = (ClauseExactTables.endpoints s).2 := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have old : Now s.frame s.context.actor s.context.post := Classical.byContradiction fun fresh =>
    Bool.noConfusion (h.symm.trans ((label_true s _).mpr
      ((sig_iff s.context _).mpr ((changed_iff s.context).mpr fresh))))
  have same := s.context.now_pre old
  have nodes : s.after.nodes = s.before.nodes := by
    change s.context.tr.post = s.context.tr.pre at same
    rw [← s.current_eq, s.context.tr.nodesEq, same]
    exact InertProfile.replace_eq s.context.inv.distinct s.context.tr.found
  have eq := BackingStutter.endpoints s nodes.symm
  rw [pre_answers, post_answers] at eq
  exact Prod.ext (congrFun eq .committed_logs_comparable_left_backed_inl)
    (congrFun eq .committed_logs_comparable_left_backed_inr)

theorem fold_cons_imp_nil (s : Step)
    (h : label s (.step .foldl_select_max_values_cons) = true) :
    label s (.step .foldl_select_max_values_nil) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  change label s (.step (Fold.column .cons)) = true at h
  rw [(Fold.exactReader .cons).eq_label s] at h
  rw [Fold.nilExact.eq_label s]
  change (Promotion.gated Fold.direct .. || _) = true at h
  change (Promotion.gated Fold.erased .. || _) = true
  rw [Bool.or_eq_true, Promotion.gated_iff] at h ⊢
  rcases h with ⟨fresh,h⟩ | h
  · refine .inl ⟨fresh,?_⟩
    simp only [Fold.direct, Bool.or_eq_true, Option.any_eq_true] at h
    rcases h with (app | ⟨_,eq,_⟩) | ⟨_,eq,_⟩
    · cases ev : s.context.event with
      | receive => simp [Fold.appends, ev] at app
      | internal i => cases i <;> simp_all [Fold.appends,Fold.erased,Fold.localNil]
    · simp [Fold.erased,eq]
    · simp [Fold.erased,eq]
  · exact .inr h

theorem append_eq (s : Step) (k : HandReadersA.Append.Branch) :
    label s (.step (HandReadersA.Append.column k)) =
      label s (.step .foldlM__items_cons) :=
  (HandReadersA.Append.exactReader k).eq_label s |>.trans
    ((HandReadersA.Append.exactReader .cons).eq_label s).symm

theorem bound_cons_eq_nonsignature (s : Step) :
    label s (.step .maxCommittableIndexBounded_values_cons) =
      label s (.step .maxCommittableIndexBounded_signature_neg) :=
  HandReadersElectionB.Bounds.nonempty.eq_label s |>.trans
    (HandReadersElectionB.Bounds.nonsignature.eq_label s).symm

theorem append_nil_eq (s : Step) :
    label s (.step .foldlM__items_nil) = label s (.step .foldlM__items_cons) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have spec (q : Classes.StepBranch) := (label_true s (.step q)).trans (sig_iff c q)
  apply Bool.eq_iff_iff.mpr
  rw [spec, spec]
  change step_foldlM__items_nil _ _ c ↔ step_foldlM__items_cons _ _ c
  refine ⟨DeepEffectCases.flushCons c, fun h => ?_⟩
  obtain ⟨es,ev⟩ := (HandReadersA.Append.cons_iff c).mp h
  exact ⟨.append es,HandReadersA.Append.origin c ev,es,rfl⟩

theorem promotion_excludes (s : Step) (pos : Bool)
    (h : label s (.step (Promotion.column pos)) = true) :
    label s (.step (Promotion.column !pos)) = false := by
  rw [(Promotion.exactReader pos).eq_label s] at h
  change Promotion.reader pos .. = true at h
  unfold Promotion.reader at h
  rw [Promotion.gated_iff] at h
  rw [(Promotion.exactReader (!pos)).eq_label s]
  change Promotion.reader (!pos) .. = false
  unfold Promotion.reader
  apply Bool.eq_false_iff.mpr
  intro no
  rw [Promotion.gated_iff] at no
  simp only [Option.any_eq_true, Bool.and_eq_true, beq_iff_eq] at h no
  obtain ⟨_, z, hz, _, sign⟩ := no
  obtain ⟨_, w, hw, _, sign'⟩ := h
  rw [hw] at hz
  cases hz
  rw [sign'] at sign
  cases pos <;> contradiction

end ConsensusCoverage.ClauseFrontierExact
