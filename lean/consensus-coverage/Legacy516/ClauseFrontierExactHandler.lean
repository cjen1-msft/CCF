module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseFrontierExactFactors
import all ConsensusCoverage.ClauseFrontierExactFactors
import all ConsensusCoverage.EventSupport
import all ConsensusCoverage.AssistAcceptedA
import all ConsensusCoverage.AssistConflictA
import all ConsensusCoverage.AssistReplyA
import all ConsensusCoverage.DeepHandlerCases
import all ConsensusCoverage.FollowerFoldCasesB
import all ConsensusCoverage.HandReadersAHandler
import all ConsensusCoverage.HandReadersAObserve
import all ConsensusCoverage.HandReadersElectionBBounds
import all ConsensusCoverage.HandReadersOtherAdvance
import all ConsensusCoverage.HandReadersOtherConditionBuild
import all ConsensusCoverage.HandReadersOtherFoldDirect
import all ConsensusCoverage.HandReadersOtherFoldNil
import all ConsensusCoverage.HandReadersOtherFrontier
import all ConsensusCoverage.HandReadersOtherPromotion
import all ConsensusCoverage.HandReadersOtherSites
import all ConsensusCoverage.LeaderEffect
import all ConsensusCoverage.NominationRows
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.ClauseFrontierExact.Handler

open ActionProfile EventSupport
open Consensus Model Model.Node Proofs Safety
open HandReadersOther HandReadersA

set_option maxHeartbeats 0
set_option maxRecDepth 8192

abbrev bit (s : Step) (q : Classes.StepBranch) := label s (.step q) = true
abbrev changed (s : Step) := bit s .inv_step_frontier_now_inl

private theorem tag_eq (s : Step) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    actionTag s.act = eventTag s.context.event := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  exact (congrArg actionTag ((s.context_eq s.context).mpr rfl)).symm.trans (actionTag_eq s.context)

private theorem changed_at (s : Step) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    changed s ↔ ¬Now s.frame s.context.actor s.context.post := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  simp only [changed, bit, label_true, holds, SolvedWitnesses.sig_iff]
  exact changed_iff _

private theorem observe_at (s : Step) (k : Observe.Branch) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    bit s (Observe.column true k) ↔ changed s ∧
      Observe.test k s.context.actor s.context.pre s.context.event := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have first : bit s (Observe.column true k) ↔ SolvedWitnesses.sig s.context (Observe.column true k) := by
    simp only [bit, label_true, holds, SolvedWitnesses.sig_iff]
  exact first.trans ((Observe.sig_iff_test _ true k).trans (and_congr (changed_at s).symm Iff.rfl))

private theorem condition_at (s : Step) (k : Bool) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    bit s (Condition.column k) ↔ changed s ∧
      Condition.test k s.context.actor s.context.pre s.context.event := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  change label s (.step (Condition.column k)) = true ↔ _
  rw [(Condition.exactReader k).eq_label s]
  change Promotion.gated (Condition.test k) s.cfg s.before s.act s.after s.past = true ↔ _
  exact (Promotion.gated_iff s (Condition.test k)).trans (and_congr (changed_at s).symm Iff.rfl)

private theorem fold_nil_at (s : Step) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    bit s .foldl_select_max_values_nil ↔
      (changed s ∧ Fold.erased s.context.actor s.context.pre s.context.event) ∨
      (s.context.pre.commitIndex < s.context.post.commitIndex ∧ Advance.Source s.context) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  change label s (.step .foldl_select_max_values_nil) = true ↔ _
  rw [Fold.nilExact.eq_label s]
  have growth : Advance.reader .growth s.cfg s.before s.act s.after s.past = true ↔
      s.context.pre.commitIndex < s.context.post.commitIndex ∧ Advance.Source s.context := by
    unfold Advance.reader
    simp only [Bool.and_eq_true, HandReadersA.actorRead_at s, Advance.source_iff s,
      Advance.test, decide_eq_true_eq]
  change (Promotion.gated Fold.erased s.cfg s.before s.act s.after s.past ||
    Advance.reader .growth s.cfg s.before s.act s.after s.past) = true ↔ _
  simp only [Bool.or_eq_true, Promotion.gated_iff s, ← changed_at s, growth]

theorem fold_nil_shape (s : Step) (h : bit s .foldl_select_max_values_nil) : changed s := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have spec : bit s .foldl_select_max_values_nil ↔ SolvedWitnesses.step_foldl_select_max_values_nil _ _ c := by
    simp only [bit,label_true,holds,SolvedWitnesses.sig_iff,c] <;> rfl
  rcases Fold.unpack c (spec.mp h) with ⟨fresh,_⟩ | ⟨grow,_⟩
  · exact (changed_at s).mpr fresh
  · exact (changed_at s).mpr (fun old => Nat.lt_irrefl _ ((c.now_pre old) ▸ grow))

theorem observe_requires_call (s : Step) :
    (bit s .observeTerm_log_primary_pos → bit s .observeTerm_log_message_proposeRequestVoteRequest) ∧
    (bit s .observeTerm_log_newer_pos →
      bit s .observeTerm_log_message_proposeRequestVoteRequest ∧
      compares (actionTag s.act) (label s (.step .observeTerm_log_primary_pos)) = true) ∧
    (bit s .observeTerm_log_message_proposeRequestVoteRequest → changed s) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  change (bit s (Observe.column true .primary) → bit s (Observe.column true .call)) ∧
    (bit s (Observe.column true .higher) → bit s (Observe.column true .call) ∧ _) ∧ _
  have pri := observe_at s .primary
  have high := observe_at s .higher
  have call := observe_at s .call
  refine ⟨?_,?_,fun h => (call.mp h).1⟩
  · rw [pri,call]
    cases ev : c.event with
    | internal i => simp [Observe.test]
    | receive n m => simp [Observe.test]; grind
  · rw [high,call,tag_eq s]
    by_cases hp : bit s (Observe.column true .primary)
    · have ph := (pri.mp hp).2
      rw [show label s (.step .observeTerm_log_primary_pos) = true from hp]
      cases ev : c.event with
      | internal i => simp [Observe.test]
      | receive n m => cases m <;> simp [Observe.test,eventTag,messageTag,compares] <;> grind
    · have no : label s (.step .observeTerm_log_primary_pos) = false := Bool.eq_false_iff.mpr hp
      rw [no]
      rw [pri] at hp
      cases ev : c.event with
      | internal i => simp [Observe.test]
      | receive n m => cases m <;> simp [Observe.test,eventTag,messageTag,compares] at * <;> grind

theorem condition_shape (s : Step) :
    (bit s .ite__condition_pos → changed s) ∧ (bit s .ite__condition_neg → changed s) ∧
    (∀ n m, letI : Config.InitialConfiguration := ⟨s.cfg⟩
      s.context.event = .receive n m →
        (bit s .ite__condition_neg ↔ bit s .observeTerm_log_message_proposeRequestVoteRequest) ∧
        (changed s → bit s .ite__condition_neg ∨ bit s .ite__condition_pos)) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have pos := condition_at s true
  have neg := condition_at s false
  have call := observe_at s .call
  refine ⟨fun h => (pos.mp h).1, fun h => (neg.mp h).1,?_⟩
  intro n m ev
  change (bit s (Condition.column false) ↔ bit s (Observe.column true .call)) ∧
    (changed s → bit s (Condition.column false) ∨ bit s (Condition.column true))
  rw [neg,call,pos]
  rw [ev]
  cases m <;> simp [Condition.test,Condition.blocked,Observe.test,Observe.eligible] <;> grind

theorem append_shape (s : Step) (tag : actionTag s.act = .append) :
    changed s ∧ bit s .ite__condition_pos ∧ bit s .ite__condition_neg ∧
      bit s .foldl_select_max_values_cons := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have ev : ∃ entries, c.event = .internal (.append entries) := by
    rw [tag_eq s] at tag
    change eventTag c.event = .append at tag
    cases eq : c.event with
    | internal i => cases i <;> simp_all [eventTag,inputTag]
    | receive n m => cases m <;> simp_all [eventTag,messageTag]
  obtain ⟨entries,ev⟩ := ev
  have fresh : changed s := (changed_at s).mpr <| by
    have ran : (Model.Node.step (CCF.Capabilities.record c.actor) c.actor c.pre
        (.internal (.append entries))).run {} = some (c.post,c.tr.outputs) := ev ▸ c.tr.ran
    obtain ⟨_,_,grow⟩ := LeaderEffect.appendBatch_grows c.actor c.pre entries _ _ _ ran
    exact fun h => Nat.lt_irrefl _ ((c.now_pre h) ▸ grow)
  refine ⟨fresh,(condition_at s true).mpr ⟨fresh,?_⟩,(condition_at s false).mpr ⟨fresh,?_⟩,?_⟩
  · rw [ev]; rfl
  · rw [ev]; rfl
  · change bit s (Fold.column .cons)
    change label s (.step (Fold.column .cons)) = true
    rw [(Fold.exactReader .cons).eq_label s]
    change (Promotion.gated Fold.direct .. || _) = true
    rw [Bool.or_eq_true, Promotion.gated_iff, ← changed_at]
    exact .inl ⟨fresh,by rw [ev]; rfl⟩

theorem nomination_stutters (s : Step) (tag : actionTag s.act = .nominateSuccessor) :
    ¬changed s := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have same := (NominationRows.run_nomination s tag).2.1
  exact fun h => (changed_at s).mp h (same ▸ s.context.pre_now)

theorem timeout_kinds (s : Step) (tag : actionTag s.act = .timeout) :
    (changed s ↔ bit s .act_kind_election ∨ bit s .act_kind_checkQuorum) ∧
    (bit s .act_kind_election → ¬bit s .act_kind_checkQuorum) ∧
    (bit s .ite__condition_pos ∨ bit s .ite__condition_neg → bit s .act_kind_election) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have ev : ∃ k, c.event = .internal (.timeout k) := by
    rw [tag_eq s] at tag
    change eventTag c.event = .timeout at tag
    cases eq : c.event with
    | internal i => cases i <;> simp_all [eventTag,inputTag]
    | receive n m => cases m <;> simp_all [eventTag,messageTag]
  obtain ⟨k,ev⟩ := ev
  have ⟨_,_,_,_,elect,check⟩ := local_dispatch c
  have spec (q : Classes.StepBranch) : bit s q ↔ SolvedWitnesses.sig c q := by
    simp only [bit, label_true, holds, SolvedWitnesses.sig_iff, c]
  rw [spec .act_kind_election, spec .act_kind_checkQuorum, elect, check, ← changed_at]
  change (_ ↔ _) ∧ (_ → _) ∧ (bit s (Condition.column true) ∨ bit s (Condition.column false) → _)
  rw [condition_at, condition_at, ev]
  cases k <;> simp [Condition.test] <;> grind

abbrev isReceive : Tag → Bool
  | .append | .sendEntries | .timeout | .nominateSuccessor | .initAsBackup => false
  | _ => true

abbrev reply : Tag → Bool
  | .appendEntriesResponse | .requestVoteResponse | .requestPreVoteResponse => true
  | _ => false

theorem receive_shape (s : Step) (tag : isReceive (actionTag s.act) = true) :
    (bit s .ite__condition_neg ↔ bit s .observeTerm_log_message_proposeRequestVoteRequest) ∧
    (changed s → bit s .ite__condition_neg ∨ bit s .ite__condition_pos) ∧
    (reply (actionTag s.act) = false → changed s → bit s .observeTerm_log_message_proposeRequestVoteRequest) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  obtain ⟨n,m,ev⟩ : ∃ n m, c.event = .receive n m := by
    rw [tag_eq s] at tag
    change isReceive (eventTag c.event) = true at tag
    cases eq : c.event with
    | internal i => cases i <;> simp_all [isReceive,eventTag,inputTag]
    | receive n m => exact ⟨n,m,rfl⟩
  have ⟨a,b⟩ := (condition_shape s).2.2 n m ev
  refine ⟨a,b,?_⟩
  intro req fresh
  rw [tag_eq s] at req
  change reply (eventTag c.event) = false at req
  rw [ev] at req
  apply (observe_at s .call).mpr
  refine ⟨fresh,?_⟩
  rw [ev]
  cases m <;> simp_all [eventTag,messageTag,reply,Observe.test,Observe.eligible]

theorem backup_changes (s : Step) (tag : actionTag s.act = .initAsBackup) : changed s := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  obtain ⟨xs,ev⟩ : ∃ xs, c.event = .internal (.initAsBackup xs) := by
    rw [tag_eq s] at tag
    change eventTag c.event = .initAsBackup at tag
    cases eq : c.event with
    | internal i => cases i <;> simp_all [eventTag,inputTag]
    | receive n m => cases m <;> simp_all [eventTag,messageTag]
  have ran : (Model.Node.step (CCF.Capabilities.record c.actor) c.actor c.pre c.event).run {} =
      some (c.post,c.tr.outputs) := c.tr.ran
  rw [ev] at ran
  by_cases valid : c.pre.isFresh ∧ (xs = [] ∨ isSignatureAt xs xs.length = true)
  · have postRole : .follower = c.post.role := by
      have eq := congrArg (Option.map (fun p => p.1.role)) ran
      simp [Model.Node.step,Model.Node.act,initAsBackup,becomeAwareOfNewTerm,guard,valid] at eq
      first | exact eq | exact eq.2
    exact (changed_at s).mpr fun old => by
      have same := congrArg NodeState.role (c.now_pre old)
      rw [same,valid.1.1] at postRole
      contradiction
  · simp [Model.Node.step,Model.Node.act,initAsBackup,guard,valid] at ran

private theorem follower_logic (fresh down reject rollback zero : Prop) (overlap : Bool) :
    let d := fresh ∧ (down ∨ reject ∧ zero)
    let k := fresh ∧ (¬down ∨ reject ∧ ¬zero)
    let a := fresh ∧ (¬reject ∧ ¬rollback)
    let c := a ∧ overlap = false
    let x := a ∧ overlap = true
    let bad := fresh ∧ (reject ∨ rollback)
    (fresh ↔ d ∨ k) ∧ (fresh ↔ (c ∨ x) ∨ bad) ∧ (c → ¬x) ∧
      (c ∨ x → ¬bad) ∧ (c ∨ x → d → ¬k) ∧ (a → c ∨ x) := by
  cases overlap <;> grind

set_option maxHeartbeats 400000 in
theorem follower_shape (s : Step) (tag : actionTag s.act = .appendEntriesRequest) :
    let down := bit s .handleAppendEntriesRequest_stepDown_pos
    let stay := bit s .handleAppendEntriesRequest_stepDown_neg
    let clear := bit s .handleAppendEntriesRequest_conflict_none
    let conflict := bit s .handleAppendEntriesRequest_conflict_some
    let accept := clear ∨ conflict
    let reject := bit s .ite__condition_pos
    (changed s ↔ down ∨ stay) ∧ (changed s ↔ accept ∨ reject) ∧
      (clear → ¬conflict) ∧ (accept → ¬reject) ∧ (accept → down → ¬stay) ∧
      ((bit s .advance_le_total_inl ∨ bit s .advance_le_total_inr) → accept) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  obtain ⟨n,q,ev⟩ : ∃ n q, c.event = .receive n (.appendEntriesRequest q) := by
    rw [tag_eq s] at tag
    change eventTag c.event = .appendEntriesRequest at tag
    cases eq : c.event with
    | internal i => cases i <;> simp_all [eventTag,inputTag]
    | receive n m => cases m <;> simp_all [eventTag,messageTag]
  have spec (q : Classes.StepBranch) : bit s q ↔ SolvedWitnesses.sig c q := by
    simp only [bit, label_true, holds, SolvedWitnesses.sig_iff, c]
  let z := observeTerm c.pre (.appendEntriesRequest q)
  have atReq (k : HandReadersA.Handler.Branch) :
      bit s (HandReadersA.Handler.column k) ↔ changed s ∧ HandReadersA.Handler.test k z q := by
    exact (spec _).trans ((HandReadersA.Handler.at_request c ev k).trans
      (and_congr (changed_at s).symm Iff.rfl))
  have adv (k : Bool) :
      bit s (AssistAcceptedA.column (Frontier.kind k)) ↔ changed s ∧
        Frontier.test k c.actor c.pre (.receive n (.appendEntriesRequest q)) := by
    exact (spec _).trans ((Frontier.iff_test c k).trans (by rw [ev,changed_at]))
  let w := DeepHandlerCases.current z q
  let afterDown := q.term = z.currentTerm ∧ (z.role = .candidate ∨ z.role = .preVoteCandidate)
  let rejects := q.term < w.currentTerm ∨ ¬appendEntryMatchesLog w q
  let noPrefix := q.term < w.currentTerm ∨ termAt w.log q.prevLogIndex = 0
  let overlaps := (DeepHandlerCases.conflict z q).isSome
  let rollsBack := q.prevLogIndex < w.commitIndex ∨ overlaps ∧ !w.isNewFollower
  have dr := atReq .down
  have sr := atReq .stay
  have cr := atReq .clear
  have xr := atReq .conflict
  have br := condition_at s true
  change bit s (Condition.column true) ↔ _ at br
  have rej : bit s (Condition.column true) ↔ changed s ∧ (rejects ∨ rollsBack) := by
    rw [br,ev]
    simp only [Condition.test,Condition.blocked,Bool.false_eq_true,false_and,decide_false,
      Bool.false_or,Condition.inner,ite_true,decide_eq_true_eq]
    try rfl
  have ad (k : Bool) (h : bit s (AssistAcceptedA.column (Frontier.kind k))) :
      changed s ∧ (¬rejects ∧ ¬rollsBack) := by
    obtain ⟨fresh,h⟩ := (adv k).mp h
    have pass : Frontier.accept c.pre q := by
      simp only [Frontier.test,Bool.and_eq_true,decide_eq_true_eq] at h
      exact h.1
    exact ⟨fresh,pass⟩
  have d : bit s .handleAppendEntriesRequest_stepDown_pos ↔
      changed s ∧ (afterDown ∨ rejects ∧ noPrefix) := dr.trans (by
    simp only [HandReadersA.Handler.test,decide_eq_true_eq] <;> rfl)
  have k : bit s .handleAppendEntriesRequest_stepDown_neg ↔
      changed s ∧ (¬afterDown ∨ rejects ∧ ¬noPrefix) := sr.trans (by
    simp only [HandReadersA.Handler.test,decide_eq_true_eq] <;> rfl)
  have a : bit s .handleAppendEntriesRequest_conflict_none ↔
      (changed s ∧ (¬rejects ∧ ¬rollsBack)) ∧ overlaps = false := cr.trans (by
    simp only [HandReadersA.Handler.test,Bool.and_eq_true,decide_eq_true_eq,beq_iff_eq,and_assoc] <;> rfl)
  have b : bit s .handleAppendEntriesRequest_conflict_some ↔
      (changed s ∧ (¬rejects ∧ ¬rollsBack)) ∧ overlaps = true := xr.trans (by
    simp only [HandReadersA.Handler.test,Bool.and_eq_true,decide_eq_true_eq,beq_iff_eq,and_assoc] <;> rfl)
  have ⟨dk,ab,cx,ar,ds,both⟩ := follower_logic (changed s) afterDown rejects rollsBack noPrefix overlaps
  rw [d,k,a,b]
  change _ ∧ (_ ↔ _ ∨ bit s (Condition.column true)) ∧ _ ∧
    (_ → ¬bit s (Condition.column true)) ∧ _ ∧ _
  rw [rej]
  exact ⟨dk,ab,cx,ar,ds,fun h => both (h.elim (ad true) (ad false))⟩

end ConsensusCoverage.ClauseFrontierExact.Handler
