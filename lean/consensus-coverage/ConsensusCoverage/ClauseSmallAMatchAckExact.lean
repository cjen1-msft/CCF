module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseSmallAMatchAck
import all ConsensusCoverage.AckAdvance
import all ConsensusCoverage.ClauseExactTables
import all ConsensusCoverage.ClauseMatchAck
import all ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.ClauseSmallA
import all ConsensusCoverage.ClauseSmallAMatchAck
import all ConsensusCoverage.ClauseSmallAMatchAckIdle
import all ConsensusCoverage.FullProfile
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.Timely
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.ClauseSmallA.MatchAckExact

open CCF CCF.MultiNodeTransitionSystem
open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open Consensus.Proofs.Ledger
open ActionProfile ClauseExactTables ClauseQuestions
open MatchAckIdle

set_option maxRecDepth 8192
set_option maxHeartbeats 1500000

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)

private theorem ack_idle {src r} (event : c.event = .receive src (.appendEntriesResponse r))
    (accepts : AckAdvance.accepts src r c.pre c.actor) : Idle c.actor c.post := by
  obtain ⟨primary,ok,term,eligible⟩ := accepts
  have ran := c.tr.ran
  change ((Model.Node.step (Capabilities.record c.actor) c.actor c.pre c.event).run {}) = _ at ran
  rw [event] at ran
  simp only [Model.Node.step, receive, eligible, not_true_eq_false, and_false, ↓reduceIte,
    observeTerm, primary, updateTerm, term, Nat.lt_irrefl, handleAppendEntriesResponse,
    bne_self_eq_false, Bool.false_eq_true, ok] at ran
  rw [← primary] at ran
  obtain ⟨_,_,proof⟩ := MatchAckIdle.advance c.actor (AckAdvance.middle c.pre src r) _ _ _ ran
  exact proof

private theorem ineligible {src r} (event : c.event = .receive src (.appendEntriesResponse r))
    (bad : src ∉ eligiblePeers c.pre c.actor) : c.post = c.pre := by
  have ran := c.tr.ran
  change ((Model.Node.step (Capabilities.record c.actor) c.actor c.pre c.event).run {}) = _ at ran
  rw [event] at ran
  simp [Model.Node.step,receive,bad] at ran
  exact ran.1.symm

private abbrev HasPeer (n : NodeID) (st : NodeState) :=
  ∃ v, v ≠ n ∧ 0 < st.matchIndex v

private theorem idle_step {ns} (folded : FullProfile.Folded Config.INITIAL_CONFIGURATION ns f)
    (prior : ∀ n st, Now f n st → st.role = .primary → HasPeer n st → Idle n st)
    (role : c.post.role = .primary) (peer : HasPeer c.actor c.post) : Idle c.actor c.post := by
  intro zero
  rcases Summary.leader c.sum role with ⟨primary,stamp⟩ | won
  · by_cases accepted : ∃ src r, c.event = .receive src (.appendEntriesResponse r) ∧
        r.success = true ∧ r.term = c.pre.currentTerm ∧ src ∈ eligiblePeers c.pre c.actor
    · obtain ⟨src,r,event,ok,term,eligible⟩ := accepted
      exact ack_idle c event ⟨primary,ok,term,eligible⟩ zero
    have matchEq : c.post.matchIndex = c.pre.matchIndex := by
      funext v
      rcases Summary.matchIndex c.sum role primary stamp v with same | ⟨r,ev,ok,term,_⟩
      · exact same
      · have eq := ineligible c ev (fun yes => accepted ⟨v,r,ev,ok,term,yes⟩)
        rw [eq]
    have prePeer : HasPeer c.actor c.pre := by
      obtain ⟨v,other,pos⟩ := peer
      exact ⟨v,other,congrFun matchEq v ▸ pos⟩
    rcases MatchAck.incumbent_kinds c primary role stamp with same | ⟨extra,sent,adv⟩ | ⟨src,r,ev,ok,term,_⟩
    · rw [congr_fields _ same.1 same.2 stamp matchEq, same.2]
      exact prior _ _ c.pre_now primary prePeer (same.2.symm.trans zero)
    · have equal : c.post.commitIndex = c.pre.commitIndex := by
        rcases adv with eq | ⟨_,_,_,_,_,_,lt,_,_⟩
        · have h := congrArg NodeState.commitIndex eq
          exact h
        · change c.pre.commitIndex < c.post.commitIndex at lt
          omega
      have preZero := equal.symm.trans zero
      apply Nat.le_of_not_gt
      intro ahead
      obtain ⟨len,signed,term,quorum⟩ := highestCommittableIndex_spec c.post c.actor ahead
      let i := highestCommittableIndex c.post c.actor
      have hpos : 0 < i := Nat.zero_lt_of_lt ahead
      have prefixLog : c.pre.log <+: c.post.log := ⟨extra,adv.log.symm⟩
      let vs := c.post.activeMembers.filter fun v => v = c.actor ∨ i ≤ c.post.matchIndex v
      have q : hasQuorum (Timely.bounded c.post.log 0 i) vs := by
        rw [← zero]
        exact quorum
      by_cases within : i ≤ c.pre.log.length
      · have qs : Timely.bounded c.post.log 0 i = Timely.bounded c.pre.log 0 i := by
          rw [adv.log]
          exact Timely.bounded_append _ _ (Nat.zero_le _) within
        have q' : hasQuorum (Timely.bounded c.pre.log c.pre.commitIndex i) vs := by
          rw [preZero,← qs]
          exact q
        have repl : ∀ v ∈ vs, v = c.actor ∨ i ≤ c.pre.matchIndex v := by
          intro v hv
          rw [← matchEq]
          exact (Finset.mem_filter.mp hv).2
        have sign : isSignatureAt c.pre.log i = true :=
          isSignatureAt_of_prefix (List.take_prefix _ _)
            (take_eq_of_prefix prefixLog within ▸ isSignatureAt_take_of_le (Nat.le_refl i) signed)
        have atTerm := (termAt_of_prefix prefixLog within).symm.trans (term.trans stamp)
        have score := score_witness c.actor c.pre within (preZero ▸ hpos) sign atTerm
          (replace_voters c.pre c.actor i q' repl)
        have idle := prior _ _ c.pre_now primary prePeer preZero
        omega
      · obtain ⟨peer,other,pos⟩ := prePeer
        obtain ⟨conf,mem,hp⟩ := MatchAck.configured_in_run folded c.actor c.pre c.pre_now
          primary preZero peer pos
        have cBound : conf.index ≤ c.pre.log.length := by
          have le := (mem_history_filterMap mem).2
          omega
        have one : ∀ v ∈ vs, v = c.actor := by
          intro v hv
          by_cases diff : v = c.actor
          · exact diff
          have enough := ((Finset.mem_filter.mp hv).2).resolve_left diff
          rw [matchEq] at enough
          obtain ⟨_,_,_,bounded,_⟩ := c.match_pre primary diff (Nat.lt_of_lt_of_le hpos enough)
          exact (within (Nat.le_trans enough bounded)).elim
        have listed : conf ∈ Timely.bounded c.post.log 0 i := by
          unfold Timely.bounded
          rw [MatchAck.active_zero]
          exact List.mem_filter.mpr ⟨MatchAck.history_mono prefixLog mem,decide_eq_true (by omega)⟩
        exact MatchAck.no_single_majority c.actor peer conf vs other hp one
          (of_decide_eq_true (List.all_eq_true.mp q.2 conf listed))
    · have eq := ineligible c ev (fun yes => accepted ⟨src,r,ev,ok,term,yes⟩)
      rw [eq] at zero ⊢
      exact prior _ _ c.pre_now primary prePeer zero
  · obtain ⟨_,_,_,_,_,_,reset,_⟩ := Wins.facts won
    obtain ⟨v,_,pos⟩ := peer
    rw [reset] at pos
    exact (Nat.lt_irrefl _ pos).elim
end

private theorem idle_run {cfg nodes f} (folded : FullProfile.Folded cfg nodes f) :
    letI : Config.InitialConfiguration := ⟨cfg⟩
    ∀ n st, Now f n st → st.role = .primary → HasPeer n st → Idle n st := by
  letI : Config.InitialConfiguration := ⟨cfg⟩
  induction folded with
  | initial init =>
    intro n st now _ peer
    obtain ⟨v,_,positive⟩ := peer
    have eq := Consensus.Proofs.Safety.initial_state init now
    rw [eq] at positive
    exact (Nat.lt_irrefl _ positive).elim
  | step prior ran ih =>
    intro n st now role peer
    obtain ⟨tr⟩ := LocalTransition.ofStep ran
    let c : Ctx _ _ := ⟨tr,prior.invariant⟩
    rcases c.now_after now with ⟨rfl,rfl⟩ | ⟨_,old⟩
    · exact idle_step c prior ih role peer
    · exact ih n st old role peer

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)

private theorem positive_commit {mid : NodeState} (advance : Advance c.actor mid c.post)
    (prefixLog : c.pre.log <+: c.post.log) (matchEq : mid.matchIndex = c.pre.matchIndex)
    (frontier : mid.commitIndex = c.pre.commitIndex) (sameTerm : c.post.currentTerm = c.pre.currentTerm)
    (within : c.post.commitIndex ≤ c.pre.log.length)
    (zero : c.pre.commitIndex = 0) (pos : 0 < c.post.commitIndex) (idle : Idle c.actor c.pre) :
    False := by
  have grows : mid.commitIndex < c.post.commitIndex := frontier.trans zero ▸ pos
  obtain ⟨signed,stamp,vs,quorum,reaches⟩ := Timely.advance_quorum c advance grows
  have qs : Timely.bounded c.post.log c.pre.commitIndex c.post.commitIndex =
      Timely.bounded c.pre.log c.pre.commitIndex c.post.commitIndex := by
    obtain ⟨extra,h⟩ := prefixLog
    rw [← h]
    exact Timely.bounded_append _ _ (zero ▸ Nat.zero_le _) within
  have q : hasQuorum (Timely.bounded c.pre.log c.pre.commitIndex c.post.commitIndex) vs := by
    rw [← qs, ← frontier]
    exact quorum
  have voters : ∀ v ∈ vs, v = c.actor ∨ c.post.commitIndex ≤ c.pre.matchIndex v := by
    intro v mem
    rw [← matchEq]
    exact reaches v mem
  have sign : isSignatureAt c.pre.log c.post.commitIndex = true :=
    isSignatureAt_of_prefix (List.take_prefix _ _)
      (take_eq_of_prefix prefixLog within ▸ isSignatureAt_take_of_le (Nat.le_refl _) signed)
  have stamp' := (termAt_of_prefix prefixLog within).symm.trans (stamp.trans sameTerm)
  have bound := score_witness c.actor c.pre within (zero ▸ pos) sign stamp'
    (replace_voters c.pre c.actor _ q voters)
  exact (Nat.not_le_of_gt (zero ▸ pos)) (Nat.le_trans bound (idle zero))

private theorem ack_split {src r} (ev : c.event = .receive src (.appendEntriesResponse r))
    (stamp : r.term = c.pre.currentTerm) (ok : r.success = true) (role : c.post.role = .primary)
    (primary : c.pre.role = .primary) (term : c.post.currentTerm = c.pre.currentTerm)
    (different : src ≠ c.actor) (fresh : ¬ Now f c.actor c.post)
    (match_index : c.post.matchIndex src = r.lastLogIndex) (pos : 0 < c.post.matchIndex src) :
    SolvedWitnesses.sig c .match_ack_matchIndex_inr := by
  have now := c.post_now
  have received := And.intro ev (And.intro ok (And.intro stamp match_index))
  exact ⟨src,⟨now,role,different,pos,fun old => fresh old.1,rfl⟩,now,different,role,pos,now,
    ⟨primary,term⟩,primary,term,⟨r,received⟩,r,received,ev,received.2,ok,received.2.2,stamp,match_index,
    now,role,different,pos⟩
end

private theorem last_zero_impossible (s : Step)
    (keep : label s (.step .match_ack_matchIndex_inl) = true)
    (noAck : label s (.step .match_ack_matchIndex_inr) = false)
    (before : (endpoints s).1.1 = true) (after : (endpoints s).2.1 = false) : False := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have hit := ((label_true s (.step .match_ack_matchIndex_inl)).trans
    (SolvedWitnesses.sig_iff c .match_ack_matchIndex_inl)).mp keep
  obtain ⟨primary,role,term,peer,diff,positive⟩ := MatchAck.keep_facts c hit
  obtain ⟨zero,pos⟩ := MatchAck.last_zero_progress s before after
  have idle := idle_run s.folded c.actor c.pre c.pre_now primary ⟨peer,diff,positive⟩
  rcases MatchAck.keep_kinds c hit with ⟨_,same⟩ | ⟨extra,sent,advance⟩ | ⟨src,r,ev,ok,stamp,advance⟩
  · exact (Nat.ne_of_gt pos (same.trans zero))
  · exact positive_commit c advance ⟨extra,advance.log.symm⟩ rfl rfl term
      (MatchAck.last_zero_append_within s keep extra sent advance zero pos) zero pos idle
  · have eligible : src ∈ eligiblePeers c.pre c.actor := by
      apply Classical.not_not.mp
      intro bad
      have eq := ineligible c ev bad
      exact Nat.ne_of_gt pos ((congrArg NodeState.commitIndex eq).trans zero)
    have neq := (Finset.mem_erase.mp eligible).1
    have fresh : ¬ Now s.frame c.actor c.post := by
      intro was
      exact Nat.ne_of_gt pos ((congrArg NodeState.commitIndex (c.now_pre was)).trans zero)
    have same : (AckAdvance.middle c.pre src r).matchIndex = c.pre.matchIndex := by
      have grow : r.lastLogIndex ≤ c.pre.matchIndex src := by
        apply Nat.le_of_not_gt
        intro gt
        have eq : c.post.matchIndex src = r.lastLogIndex := by
          rw [advance.matchIndex]
          change Function.update _ src _ src = _
          rw [Function.update_self, Nat.max_eq_right (Nat.le_of_lt gt)]
        have positive' : 0 < c.post.matchIndex src := by omega
        have acked := ack_split c ev stamp ok role primary term neq fresh eq positive'
        have labelYes := ((label_true s (.step .match_ack_matchIndex_inr)).trans
          (SolvedWitnesses.sig_iff c .match_ack_matchIndex_inr)).mpr acked
        exact Bool.noConfusion (noAck.symm.trans labelYes)
      funext v
      change Function.update _ src (max _ _) v = _
      by_cases eq : v = src
      · subst v
        rw [Function.update_self, Nat.max_eq_left grow]
      · exact Function.update_of_ne eq _ _
    have log : c.post.log = c.pre.log := advance.log
    have within := (c.inv_step.frontier _ _ c.post_now).1
    rw [log] at within
    exact positive_commit c advance (log ▸ List.prefix_refl _) same rfl term within zero pos idle

public def rows := MatchAck.witnessed
public def patterns := MatchAck.patterns

public theorem counts : rows.Nodup ∧ rows.length = 20 ∧ patterns.Nodup ∧ patterns.length = 5 :=
  by decide +kernel

public theorem upper (s : Step) : nonTrunkLabel .match_ack s ∈ rows := by
  rcases List.mem_append.mp (MatchAck.upper s) with known | pending
  · exact known
  have one : MatchAck.remaining =
      [⟨(true,true),[true,true,false,false,false,false,false],(false,true)⟩] := by decide +kernel
  rw [one,List.mem_singleton] at pending
  have bits : ((nonTrunk .match_ack).map (fun b => label s (.step b))) =
      [true,true,false,false,false,false,false] := congrArg RestrictedProfile.bits pending
  rw [show nonTrunk .match_ack = _ from ClauseMatchAck.columns] at bits
  have step1 := congrArg (fun bs : List Bool => bs[1]?.getD false) bits
  have step2 := congrArg (fun bs : List Bool => bs[2]?.getD false) bits
  change label s (.step .match_ack_matchIndex_inl) = true at step1
  change label s (.step .match_ack_matchIndex_inr) = false at step2
  exact (last_zero_impossible s step1 step2
    (congrArg (fun r => (RestrictedProfile.pre r).1) pending)
    (congrArg (fun r => (RestrictedProfile.post r).1) pending)).elim

public theorem exact_rows (r : RestrictedProfile) :
    r ∈ rows ↔ ∃ s : Step, nonTrunkLabel .match_ack s = r :=
  ⟨MatchAck.lower r, by rintro ⟨s,rfl⟩; exact upper s⟩

public theorem exact_patterns (ps : List Bool) :
    ps ∈ patterns ↔ ∃ s : Step, (nonTrunkLabel .match_ack s).bits = ps :=
  MatchAck.exact_patterns ps

end ConsensusCoverage.ClauseSmallA.MatchAckExact
