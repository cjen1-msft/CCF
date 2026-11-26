module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseSmallA
public import ConsensusCoverage.ClauseMatchAckBounds
import all ConsensusCoverage.AckAdvance
import all ConsensusCoverage.ClauseExactTables
import all ConsensusCoverage.ClauseMatchAck
import all ConsensusCoverage.ClauseMatchAckBounds
import all ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.ClauseSmallA
import all ConsensusCoverage.FrontierRows
import all ConsensusCoverage.FullProfile
import all ConsensusCoverage.PairQuestions
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.StateCoverage
import all ConsensusCoverage.Timely
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.ClauseSmallA.MatchAck

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open CCF
open CCF.MultiNodeTransitionSystem
open Consensus.Proofs.Ledger
open ActionProfile ClauseQuestions ClauseExactTables

set_option maxHeartbeats 0
set_option maxRecDepth 8192

public def patterns := ClauseMatchAck.patterns
public def witnessed := ClauseMatchAckBounds.witnessed
public def remaining := ClauseMatchAckBounds.remaining.drop 1

public theorem exact_patterns (bits : List Bool) :
    bits ∈ patterns ↔ ∃ s : Step, (nonTrunkLabel .match_ack s).bits = bits :=
  ClauseMatchAck.patterns_exact bits

public theorem lower (r : RestrictedProfile) (mem : r ∈ witnessed) :
    ∃ s : Step, nonTrunkLabel .match_ack s = r :=
  ClauseMatchAckBounds.witnessed_realized mem

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private theorem keep_facts (h : SolvedWitnesses.sig c .match_ack_matchIndex_inl) :
    c.pre.role = .primary ∧ c.post.role = .primary ∧ c.post.currentTerm = c.pre.currentTerm ∧
      ∃ peer, peer ≠ c.actor ∧ 0 < c.pre.matchIndex peer := by
  obtain ⟨peer, _, _, diff, primary, pos, _, ⟨oldRole, term⟩, _, _, same, _⟩ := h
  exact ⟨oldRole,primary,term,peer,diff,same ▸ pos⟩

private theorem incumbent_kinds (oldRole : c.pre.role = .primary) (primary : c.post.role = .primary)
    (term : c.post.currentTerm = c.pre.currentTerm) :
    (c.post.log = c.pre.log ∧ c.post.commitIndex = c.pre.commitIndex) ∨
    (∃ entries sent, Advance c.actor { c.pre with log := c.pre.log ++ entries, sentIndex := sent } c.post) ∨
    ∃ source response, c.event = .receive source (.appendEntriesResponse response) ∧
      response.success = true ∧ response.term = c.pre.currentTerm ∧
      Advance c.actor (AckAdvance.middle c.pre source response) c.post := by
  cases Summary.kind c.sum with
  | same log commit => exact .inl ⟨log,commit⟩
  | append entries sent _ _ adv => exact .inr (.inl ⟨entries,sent,adv⟩)
  | ack source response received _ success stamp advance =>
    exact .inr (.inr ⟨source,response,received,success,stamp,advance⟩)
  | accept source request recv accepted =>
    obtain ⟨_, evidence, _⟩ := c.accept_shape recv accepted
    have oldLed := c.pre_led oldRole
    have same := accepted.1.trans term
    rw [← same] at oldLed
    exact (evidence.different (c.inv.election_safety _ _ _ evidence.led oldLed).symm).elim
  | elect won =>
    have ⟨_,_,_,phases,_,_,_,_⟩ := c.electStep (c.wins_elect won)
    have eq := (c.electStep (c.wins_elect won)).2.2.2.2.1
    rcases phases with lt | ⟨_, cand⟩
    · omega
    · rw [oldRole] at cand
      contradiction
  | install _ _ _ _ _ _ _ _ role =>
    rw [primary] at role
    contradiction

private theorem keep_kinds (h : SolvedWitnesses.sig c .match_ack_matchIndex_inl) :
    (c.post.log = c.pre.log ∧ c.post.commitIndex = c.pre.commitIndex) ∨
    (∃ entries sent, Advance c.actor { c.pre with log := c.pre.log ++ entries, sentIndex := sent } c.post) ∨
    ∃ source response, c.event = .receive source (.appendEntriesResponse response) ∧
      response.success = true ∧ response.term = c.pre.currentTerm ∧
      Advance c.actor (AckAdvance.middle c.pre source response) c.post := by
  obtain ⟨oldRole,primary,term,_⟩ := keep_facts c h
  exact incumbent_kinds c oldRole primary term

omit [Config.InitialConfiguration] in
private theorem history_mono {l r : List Entry} (sub : l <+: r) :
    configurationHistory l ⊆ configurationHistory r := by
  obtain ⟨rest,eq,_⟩ := configurationHistory_split r l.length
  have take : r.take l.length = l := List.prefix_iff_eq_take.mp sub |>.symm
  rw [take] at eq
  rw [eq]
  exact fun _ mem => List.mem_append_left _ mem

omit [Config.InitialConfiguration] in
private theorem current_eligible (st : NodeState) (self peer : NodeID) (zero : st.commitIndex = 0)
    (eligible : peer ∈ eligiblePeers st self) :
    ∃ cfg ∈ configurationHistory st.log, peer ∈ cfg.nodes := by
  have elig := (Finset.mem_erase.mp eligible).2
  have h : peer ∈ st.activeMembers := by
    simpa [NodeState.activeMembers,
      NodeState.retirementCompletedNodes, NodeState.committedLog, zero, configurationHistory,
      latestConfigurationMembers, retiredCommittedNodes, configurationMembers] using elig
  have fold (l : List Node.Configuration) (acc : Finset NodeID)
      (mem : peer ∈ l.foldl (fun a x => a ∪ x.nodes) acc) :
      peer ∈ acc ∨ ∃ cfg ∈ l, peer ∈ cfg.nodes := by
    induction l generalizing acc with
    | nil => exact .inl mem
    | cons cfg rest ih =>
      rcases ih (acc ∪ cfg.nodes) mem with found | ⟨c,hc,hp⟩
      · rcases Finset.mem_union.mp found with x | x
        · exact .inl x
        · exact .inr ⟨cfg,List.mem_cons_self,x⟩
      · exact .inr ⟨c,List.mem_cons_of_mem _ hc,hp⟩
  obtain ⟨cfg,mem,witness⟩ := (fold st.activeConfigurations ∅ h).resolve_left (by simp)
  exact ⟨cfg,List.mem_of_mem_drop mem,witness⟩

include c in
private theorem match_preconfigured {ns act} (ran : (transitionSystem Config.INITIAL_CONFIGURATION ns).step f.current act = some t)
    (old : ∀ n st, Now f n st → st.role = .primary → st.commitIndex = 0 →
      ∀ peer, 0 < st.matchIndex peer → ∃ cfg ∈ configurationHistory st.log, peer ∈ cfg.nodes)
    {n st} (now : Now (f.advance t) n st) (primary : st.role = .primary) (zero : st.commitIndex = 0)
    {peer} (positive : 0 < st.matchIndex peer) :
    ∃ cfg ∈ configurationHistory st.log, peer ∈ cfg.nodes := by
  rcases c.now_after now with ⟨rfl,rfl⟩ | ⟨_,prior⟩
  · rcases Summary.leader c.sum primary with ⟨preRole,term⟩ | won
    · have le := (Direct.committed_log_step c.inv.distinct ran c.pre_now c.post_now).length_le
      have preZero : c.pre.commitIndex = 0 := by
        simpa [NodeState.committedLog, zero, List.length_take, Nat.min_eq_left c.frontier_pre] using le
      have logPrefix : c.pre.log <+: c.post.log := by
        rcases incumbent_kinds c preRole primary term with ⟨same,_⟩ | ⟨entries,_,adv⟩ | ⟨_,_,_,_,_,adv⟩
        · rw [same]
          exact List.prefix_refl _
        · exact ⟨entries,adv.log.symm⟩
        · rw [adv.log]
          exact List.prefix_refl _
      suffices h : ∃ cfg ∈ configurationHistory c.pre.log, peer ∈ cfg.nodes by
        obtain ⟨cfg,mem,yes⟩ := h
        exact ⟨cfg,history_mono logPrefix mem,yes⟩
      by_cases was : 0 < c.pre.matchIndex peer
      · exact old _ _ c.pre_now preRole preZero peer was
      have ⟨r,event,ok,stamp,_⟩ := (Summary.matchIndex c.sum primary preRole term peer).resolve_left
        (fun same => was (same ▸ positive))
      by_cases eligible : peer ∈ eligiblePeers c.pre c.actor
      · exact current_eligible _ _ _ preZero eligible
      · have executes := c.tr.ran
        change ((Model.Node.step (Capabilities.record c.actor) c.actor c.pre c.event).run {}) = _ at executes
        rw [event] at executes
        simp [Model.Node.step,receive,eligible] at executes
        have eq : c.post.matchIndex peer = c.pre.matchIndex peer :=
          congrArg (fun s : NodeState => s.matchIndex peer) executes.1.symm
        exact (was (eq ▸ positive)).elim
    · obtain ⟨_,_,_,_,_,_,reset,_⟩ := Wins.facts won
      rw [reset] at positive
      omega
  · exact old n st prior primary zero peer positive
end

private theorem configured_in_run {cfg nodes f} (folded : FullProfile.Folded cfg nodes f) :
    letI : Config.InitialConfiguration := ⟨cfg⟩
    ∀ n st, Now f n st → st.role = .primary → st.commitIndex = 0 →
      ∀ peer, 0 < st.matchIndex peer → ∃ c ∈ configurationHistory st.log, peer ∈ c.nodes := by
  letI : Config.InitialConfiguration := ⟨cfg⟩
  induction folded with
  | initial init =>
    intro n st now _ _ peer positive
    have eq := Consensus.Proofs.Safety.initial_state init now
    rw [eq] at positive
    exact (Nat.lt_irrefl _ positive).elim
  | step prior ran ih =>
    intro n st now primary zero peer positive
    obtain ⟨tr⟩ := LocalTransition.ofStep ran
    let c : Ctx _ _ := ⟨tr,prior.invariant⟩
    exact match_preconfigured c ran ih now primary zero positive

private theorem observed_anchor {cfg nodes f} (folded : FullProfile.Folded cfg nodes f) :
    letI : Config.InitialConfiguration := ⟨cfg⟩
    ∀ n o i, Seen f n o → 0 < i → i ≤ o.log.length →
      ∃ log, Canon f (termAt o.log i) log ∧ i ≤ log.length := by
  letI : Config.InitialConfiguration := ⟨cfg⟩
  induction folded with
  | initial init =>
    intro n o i seen positive bound
    rcases seen with no | ⟨st,now,_,eq⟩
    · contradiction
    · rw [← eq] at bound ⊢
      obtain ⟨log,can,len,_⟩ := (FullProfile.Folded.initial init).invariant.anchor n st i now positive bound
      exact ⟨log,can,len⟩
  | step prior ran ih =>
    intro n o i seen positive bound
    obtain ⟨tr⟩ := LocalTransition.ofStep ran
    let c : Ctx _ _ := ⟨tr,prior.invariant⟩
    rcases c.seen_after seen with old | ⟨rfl,rfl⟩
    · obtain ⟨log,can,len⟩ := ih _ _ _ old positive bound
      exact ⟨log,.inl can,len⟩
    · obtain ⟨log,can,len,_⟩ := c.inv_step.anchor c.actor c.post i c.post_now positive bound
      exact ⟨log,can,len⟩

private theorem active_zero (l : List Entry) :
    activeConfigurations l 0 = configurationHistory l := by
  unfold activeConfigurations
  dsimp only
  have cut : (configurationHistory l).filter (fun c => decide (c.index ≤ 0)) = [] := by
    apply List.filter_eq_nil_iff.mpr
    intro c mem
    have pos := (mem_history_filterMap mem).1
    intro hit
    exact Nat.not_le_of_gt pos (of_decide_eq_true hit)
  rw [cut]
  rfl

private theorem no_single_majority (self peer : NodeID) (conf : Node.Configuration) (vs : Finset NodeID)
    (other : peer ≠ self) (member : peer ∈ conf.nodes)
    (only : ∀ v ∈ vs, v = self) (majority : hasConfigurationMajority vs conf) : False := by
  have small : (vs ∩ conf.nodes).card ≤ 1 := by
    have sub : vs ∩ conf.nodes ⊆ ({self} : Finset NodeID) := fun _ mem =>
      Finset.mem_singleton.mpr (only _ (Finset.mem_inter.mp mem).1)
    exact Finset.card_le_card sub
  by_cases here : self ∈ conf.nodes
  · have dis : Finset.Disjoint ({self} : Finset NodeID) {peer} := by
      apply Finset.disjoint_left.mpr
      intro v h
      have eq := Finset.mem_singleton.mp h
      subst v
      exact fun hp => other (Finset.mem_singleton.mp hp).symm
    have sub : ({self} : Finset NodeID) ∪ {peer} ⊆ conf.nodes := by
      intro v h
      rcases Finset.mem_union.mp h with h | h
      · exact (Finset.mem_singleton.mp h).symm ▸ here
      · exact (Finset.mem_singleton.mp h).symm ▸ member
    have large := Finset.card_le_card sub
    rw [Finset.card_union_of_disjoint dis] at large
    change 1+1 ≤ conf.nodes.card at large
    unfold hasConfigurationMajority at majority
    omega
  · have empty : vs ∩ conf.nodes = ∅ := by
      ext v
      simp only [Finset.mem_inter, Finset.notMem_empty, iff_false]
      intro ⟨a,b⟩
      exact here (only v a ▸ b)
    unfold hasConfigurationMajority at majority
    simp [empty] at majority

public theorem first_backing_impossible (s : Step)
    (keep : label s (.step .match_ack_matchIndex_inl) = true)
    (before : (endpoints s).1.2 = false) (after : (endpoints s).2.2 = true) : False := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have hit := (SolvedWitnesses.sig_iff c .match_ack_matchIndex_inl).mp
    ((label_true s (.step .match_ack_matchIndex_inl)).mp keep)
  obtain ⟨primary,_,term,peer,diff,positive⟩ := keep_facts c hit
  have prefixLog : c.pre.log <+: c.post.log := by
    rcases keep_kinds c hit with ⟨same,_⟩ | ⟨entries,_,adv⟩ | ⟨_,_,_,_,_,adv⟩
    · exact same ▸ List.prefix_refl _
    · exact ⟨entries,adv.log.symm⟩
    · rw [adv.log]
      exact List.prefix_refl _
  have noKeys : ∀ k p, ¬ Committed s.frame k p := by
    intro k p yes
    have backing := (StateCoverage.backed_iff _ c.inv).mpr ⟨List.ne_nil_of_mem c.pre_now,k,p,yes⟩
    exact Bool.noConfusion (before.symm.trans ((StateCoverage.read_iff _ _ c.inv).2.mpr backing))
  have preZero : c.pre.commitIndex = 0 := by
    obtain ⟨_, zero | ⟨k,p,was,_⟩⟩ := (c.inv.commit_backed _ _ c.pre_now).1
    · exact zero
    · exact (noKeys k p was).elim
  obtain ⟨conf, member, hp⟩ := configured_in_run s.folded c.actor c.pre c.pre_now primary preZero peer positive
  have confBound : conf.index ≤ c.pre.log.length := by
    have bound := (mem_history_filterMap member).2
    omega
  have ledPre := c.pre_led primary
  have ncPre : c.pre.role ≠ .candidate := by rw [primary]; decide
  have oldLed {n k} (h : Led (s.frame.advance s.after) n k) : Led s.frame n k := by
    obtain old | ⟨_,_,e⟩ := c.led_after h
    · exact old
    · obtain ⟨_,_,_,lt | ⟨_,cand⟩,same,_⟩ := c.electStep e
      · have same' : c.post.currentTerm = c.pre.currentTerm := term
        omega
      · rw [primary] at cand
        contradiction
  have yes : (s.frame.advance s.after).current.nodes ≠ [] ∧
      ∃ k p, Committed (s.frame.advance s.after) k p := (StateCoverage.backed_iff _ c.inv_step).mp
    ((StateCoverage.read_iff s.after (s.before :: s.past) c.inv_step).2.mp after)
  obtain ⟨_,k,p,key⟩ := yes
  rcases key with old | ⟨n,st,base,i,cert,rfl,backing⟩
  · exact noKeys k p old
  change CommitStep (s.frame.advance s.after) n st k base i at cert
  change Backed s.frame st.log base k at backing
  have zero : base = 0 := backing.elim id (fun ⟨a,l,past,_⟩ => (noKeys a l past).elim)
  subst base
  obtain ⟨⟨now,stamp,nc,lead⟩,bi,within,signed,atI,vs,quorum,observed⟩ := cert
  rcases c.now_after now with ⟨rfl,rfl⟩ | ⟨ne,prior⟩
  · by_cases short : i ≤ c.pre.log.length
    · have part := take_eq_of_prefix prefixLog short
      have signature : isSignatureAt c.pre.log i = true := by
        exact isSignatureAt_of_prefix (List.take_prefix _ _)
          (part ▸ isSignatureAt_take_of_le (Nat.le_refl i) signed)
      have indexTerm : termAt c.pre.log i = k := (termAt_of_prefix prefixLog short).symm.trans atI
      have qs : Timely.bounded c.post.log 0 i = Timely.bounded c.pre.log 0 i := by
        obtain ⟨extra,log⟩ := prefixLog
        rw [← log]
        exact Timely.bounded_append _ _ bi short
      apply noKeys k (c.pre.log.take i)
      apply FrontierRows.fresh_commit (n := c.actor)
      have preQuorum : hasQuorum (Timely.bounded c.pre.log 0 i) vs := by
        rw [← qs]
        exact quorum
      refine ⟨⟨c.pre_now,term.symm.trans stamp,ncPre,oldLed lead⟩,bi,short,signature,indexTerm,
        vs,preQuorum,?_⟩
      intro v hv
      obtain ⟨l,seen,sub⟩ := observed v hv
      rcases c.seen_after (o := ⟨k,l⟩) seen with old | ⟨rfl,_⟩
      · exact ⟨l,old,part ▸ sub⟩
      · exact ⟨c.pre.log, (term.symm.trans stamp) ▸ c.inv.observed _ _ c.pre_now,
          List.take_prefix _ _⟩
    · have total : ∀ v ∈ vs, v = c.actor := by
        intro v hv
        by_cases other : v = c.actor
        · exact other
        obtain ⟨l,seen,sub⟩ := observed v hv
        have old : Seen s.frame v ⟨k,l⟩ :=
          (c.seen_after (o := ⟨k,l⟩) seen).resolve_right (fun h => other h.1)
        have bound : i ≤ l.length := by
          have h := sub.length_le
          rwa [List.length_take, Nat.min_eq_left within] at h
        have lt : 0 < i := by omega
        obtain ⟨anchor,can,len⟩ := observed_anchor s.folded v ⟨k,l⟩ i old lt bound
        have atTerm : termAt l i = k := by
          have subBound : i ≤ (c.post.log.take i).length := by
            simp [List.length_take, Nat.min_eq_left within]
          rw [termAt_of_prefix sub subBound, termAt_take (Nat.le_refl i)]
          exact atI
        rw [atTerm, ← stamp, term] at can
        have inPre := (c.inv.canon_mono _ _ c.pre_now ncPre ledPre).1 _ can
        exact (short (Nat.le_trans len inPre.length_le)).elim
      have elem : conf ∈ Timely.bounded c.post.log 0 i := by
        unfold Timely.bounded
        rw [active_zero]
        apply List.mem_filter.mpr
        refine ⟨history_mono prefixLog member,decide_eq_true ?_⟩
        omega
      exact no_single_majority c.actor peer conf vs diff hp total
        (of_decide_eq_true (List.all_eq_true.mp quorum.2 conf elem))
  · apply noKeys k (st.log.take i)
    apply FrontierRows.fresh_commit (n := n)
    refine ⟨⟨prior,stamp,nc,oldLed lead⟩,bi,within,signed,atI,vs,quorum,?_⟩
    intro v hv
    obtain ⟨l,seen,sub⟩ := observed v hv
    rcases c.seen_after (o := ⟨k,l⟩) seen with old | ⟨rfl,eq⟩
    · exact ⟨l,old,sub⟩
    · have stamp' : k = c.post.currentTerm := congrArg Observation.currentTerm eq
      have actorLed : Led s.frame c.actor k := (stamp'.trans term).symm ▸ ledPre
      exact (ne (c.inv.election_safety n c.actor k (oldLed lead) actorLed)).elim

private theorem first_row_quotient (r : RestrictedProfile)
    (mem : r ∈ ClauseMatchAckBounds.remaining) :
    r ∈ remaining ∨ r =
      ⟨(true,false),[true,true,false,false,false,false,false],(true,true)⟩ := by
  have exhaustive : ∀ q ∈ ClauseMatchAckBounds.remaining,
      q ∈ remaining ∨ q = ⟨(true,false),[true,true,false,false,false,false,false],(true,true)⟩ :=
    by decide +kernel
  exact exhaustive r mem

public theorem upper (s : Step) : nonTrunkLabel .match_ack s ∈ witnessed ++ remaining := by
  rcases List.mem_append.mp (ClauseMatchAckBounds.upper s) with known | extra
  · exact List.mem_append_left _ known
  rcases first_row_quotient _ extra with still | impossible
  · exact List.mem_append_right _ still
  have atKept := congrArg (fun r : RestrictedProfile => r.bits[1]?.getD false) impossible
  have keep : label s (.step .match_ack_matchIndex_inl) = true := by
    change (nonTrunkLabel .match_ack s).bits[1]?.getD false = true at atKept
    change ((ClauseMatchAck.nonTrunk .match_ack).map (fun b => label s (.step b)))[1]?.getD false =
      true at atKept
    rw [ClauseMatchAck.columns] at atKept
    exact atKept
  exact (first_backing_impossible s keep
    (congrArg (fun r : RestrictedProfile => r.pre.2) impossible)
    (congrArg (fun r : RestrictedProfile => r.post.2) impossible)).elim

public theorem counts :
    patterns.length = 5 ∧ patterns.Nodup ∧ witnessed.length = 20 ∧
      (witnessed ++ remaining).length = 21 ∧ (witnessed ++ remaining).Nodup :=
  by decide +kernel

private theorem last_zero_progress (s : Step)
    (before : (endpoints s).1.1 = true) (after : (endpoints s).2.1 = false) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    let c := s.context
    c.pre.commitIndex = 0 ∧ 0 < c.post.commitIndex := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  obtain ⟨n,st,mem,zero⟩ := (PairQuestions.zero_mem s.before).mp before
  have old : Now s.frame n st := by
    change (n,st) ∈ s.frame.current.nodes
    rwa [show s.frame.current = s.before from s.current_eq]
  have none : ¬ ∃ n st, (n,st) ∈ s.after.nodes ∧ st.commitIndex = 0 := by
    intro h
    exact Bool.noConfusion (after.symm.trans ((PairQuestions.zero_mem s.after).mpr h))
  have actor : n = c.actor := by
    apply Classical.not_not.mp
    intro diff
    apply none
    refine ⟨n,st,?_,zero⟩
    rw [c.tr.nodesEq]
    exact List.mem_map.mpr ⟨_,old,by simp [diff]⟩
  subst n
  have preZero : c.pre.commitIndex = 0 := by rwa [c.now_pre old] at zero
  have postPos : 0 < c.post.commitIndex := Nat.pos_of_ne_zero fun eq =>
    none ⟨_, _, c.post_now, eq⟩
  exact ⟨preZero,postPos⟩

private theorem last_zero_append_within (s : Step)
    (keep : label s (.step .match_ack_matchIndex_inl) = true) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    let c := s.context
    ∀ entries sent, Advance c.actor { c.pre with log := c.pre.log ++ entries, sentIndex := sent } c.post →
      c.pre.commitIndex = 0 → 0 < c.post.commitIndex → c.post.commitIndex ≤ c.pre.log.length := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  change ∀ entries sent, Advance c.actor { c.pre with log := c.pre.log ++ entries, sentIndex := sent } c.post →
      c.pre.commitIndex = 0 → 0 < c.post.commitIndex → c.post.commitIndex ≤ c.pre.log.length
  intro entries sent adv zero positive
  have hit := (SolvedWitnesses.sig_iff c .match_ack_matchIndex_inl).mp
    ((label_true s (.step .match_ack_matchIndex_inl)).mp keep)
  obtain ⟨primary,_,_,peer,diff,index⟩ := keep_facts c hit
  obtain ⟨conf,member,hp⟩ := configured_in_run s.folded c.actor c.pre c.pre_now primary zero peer index
  have bounded : conf.index ≤ c.pre.log.length := by
    have le := (mem_history_filterMap member).2
    omega
  apply Classical.not_not.mp
  intro tooLong
  have grows : c.pre.commitIndex < c.post.commitIndex := by omega
  obtain ⟨_,_,vs,quorum,reach⟩ := Timely.advance_quorum c adv grows
  have total : ∀ v ∈ vs, v = c.actor := by
    intro v hv
    by_cases other : v = c.actor
    · exact other
    have enough := (reach v hv).resolve_left other
    have posMatch : 0 < c.pre.matchIndex v := Nat.lt_of_lt_of_le positive enough
    obtain ⟨_,_,_,bound,_⟩ := c.match_pre primary other posMatch
    exact (tooLong (Nat.le_trans enough bound)).elim
  have nextLog : c.pre.log <+: c.post.log := ⟨entries,adv.log.symm⟩
  have elem : conf ∈ Timely.bounded c.post.log c.pre.commitIndex c.post.commitIndex := by
    rw [zero]
    unfold Timely.bounded
    rw [active_zero]
    exact List.mem_filter.mpr ⟨history_mono nextLog member,decide_eq_true (by omega)⟩
  exact no_single_majority c.actor peer conf vs diff hp total
    (of_decide_eq_true (List.all_eq_true.mp quorum.2 conf elem))

public theorem last_zero_at_primary (s : Step)
    (keep : label s (.step .match_ack_matchIndex_inl) = true)
    (before : (endpoints s).1.1 = true) (after : (endpoints s).2.1 = false) :
    ∃ n pre post, (n,pre) ∈ s.before.nodes ∧ (n,post) ∈ s.after.nodes ∧
      pre.role = .primary ∧ pre.commitIndex = 0 ∧ 0 < post.commitIndex ∧
        post.commitIndex ≤ pre.log.length := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have pre : (c.actor,c.pre) ∈ s.before.nodes := by
    rw [← show s.frame.current = s.before from s.current_eq]
    exact c.pre_now
  have hit := (SolvedWitnesses.sig_iff c .match_ack_matchIndex_inl).mp
    ((label_true s (.step .match_ack_matchIndex_inl)).mp keep)
  obtain ⟨zero,pos⟩ := last_zero_progress s before after
  refine ⟨_,_,_,pre,c.post_now,(keep_facts c hit).1,zero,pos,?_⟩
  rcases keep_kinds c hit with ⟨_,same⟩ | ⟨extra,sent,adv⟩ | ⟨_,_,_,_,_,adv⟩
  · change s.context.post.commitIndex = s.context.pre.commitIndex at same
    exact (Nat.ne_of_gt pos (same.trans zero)).elim
  · exact last_zero_append_within s keep extra sent adv zero pos
  · have bounded := (c.inv_step.frontier _ _ c.post_now).1
    rwa [adv.log] at bounded

end ConsensusCoverage.ClauseSmallA.MatchAck
