module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersOtherConditionBase
import all ConsensusCoverage.HandReadersOtherPromotion
import all ConsensusCoverage.SelfQuorumCasesB
import all ConsensusCoverage.AssistConflictA
import all ConsensusCoverage.AssistReplyA
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersOther.Condition

open CCF Consensus Model Model.Node Proofs Safety Ledger ActionProfile HandReadersA SolvedWitnesses
set_option maxRecDepth 8192
set_option maxHeartbeats 1800000

abbrev Picks (pos : Bool) (p : Prop) := if pos then p else ¬p

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private theorem remote {n m} (pos : Bool) (fresh : Fresh c) (ev : c.event = .receive n m)
    (pass : ¬blocked c.actor c.pre n m) (ok : pos = true → inner c.actor c.pre m = true) : Answer c pos := by
  refine ⟨fresh,?_⟩; rw [ev]; cases pos <;> simp [test,pass,ok]

private abbrev Both := ∀ pos, Answer c pos

private theorem campaign {caps self z} (h : (reach% step_ite__condition_pos[0,3]) f t c caps self z) : Both c := by
  rcases h with ⟨_,n,_,co,_,q,rfl,pass,g,_⟩ |
    ⟨_,(⟨_,n,_,co,_,q,rfl,pass,g,_⟩ | ⟨_,n,m,co,_,msg,pass,can,_⟩),_⟩
  all_goals obtain ⟨fresh,rfl,rfl,ev,_⟩ := (receive_iff c).mp co
  · exact fun pos => remote c pos fresh ev pass (fun _ => decide_eq_true g)
  · exact fun pos => remote c pos fresh ev pass (fun _ => decide_eq_true g)
  · generalize eq : (observeTerm c.pre m).currentTerm = k at msg; subst m
    exact fun pos => remote c pos fresh ev pass (fun _ => decide_eq_true ⟨eq.symm,can⟩)

private theorem advanced {m self caps} (h : (reach% step_ite__condition_pos[0,1]) f t c m self caps) : Both c := by
  rcases h with ⟨_,n,_,co,_,q,rfl,pass,_,success,_⟩ | ⟨_,co,_⟩
  · obtain ⟨fresh,rfl,rfl,ev,_⟩ := (receive_iff c).mp co
    exact fun pos => remote c pos fresh ev pass (fun _ => decide_eq_true (.inr success))
  · exact campaign c co.1

private theorem timeCandidate {caps self st} (h : (reach% step_ite__condition_pos[1,3]) f t c caps self st) :
    Fresh c ∧ c.event = .internal (.timeout .election) ∧ self = c.actor ∧
      timeQuorum c.actor c.pre ∧ st = freshCandidate c.actor (firstVote c.actor c.pre) := by
  obtain ⟨_,⟨_,co,q,_,rfl⟩,_,rfl⟩ := h
  obtain ⟨fresh,rfl,rfl,ev,_⟩ := (timeout_iff c).mp co
  exact ⟨fresh,ev,rfl,q,rfl⟩

private theorem appended {caps self i} (h : Local c caps self i) {es} (eq : i = .append es) : Both c := by
  obtain ⟨fresh,_,ev,_⟩ := (local_iff c).mp h
  exact fun _ => ⟨fresh,by rw [ev,eq]; rfl⟩

private theorem timedHigh : let m := primaryState (freshCandidate c.actor (firstVote c.actor c.pre))
    highestCommittableIndex m c.actor ≤ m.commitIndex := by
  dsimp only
  apply Nat.le_of_not_gt; intro gt
  obtain ⟨_,sig,atTerm,_⟩ := highestCommittableIndex_spec _ _ gt
  obtain ⟨e,found,_⟩ := isSignatureAtTrue sig
  have mem := (primaryState_log_prefix _).subset (entryAt_mem found)
  have bound := c.inv.terms c.actor c.pre c.pre_now e mem
  unfold termAt at atTerm; rw [found] at atTerm
  change e.term = c.pre.currentTerm + 1 at atTerm
  omega

private theorem timeAdvance {m self caps} (h : (reach% step_ite__condition_pos[1,1]) f t c m self caps) :
    Both c ∨ (Fresh c ∧ c.event = .internal (.timeout .election) ∧ timeQuorum c.actor c.pre ∧
      highestCommittableIndex m self ≤ m.commitIndex) := by
  rcases h with ⟨i,co,es,eq,_⟩ | ⟨z,co,_,rfl⟩
  · exact .inl (appended c co eq)
  · obtain ⟨fresh,ev,rfl,q,rfl⟩ := timeCandidate c co.1
    exact .inr ⟨fresh,ev,q,timedHigh c⟩

private theorem request {self z r caps n} (h : (reach% step_ite__condition_pos[0,2]) f t c self z r caps n) :
    Fresh c ∧ self = c.actor ∧ c.event = .receive n (.appendEntriesRequest r) ∧
      z = observeTerm c.pre (.appendEntriesRequest r) := by
  obtain ⟨_,_,co,_,rfl,_,_,_,rfl⟩ := h
  obtain ⟨fresh,rfl,rfl,ev,_⟩ := (receive_iff c).mp co
  exact ⟨fresh,rfl,ev,rfl⟩

private theorem receive_only {p m v} (route : (reach% step_ite__condition_pos[0]) f t c p m v)
    (pos : Bool) (cut : Picks pos p) : Answer c pos := by
  rcases route with h | h | h | h | h | h | h | h | h | h | h | h | h | h
  all_goals first
    | obtain ⟨caps,self,_,n,_,co,_,r,rfl,pass,rest⟩ := h
      obtain ⟨fresh,rfl,rfl,ev,_⟩ := (receive_iff c).mp co
      apply remote c pos fresh ev pass; rintro rfl
      change p at cut
      repeat' (change _ ∧ _ at rest; obtain ⟨field,rest⟩ := rest)
      subst p
      simp only [inner,decide_eq_true_eq]
      first | assumption | exact .inr (by assumption) | exact .inl (by simpa using cut)
    | obtain ⟨caps,self,st,n,msg,co,_,_,rfl,_,_⟩ := h
      obtain ⟨fresh,rfl,rfl,ev,_⟩ := (receive_iff c).mp co
      refine ⟨fresh,?_⟩; rw [ev]
      cases pos
      · exact decide_eq_true cut
      · exact Bool.or_eq_true_iff.mpr (.inl (decide_eq_true cut))
    | obtain ⟨_,_,_,co,_⟩ := h; exact advanced c co pos
    | obtain ⟨_,_,_,co,_⟩ := h; exact campaign c co pos
    | obtain ⟨_,_,r,_,_,co,rest⟩ := h
      obtain ⟨fresh,rfl,ev,rfl⟩ := request c co
      apply remote c pos fresh ev (fun bad => Bool.noConfusion bad.1); rintro rfl
      change p at cut
      repeat' (change _ ∧ _ at rest; obtain ⟨field,rest⟩ := rest)
      subst p
      apply decide_eq_true
      first | exact .inl cut | exact .inr cut

private theorem local_only {p m v} (route : (reach% step_ite__condition_pos[1]) f t c p m v)
    (pos : Bool) (cut : Picks pos p) : Answer c pos := by
  rcases route with h | h | h | h | h | h | h | h
  all_goals first
    | obtain ⟨_,_,_,_,⟨_,co,es,eq,_⟩,_⟩ := h; exact appended c co eq pos
    | obtain ⟨_,_,_,co,grow,_⟩ := h
      rcases timeAdvance c co with both | ⟨_,_,_,le⟩
      · exact both pos
      · exact (grow le).elim
    | obtain ⟨_,_,_,co,_,rfl,_,_⟩ := h
      rcases timeAdvance c co with both | ⟨fresh,ev,q,le⟩
      · exact both pos
      · cases pos
        · exact (cut le).elim
        · exact ⟨fresh,by rw [ev]; exact decide_eq_true q⟩
    | obtain ⟨_,_,_,co,_,rfl,_,_⟩ := h
      obtain ⟨fresh,rfl,rfl,ev,_⟩ := (timeout_iff c).mp co
      cases pos
      · exact ⟨fresh,by rw [ev]; exact decide_eq_true (.inl cut)⟩
      · exact ⟨fresh,by rw [ev]; exact decide_eq_true cut⟩
    | obtain ⟨_,_,_,co,_,rfl,_,_⟩ := h
      obtain ⟨fresh,ev,rfl,q,rfl⟩ := timeCandidate c co
      cases pos
      · exact ⟨fresh,by rw [ev]; exact decide_eq_true (.inr cut)⟩
      · exact ⟨fresh,by rw [ev]; exact decide_eq_true q⟩

theorem necessary (pos : Bool) (yes : sig c (column pos)) : Answer c pos := by
  cases pos <;> rcases yes with ⟨_,_,_,route,cut,_⟩ | ⟨_,_,_,route,cut,_⟩
  all_goals first | exact receive_only c route _ cut | exact local_only c route _ cut
end

end ConsensusCoverage.HandReadersOther.Condition
