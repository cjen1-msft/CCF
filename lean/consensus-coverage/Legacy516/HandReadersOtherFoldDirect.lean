module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersOtherPromotion
import all ConsensusCoverage.HandReadersOtherAdvance
import all ConsensusCoverage.HandReadersAObserve
import all ConsensusCoverage.AckAdvance
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersOther.Fold

open CCF Consensus Model Model.Node Proofs Safety ActionProfile HandReadersA SolvedWitnesses

set_option maxRecDepth 8192
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private def ack (self : NodeID) (pre : NodeState) : Event → Option NodeState
  | .receive src m@(.appendEntriesResponse r) =>
    let z := observeTerm pre m
    if src ∈ eligiblePeers pre self ∧ z.role = .primary ∧ r.success ∧ r.term = z.currentTerm then
      some (AckAdvance.middle z src r) else none
  | _ => none

private def appends : Event → Bool
  | .internal (.append _) => true
  | _ => false

private def direct (self : NodeID) (pre : NodeState) (ev : Event) : Bool :=
  appends ev || (ack self pre ev).any (fun m => decide (m.commitIndex < highestCommittableIndex m self)) ||
    (Promotion.candidate self pre ev).any (fun z => decide (Promotion.elects self z ∧
      z.commitIndex < highestCommittableIndex (primaryState z) self))

def reader : Reader := fun cfg before act after past =>
  Promotion.gated direct cfg before act after past || Advance.reader .growth cfg before act after past

private def sample : NodeState :=
  ⟨.primary,0,[⟨0,.transaction 0 {configuration := some {0}}⟩,⟨0,.signature⟩],0,
    fun _ => 0,fun _ => 2,false,none,false,∅,∅,none⟩

private theorem sample_high (self : NodeID) : sample.commitIndex < highestCommittableIndex sample self := by
  let test := fun (i : Nat) => i > sample.commitIndex ∧ isSignatureAt sample.log i ∧
    termAt sample.log i = sample.currentTerm ∧
    hasQuorum (sample.activeConfigurations.filter fun c => c.index ≤ i)
      (sample.activeMembers.filter fun v => v = self ∨ sample.matchIndex v ≥ i)
  have all : sample.activeMembers.filter (fun v => v = self ∨ sample.matchIndex v ≥ 2) = sample.activeMembers := by
    apply Finset.ext; intro v; simp only [Finset.mem_filter]; exact ⟨And.left,fun m => ⟨m,.inr (Nat.le_refl _)⟩⟩
  have good : test 2 := by
    refine ⟨by decide,by decide,rfl,?_⟩; rw [all]; decide
  let step := fun (a i : Nat) => if test i then max a i else a
  change 0 < step (step (step 0 0) 1) 2
  simp only [step,ite_eq_left good]; omega

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private abbrev LeftCall (m : NodeState) (n : NodeID) :=
  (reach% step_foldl_select_max_values_cons[4,0,0,0]) f t c m n
private abbrev RightCall (m : NodeState) (n : NodeID) :=
  (reach% step_foldl_select_max_values_cons[5,0,0,0]) f t c m n
abbrev DirectSite (m : NodeState) (n : NodeID) :=
  (reach% step_foldl_select_max_values_cons[4,0,0]) f t c m n ∨
  (reach% step_foldl_select_max_values_cons[5,0,0]) f t c m n

private theorem inputs {n i} (h : (reach% step_foldl_select_max_values_cons[4,0,0,0,0]) f t c n i) :
    ¬Now f c.actor c.post ∧ n = c.actor ∧ c.event = .internal i := by
  obtain ⟨st,ev,post,out,⟨_,_,_,fresh,eq,_,same,_,_⟩,int,_⟩ := h
  exact ⟨fresh,eq,same.symm.trans int⟩

private theorem from_ack {m self} (h : RightCall c m self) :
    (¬Now f c.actor c.post ∧ self = c.actor ∧ ack self c.pre c.event = some m) ∨
    ∃ z, Promotion.Primary c self z ∧ m = primaryState z := by
  rcases h with h | ⟨z,co,_,rfl⟩
  · obtain ⟨_,src,_,co,_,r,rfl,pass,leader,pos,term,_,_,rfl⟩ := h
    obtain ⟨fresh,rfl,rfl,ev⟩ := (Observe.receive_iff c).mp co
    have peer := Classical.byContradiction fun no => pass ⟨rfl,no⟩
    have role : (observeTerm c.pre (.appendEntriesResponse r)).role = .primary := by simpa using leader
    exact .inl ⟨fresh,rfl,by rw [ev,ack,ite_eq_left ⟨peer,role,pos,term⟩]; rfl⟩
  · exact .inr ⟨z,.inl co,rfl⟩

private theorem to_ack {m} (fresh : ¬Now f c.actor c.post) (h : ack c.actor c.pre c.event = some m) :
    RightCall c m c.actor ∧ Direct.CommitFrontier m := by
  cases ev : c.event with
  | internal => simp [ev,ack] at h
  | receive n msg =>
    have co := (Observe.receive_iff c (self := c.actor) (st := c.pre)).mpr ⟨fresh,rfl,rfl,ev⟩
    have fr := c.inv.frontier _ _ c.pre_now
    have seen : Direct.CommitFrontier (observeTerm c.pre msg) :=
      fr.of_log (Concrete.observeTerm_log ..) (Concrete.observeTerm_commitIndex ..)
    cases msg <;> simp only [ev,ack] at h <;> try contradiction
    split at h <;> try contradiction
    rename_i g; cases h
    exact ⟨.inl ⟨_,_,_,co,fun h => h.2 g.1,_,rfl,fun h => h.2 g.1,
      by simp [g.2.1],g.2.2.1,g.2.2.2,fr,seen,rfl⟩,seen⟩

private theorem origin {n m} (h : LeftCall c m n ∨ RightCall c m n)
    (gt : m.commitIndex < highestCommittableIndex m n) :
    ¬Now f c.actor c.post ∧ direct c.actor c.pre c.event := by
  rcases h with (⟨i,co,xs,rfl,_⟩ | ⟨z,co,_,rfl⟩) | right
  · obtain ⟨fresh,rfl,ev⟩ := inputs c co
    exact ⟨fresh,by simp [direct,ev,appends]⟩
  · obtain ⟨fresh,rfl,eq,e⟩ := (Promotion.primary_iff c).mp (.inr co)
    exact ⟨fresh,by simp [direct,eq,e,show z.commitIndex < _ from gt]⟩
  · rcases from_ack c right with ⟨fresh,rfl,eq⟩ | ⟨z,co,rfl⟩
    · exact ⟨fresh,by simp [direct,eq,gt]⟩
    · obtain ⟨fresh,rfl,eq,e⟩ := (Promotion.primary_iff c).mp co
      exact ⟨fresh,by simp [direct,eq,e,show z.commitIndex < _ from gt]⟩

private theorem construct (fresh : ¬Now f c.actor c.post) (yes : direct c.actor c.pre c.event) :
    ∃ m, (LeftCall c m c.actor ∨ RightCall c m c.actor) ∧
      m.commitIndex < highestCommittableIndex m c.actor ∧ Direct.CommitFrontier m := by
  simp only [direct,Bool.or_eq_true,Option.any_eq_true,decide_eq_true_eq] at yes
  rcases yes with (app | ⟨m,co,gt⟩) | ⟨z,eq,e,gt⟩
  · cases ev : c.event with
    | receive => simp [appends,ev] at app
    | internal i =>
      cases i <;> simp only [ev,appends] at app <;> try contradiction
      have input := (Promotion.input_iff c (st := c.pre) (self := c.actor)).mpr ⟨fresh,rfl,rfl,ev⟩
      obtain ⟨_,_,_,co,i,ran,fr,run⟩ := input
      have ok : Direct.CommitFrontier sample := by unfold Direct.CommitFrontier; decide
      exact ⟨sample,.inl (.inl ⟨_,⟨_,_,_,_,co,i,ran,fr,run⟩,_,rfl,rfl,ok⟩),sample_high _,ok⟩
  · obtain ⟨path,fr⟩ := to_ack c fresh co
    exact ⟨m,.inr path,gt,fr⟩
  · obtain ⟨cast,fr⟩ := Promotion.cast_of c fresh eq
    have p := (Promotion.primary_iff c).mpr ⟨fresh,rfl,eq,e⟩
    have kept := Direct.CommitFrontier.promotedLog fr
    refine ⟨primaryState z,?_,gt,kept.of_log rfl rfl⟩
    rcases p with p | p
    · exact .inr (.inr ⟨z,p,fr,rfl⟩)
    · exact .inl (.inr ⟨z,p,fr,rfl⟩)

theorem direct_only {m n} (h : DirectSite c m n) : ¬Now f c.actor c.post ∧ direct c.actor c.pre c.event := by
  repeat' (change _ ∨ _ at h; rcases h with h | h)
  all_goals exact origin c (by first | exact .inl h.1 | exact .inr h.1) (Nat.lt_of_not_ge h.2.1)

local macro "pick_arm " call:term:arg ng:term:arg ret:term:arg role:term:arg fr:term:arg : tactic => `(tactic| {
  repeat' first | exact ⟨$call,$ng,$ret,$role,$fr⟩ | exact Or.inl ⟨$call,$ng,$ret,$role,$fr⟩
                | exact ⟨$call,$ng,$ret,$fr⟩ | exact Or.inl ⟨$call,$ng,$ret,$fr⟩ | apply Or.inr
  done })

theorem direct_of (fresh : ¬Now f c.actor c.post) (yes : direct c.actor c.pre c.event) :
    ∃ m n, DirectSite c m n ∧ m.commitIndex < highestCommittableIndex m n := by
  obtain ⟨m,call,gt,fr⟩ := construct c fresh yes
  refine ⟨m,c.actor,?_,gt⟩
  have ng := Nat.not_le_of_gt gt
  rcases call with call | call <;>
    by_cases ret : (m.recordCommit c.actor (highestCommittableIndex m c.actor)).isRetiredCommitted c.actor <;>
    by_cases role : m.role = .primary
  all_goals first | left; pick_arm call ng ret role fr | right; pick_arm call ng ret role fr
end

end ConsensusCoverage.HandReadersOther.Fold
