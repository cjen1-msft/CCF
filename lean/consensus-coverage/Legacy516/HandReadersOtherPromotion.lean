module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersAObserve
import all ConsensusCoverage.SelfQuorumCasesB
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersOther.Promotion

open CCF Consensus Model Model.Node Proofs Safety ActionProfile HandReadersA SolvedWitnesses

set_option maxRecDepth 8192
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private def ballot (st : NodeState) (n : NodeID) := {st with votesGranted := insert n st.votesGranted}
private def preBallot (st : NodeState) (n : NodeID) := {st with preVotesGranted := insert n st.preVotesGranted}
private abbrev obs (st : NodeState) (m : Message) := observeTerm st m

def candidate (self : NodeID) (pre : NodeState) : Event → Option NodeState
  | .receive n m@(.requestVoteResponse q) =>
    let z := obs pre m
    if n ∈ eligiblePeers pre self ∧ z.role = .candidate ∧ q.term = z.currentTerm ∧ q.voteGranted then
      some (ballot z n) else none
  | .receive n m@(.requestPreVoteResponse q) =>
    let z := obs pre m
    let next := preBallot z n
    if n ∈ eligiblePeers pre self ∧ z.role = .preVoteCandidate ∧ q.term = z.currentTerm ∧ q.voteGranted ∧
        hasQuorum next.activeConfigurations next.preVotesGranted then some (freshCandidate self next) else none
  | .receive _ m@(.proposeRequestVoteRequest k) =>
    let z := obs pre m
    if k = z.currentTerm ∧ canStartElection z self then some (freshCandidate self z) else none
  | .internal (.timeout .election) =>
    let z := SelfQuorumCasesB.pre self pre
    if hasQuorum z.activeConfigurations z.preVotesGranted then some (freshCandidate self z) else none
  | _ => none

def elects (self : NodeID) (z : NodeState) : Prop :=
  z.role = .candidate ∧ hasQuorum z.activeConfigurations z.votesGranted ∧ ¬z.isRetiredCommitted self

instance (self : NodeID) (z : NodeState) : Decidable (elects self z) := by unfold elects; infer_instance

def gated (p : NodeID → NodeState → Event → Bool) : Reader := fun cfg before act after past =>
  (GuardedDomain.ofAction cfg before after past act).any fun v =>
    v.changed && p v.actor v.pre (ReadersAtoms.eventOf act)

def reader (positive : Bool) : Reader := gated fun self pre ev =>
  (candidate self pre ev).any fun z => decide (elects self z) && (decide (0 < z.commitIndex) == positive)

theorem gated_iff (s : Step) (p : NodeID → NodeState → Event → Bool) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    gated p s.cfg s.before s.act s.after s.past = true ↔
      ¬Now s.frame s.context.actor s.context.post ∧ p s.context.actor s.context.pre s.context.event := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨v,made,ok⟩ := GuardedDomain.ofAction_matches s
  have ev : ReadersAtoms.eventOf s.act = s.context.event := by
    rw [← (s.context_eq s.context).mpr rfl]
    change ReadersAtoms.eventOf (ActionContext.encode s.context.tr.actor s.context.tr.event) = s.context.tr.event
    cases s.context.tr.event <;> rfl
  rw [gated,made,Option.any_some,Bool.and_eq_true,GuardedDomain.View.old_post ok,Bool.not_eq_false,
    ev,GuardedDomain.View.actor_eq ok,GuardedDomain.View.pre_eq ok]

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

abbrev InputSeed (self : NodeID) (st : NodeState) (i : Input) :=
  (reach% step_promotedLog_committed_pos[1,0,0,0,0,0]) f t c self st i

theorem input_iff {self st i} : InputSeed c self st i ↔
    ¬Now f c.actor c.post ∧ self = c.actor ∧ st = c.pre ∧ c.event = .internal i := by
  constructor
  · rintro ⟨_,_,_,⟨_,_,_,fresh,hs,hp,ev,_,_⟩,eq,_⟩; exact ⟨fresh,hs,hp,ev.symm.trans eq⟩
  · rintro ⟨fresh,rfl,rfl,ev⟩
    exact ⟨_,_,_,⟨c.post_now,c.post_now,c.post_now,fresh,rfl,rfl,rfl,rfl,rfl⟩,ev,ev ▸ c.tr.ran,
      c.inv.frontier _ _ c.pre_now,c.tr.ran⟩

abbrev Cast (self : NodeID) (st : NodeState) :=
  (reach% step_promotedLog_committed_pos[0,0,0]) f t c self st ∨
  (reach% step_promotedLog_committed_pos[1,0,0]) f t c self st

theorem cast_only {self st} (h : Cast c self st) :
    ¬Now f c.actor c.post ∧ self = c.actor ∧ candidate self c.pre c.event = some st := by
  rcases h with (h | h) | h
  · obtain ⟨_,n,_,call,_,q,rfl,pass,g,_,_,rfl⟩ := h
    obtain ⟨fresh,rfl,rfl,ev⟩ := (Observe.receive_iff c).mp call
    have peer := Classical.byContradiction (fun no => pass ⟨rfl,no⟩)
    exact ⟨fresh,rfl,by rw [ev,candidate,ite_eq_left ⟨peer,g⟩]; rfl⟩
  · obtain ⟨_,call,_,rfl⟩ := h
    rcases call with ⟨_,n,_,co,_,q,rfl,pass,g,quorum,_,_,rfl⟩ | ⟨_,n,m,co,_,msg,_,can,_,_,rfl⟩
    · obtain ⟨fresh,rfl,rfl,ev⟩ := (Observe.receive_iff c).mp co
      have peer := Classical.byContradiction (fun no => pass ⟨rfl,no⟩)
      refine ⟨fresh,rfl,?_⟩
      rw [ev,candidate,ite_eq_left ⟨peer,g.1,g.2.1,g.2.2,quorum⟩]; rfl
    · obtain ⟨fresh,rfl,rfl,ev⟩ := (Observe.receive_iff c).mp co
      generalize kEq : (observeTerm c.pre m).currentTerm = k at msg
      subst m
      refine ⟨fresh,rfl,?_⟩
      rw [ev,candidate,ite_eq_left ⟨kEq.symm,can⟩]
      unfold freshCandidate; rw [kEq]
  · obtain ⟨_,⟨_,⟨_,call,rfl,_,_⟩,q,_,rfl⟩,_,rfl⟩ := h
    obtain ⟨fresh,rfl,rfl,ev⟩ := (input_iff c).mp call
    have yes : hasQuorum (SelfQuorumCasesB.pre c.actor c.pre).activeConfigurations
        (SelfQuorumCasesB.pre c.actor c.pre).preVotesGranted := q
    exact ⟨fresh,rfl,by rw [ev,candidate,ite_eq_left yes]; rfl⟩

theorem cast_of {st} (fresh : ¬Now f c.actor c.post)
    (h : candidate c.actor c.pre c.event = some st) : Cast c c.actor st ∧ Direct.CommitFrontier st := by
  have fr := c.inv.frontier _ _ c.pre_now
  cases ev : c.event with
  | internal i =>
    cases i <;> simp only [ev,candidate] at h <;> try contradiction
    rename_i k; cases k <;> try contradiction
    change (if hasQuorum (SelfQuorumCasesB.pre c.actor c.pre).activeConfigurations
      (SelfQuorumCasesB.pre c.actor c.pre).preVotesGranted then
        some (freshCandidate c.actor (SelfQuorumCasesB.pre c.actor c.pre)) else none) = some st at h
    split at h <;> try contradiction
    rename_i q; cases h
    exact ⟨.inr ⟨_,⟨_,⟨_,(input_iff c).mpr ⟨fresh,rfl,rfl,ev⟩,rfl,rfl,fr⟩,q,fr,rfl⟩,fr,rfl⟩,fr⟩
  | receive n m =>
    have co := (Observe.receive_iff c (self := c.actor) (st := c.pre)).mpr ⟨fresh,rfl,rfl,ev⟩
    have seen : Direct.CommitFrontier (obs c.pre m) :=
      fr.of_log (Concrete.observeTerm_log ..) (Concrete.observeTerm_commitIndex ..)
    cases m <;> simp only [ev,candidate] at h <;> try contradiction
    all_goals split at h <;> try contradiction
    all_goals rename_i g; cases h; refine ⟨.inl ?_,seen⟩
    case requestVoteResponse.isTrue.refl =>
      exact .inl ⟨_,n,_,co,fun no => no.2 g.1,_,rfl,fun no => no.2 g.1,g.2,fr,seen,rfl⟩
    case requestPreVoteResponse.isTrue.refl =>
      exact .inr ⟨_,.inl ⟨_,n,_,co,fun no => no.2 g.1,_,rfl,fun no => no.2 g.1,
        ⟨g.2.1,g.2.2.1,g.2.2.2.1⟩,g.2.2.2.2,fr,seen,rfl⟩,seen,rfl⟩
    case proposeRequestVoteRequest.isTrue.refl =>
      exact .inr ⟨_,.inr ⟨_,n,_,co,fun h => Bool.noConfusion h.1,congrArg Message.proposeRequestVoteRequest g.1,
        fun h => Bool.noConfusion h.1,g.2,fr,seen,rfl⟩,seen,rfl⟩

abbrev Primary (self : NodeID) (st : NodeState) :=
  (reach% step_foldl_select_max_values_cons[5,0,0,0,1]) f t c self st ∨
  (reach% step_foldl_select_max_values_cons[4,0,0,0,1]) f t c self st

theorem primary_iff {self st} : Primary c self st ↔
    ¬Now f c.actor c.post ∧ self = c.actor ∧ candidate self c.pre c.event = some st ∧ elects self st := by
  constructor
  · rintro (⟨h,e,_⟩ | ⟨h,e,_⟩)
    all_goals
      obtain ⟨fresh,eq,yes⟩ := cast_only c (by first | exact .inl h | exact .inr h)
      exact ⟨fresh,eq,yes,e⟩
  · rintro ⟨fresh,rfl,h,e⟩
    obtain ⟨h | h,fr⟩ := cast_of c fresh h
    · exact .inl ⟨h,e,fr⟩
    · exact .inr ⟨h,e,fr⟩
end

def column (pos : Bool) : Classes.StepBranch :=
  if pos then .promotedLog_committed_pos else .promotedLog_committed_neg

def exactReader (pos : Bool) : Exact (column pos) where
  eval := reader pos
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    let c := s.context
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff,reader,gated_iff,Option.any_eq_true]
    constructor
    · intro h
      cases pos <;> rcases h with ⟨z,⟨⟨self,call,e,fr⟩,_⟩,cut,_⟩ | ⟨z,⟨⟨self,call,e,fr⟩,_⟩,cut,_⟩
      all_goals
        obtain ⟨fresh,rfl,eq⟩ := cast_only c (by first | exact .inl call | exact .inr call)
        exact ⟨fresh,z,eq,Bool.and_eq_true_iff.mpr ⟨decide_eq_true e,by simpa using cut⟩⟩
    · rintro ⟨fresh,z,eq,ok⟩
      obtain ⟨a,b⟩ := Bool.and_eq_true_iff.mp ok
      have e := of_decide_eq_true a
      obtain ⟨h | h,fr⟩ := cast_of c fresh eq
      all_goals cases pos <;> simp at b
      all_goals first
        | exact .inl ⟨z,⟨⟨_,h,e,fr⟩,fr⟩,b,fr⟩
        | exact .inr ⟨z,⟨⟨_,h,e,fr⟩,fr⟩,b,fr⟩
        | exact .inl ⟨z,⟨⟨_,h,e,fr⟩,fr⟩,by omega,fr⟩
        | exact .inr ⟨z,⟨⟨_,h,e,fr⟩,fr⟩,by omega,fr⟩

end ConsensusCoverage.HandReadersOther.Promotion
