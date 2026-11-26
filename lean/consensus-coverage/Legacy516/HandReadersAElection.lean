module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersABase
import all ConsensusCoverage.DeepElectionCases
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersA.Election

open CCF.MultiNodeTransitionSystem Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open ActionProfile SolvedWitnesses ReadersAtoms
set_option maxRecDepth 8192
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

def reader : Reader := fun cfg before act after past =>
  actorRead (fun n pre _ post =>
    electionExact after before past n post.currentTerm pre.log pre.commitIndex) cfg before act after past

def termReader (fresh : Bool) : Reader := fun cfg before act after past =>
  actorRead (fun n pre _ post =>
    (decide (pre.currentTerm < post.currentTerm) == fresh) &&
      electionExact after before past n post.currentTerm pre.log pre.commitIndex) cfg before act after past

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)

private theorem iff_election : step_led_after_elected_after_inr f t c ↔
    ElectStep f t c.actor c.post.currentTerm c.pre.log c.pre.commitIndex := by
  constructor
  · rintro (h | h | h | h | h | h | h | h | h | h | h)
    all_goals
      obtain ⟨n,k,_,_,log,_,i,_,e,_⟩ := h
      obtain ⟨rfl,hl,hi,_,hk,_⟩ := c.electStep e
      simpa only [hl,hi,hk] using e
  · intro e
    have new : ¬ Now f c.actor c.post := by
      intro old
      have eq := c.now_pre old
      obtain ⟨_,_,_,lt | ⟨_,cand⟩,_,role,_⟩ := c.electStep e
      · rw [eq] at lt; exact (Nat.lt_irrefl _ lt)
      · rw [eq,cand] at role
        cases role <;> contradiction
    have led : Led (f.advance t) c.actor c.post.currentTerm :=
      .inr ⟨_,_,.inr ⟨f.current,rfl,e⟩⟩
    have now := c.post_now
    have origin : (reach% step_led_cur_led_after_inr[0]) f t c c c.actor c.post c.post.currentTerm :=
      ⟨now,led,fun p => new p.1,rfl⟩
    exact DeepElectionCases.electedNew c ⟨_,origin,now,led,now,⟨_,_,e⟩,_,⟨_,e⟩,_,e,now,led⟩
end

def exactReader : Exact .led_after_elected_after_inr where
  eval := reader
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    obtain ⟨x,made,ok⟩ := ofXAction_matches s
    have history : x.base.past = s.past := by
      unfold ofXAction GuardedDomain.ofAction at made
      cases hp : nodeState s.before (GuardedDomain.actionActor s.act) <;>
        cases hq : nodeState s.after (GuardedDomain.actionActor s.act) <;> simp [hp,hq] at made
      rw [← made]
      rfl
    have bef := (GuardedDomain.View.before_eq ok.1).symm.trans s.current_eq
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff]
    change step_led_after_elected_after_inr _ _ _ ↔ _
    rw [iff_election,reader,actorRead_at,X.elect_now ok]
    simp only [GuardedDomain.View.actor_eq ok.1,GuardedDomain.View.pre_eq ok.1,
      GuardedDomain.View.post_eq ok.1,← GuardedDomain.View.after_eq ok.1,bef,history,true_and]

def termColumn (fresh : Bool) : Classes.StepBranch :=
  if fresh then .elect_backed_termCase_inl else .elect_backed_termCase_inr

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)

private abbrev Election := ElectStep f t c.actor c.post.currentTerm c.pre.log c.pre.commitIndex

private theorem new_site (e : Election c) :
    (reach% step_elect_backed_termCase_inl[4]) f t c c c.actor c.post.currentTerm c.pre.log c.pre.commitIndex := by
  have elected : Elected (f.advance t) c.actor c.post.currentTerm c.pre.log c.pre.commitIndex :=
    .inr ⟨f.current,rfl,e⟩
  have fresh : ¬Elected f c.actor c.post.currentTerm c.pre.log c.pre.commitIndex := by
    intro old
    have before := c.inv.led_cur _ _ _ c.pre_now (.inr ⟨_,_,old⟩)
    have phase := (c.electStep e).2.2.2.1
    grind
  have root : (reach% step_elect_backed_termCase_inl[4,0]) f t c c c.actor c.post.currentTerm c.pre.commitIndex c.pre.log :=
    ⟨⟨⟨elected,fresh,rfl⟩,elected,rfl⟩,e,elected,rfl⟩
  obtain ⟨pre,post,facts⟩ := e
  have ⟨prev,now,log,commit,limit,phase,term,role,pref,floor,vs,quorum,support⟩ := facts
  refine ⟨_,_,_,root,pre,⟨post,facts⟩,post,facts,?_⟩
  repeat' first | assumption | rfl | apply And.intro | exact ⟨vs,quorum,support⟩
                | refine ⟨vs,⟨quorum,support⟩,quorum,support,?_⟩ | exact ⟨pre,post,facts⟩

private theorem phase_iff (fresh : Bool) : sig c (termColumn fresh) ↔
    decide (c.pre.currentTerm < c.post.currentTerm) = fresh ∧ Election c := by
  constructor
  · intro h
    cases fresh
    all_goals
      rcases h with h | h | h | h | h | h | h | h | h | h | h | h | h
      all_goals
        obtain ⟨_,_,_,_,_,e,cut,_⟩ := h
        refine ⟨?_,e⟩
        first | exact decide_eq_true cut | exact decide_eq_false (Nat.not_lt_of_ge (Nat.le_of_eq cut.1.symm))
  · rintro ⟨guard,e⟩
    have origin := new_site c e
    have ⟨_,_,_,terms,_,role,pr,floor⟩ := c.electStep e
    cases fresh
    all_goals
      iterate 4 right
      left
      first
      | exact ⟨origin,terms,role,pr,floor,e,of_decide_eq_true guard,e⟩
      | have old := terms.resolve_left (of_decide_eq_false guard)
        exact ⟨origin,terms,role,pr,floor,e,old,old.1,old.2,e⟩
end

def termExact (fresh : Bool) : Exact (termColumn fresh) where
  eval := termReader fresh
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    have elected := Bool.eq_iff_iff.mp (exactReader.eq_label s)
    rw [label_true,holds,sig_iff] at elected
    change step_led_after_elected_after_inr s.frame s.after s.context ↔
      reader s.cfg s.before s.act s.after s.past = true at elected
    rw [iff_election,reader,actorRead_at] at elected
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff,phase_iff,termReader,actorRead_at,Bool.and_eq_true,beq_iff_eq]
    exact and_congr_right fun _ => elected

end ConsensusCoverage.HandReadersA.Election
