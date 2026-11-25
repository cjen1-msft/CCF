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

end ConsensusCoverage.HandReadersA.Election
