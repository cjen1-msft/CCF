module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersABase
import all ConsensusCoverage.BackingArms
import all ConsensusCoverage.CommitKeys
import all ConsensusCoverage.StateCoverage
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersA.CommitTerm

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety ActionProfile SolvedWitnesses CommitKeys
set_option maxRecDepth 8192
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

def reader (boot : Bool) : Reader := fun cfg before _ after past =>
  let history := before :: past
  let bootstrap := cfg.min?.getD 0
  let old := keys bootstrap history
  (here bootstrap after history (backed old)).any fun key => (key.1 == BOOTSTRAP_TERM) == boot && decide (key ∉ old)

def column (boot : Bool) : Classes.StepBranch := if boot then .commitChains_step_led_inl else .commitChains_step_led_inr

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State}

private def New (f : Frame) (t : Model.State) (boot : Bool) :=
  ∃ k p, (Committed (f.advance t) k p ∧ ¬Committed f k p) ∧ (k == BOOTSTRAP_TERM) = boot

private theorem iff_new (c : Ctx f t) (boot : Bool) : sig c (column boot) ↔ New f t boot := by
  constructor
  · intro h
    cases boot
    · rcases h with h | h
      all_goals
        obtain ⟨k,p,fresh,spine⟩ := h
        refine ⟨k,p,fresh,?_⟩
        have floor : 3 ≤ k := by
          repeat' first | exact (c.electionCerts _ _ _ _ spine.1).above | obtain ⟨_,spine⟩ := spine
        have : k ≠ BOOTSTRAP_TERM := by unfold BOOTSTRAP_TERM; omega
        exact beq_eq_false_iff_ne.mpr this
    · rcases h with h | h
      all_goals
        obtain ⟨k,p,fresh,spine⟩ := h
        refine ⟨k,p,fresh,beq_iff_eq.mpr ?_⟩
        repeat' first | exact spine.1 | obtain ⟨_,spine⟩ := spine
  · rintro ⟨k,p,⟨post,newKey⟩,side⟩
    obtain old | ⟨n,st,b,i,step,rfl,back⟩ := post
    · exact (newKey old).elim
    have post : Committed (f.advance t) k (st.log.take i) := .inr ⟨n,st,b,i,step,rfl,back⟩
    have branch := And.intro step (And.intro (Eq.refl (st.log.take i)) back)
    have facts := BackingArms.commitFacts c step
    have ⟨now,le,bound,signature,term,acks⟩ := step
    rcases now.2.2.2 with ⟨bootTerm,bootNode⟩ | ⟨electLog,electIndex,elect⟩
    · subst bootNode
      subst bootTerm
      change true = boot at side
      subst boot
      let k := BOOTSTRAP_TERM
      let n := Config.INITIAL_PRIMARY
      rcases back with rfl | ⟨e,q,old,earlier,within⟩
      · have support : True ∨ ∃ e q, Committed f e q ∧ e ≤ k ∧ st.log.take 0 <+: q := .inl trivial
        have zero := And.intro step (And.intro (Eq.refl (st.log.take i)) support)
        exact Or.inl ⟨k,st.log.take i,⟨post,newKey⟩,⟨n,st,0,i,branch⟩,⟨st,0,i,branch⟩,
          st,⟨0,i,branch⟩,⟨i,zero⟩,i,zero,step,zero.2,rfl,support,now,step.2,le,step.2.2,
          bound,step.2.2.2,signature,step.2.2.2.2,term,acks,le,acks,facts,rfl,rfl,post⟩
      · have prior := And.intro old (And.intro earlier within)
        have existsPrior : ∃ e q, Committed f e q ∧ e ≤ k ∧ st.log.take b <+: q := ⟨e,q,prior⟩
        exact Or.inr ⟨k,st.log.take i,⟨post,newKey⟩,⟨n,st,b,i,branch⟩,⟨st,b,i,branch⟩,
          st,⟨b,i,branch⟩,b,⟨i,branch⟩,i,branch,step,branch.2,rfl,branch.2.2,now,step.2,le,
          step.2.2,bound,step.2.2.2,signature,step.2.2.2.2,term,acks,existsPrior,e,⟨q,prior⟩,
          q,prior,old,prior.2,earlier,within,rfl,rfl,post⟩
    · have floor := (c.electionCerts _ _ _ _ elect).above
      have diff : k ≠ BOOTSTRAP_TERM := by unfold BOOTSTRAP_TERM; omega
      rw [beq_eq_false_iff_ne.mpr diff] at side
      subst boot
      have elected : ∃ l j, (f.advance t).logs.elected n k l j := ⟨_,_,elect⟩
      rcases back with rfl | ⟨e,q,old,earlier,within⟩
      · have support : True ∨ ∃ e q, Committed f e q ∧ e ≤ k ∧ st.log.take 0 <+: q := .inl trivial
        have zero := And.intro step (And.intro (Eq.refl (st.log.take i)) support)
        exact Or.inl ⟨k,st.log.take i,⟨post,newKey⟩,⟨n,st,0,i,branch⟩,n,⟨st,0,i,branch⟩,
          st,⟨0,i,branch⟩,⟨i,zero⟩,i,zero,step,zero.2,rfl,support,now,step.2,le,step.2.2,
          bound,step.2.2.2,signature,step.2.2.2.2,term,acks,le,acks,facts,
          elected,electLog,⟨electIndex,elect⟩,electIndex,elect,post⟩
      · have prior := And.intro old (And.intro earlier within)
        have existsPrior : ∃ e q, Committed f e q ∧ e ≤ k ∧ st.log.take b <+: q := ⟨e,q,prior⟩
        exact Or.inr ⟨k,st.log.take i,⟨post,newKey⟩,⟨n,st,b,i,branch⟩,n,⟨st,b,i,branch⟩,
          st,⟨b,i,branch⟩,b,⟨i,branch⟩,i,branch,step,branch.2,rfl,branch.2.2,now,step.2,le,
          step.2.2,bound,step.2.2.2,signature,step.2.2.2.2,term,acks,existsPrior,e,⟨q,prior⟩,
          q,prior,old,prior.2,earlier,within,elected,electLog,⟨electIndex,elect⟩,electIndex,elect,post⟩
end

private theorem read_at (s : Step) (boot : Bool) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    reader boot s.cfg s.before s.act s.after s.past = true ↔ New s.frame s.after boot := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let hist := s.before :: s.past
  have after (k p) : Committed (s.frame.advance s.after) k p ↔ (k,p) ∈ keys (s.cfg.min?.getD 0) (s.after :: hist) := by
    change (StateCoverage.frame s.after hist).logs.committed k p ↔ _
    rw [StateCoverage.frame_logs]
    exact (mem_iff s.cfg (s.after :: hist) k p).symm
  have before (k p) : Committed s.frame k p ↔ (k,p) ∈ keys (s.cfg.min?.getD 0) hist := (step_mem s k p).symm
  simp only [New,after,before,reader,List.any_eq_true,Bool.and_eq_true,beq_iff_eq,decide_eq_true_eq,
    Prod.exists,hist,keys,List.mem_eraseDups,List.mem_append]
  constructor
  · rintro ⟨k,p,mem,side,fresh⟩
    exact ⟨k,p,⟨.inl mem,fresh⟩,side⟩
  · rintro ⟨k,p,⟨mem,fresh⟩,side⟩
    exact ⟨k,p,mem.resolve_right fresh,side,fresh⟩

def exactReader (boot : Bool) : Exact (column boot) where
  eval := reader boot
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff,iff_new]
    exact (read_at s boot).symm

end ConsensusCoverage.HandReadersA.CommitTerm
