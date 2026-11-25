module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersAFacts
import all ConsensusCoverage.HandReadersAElection
import all ConsensusCoverage.DeepCarriedCases
import all ConsensusCoverage.CommitKeys
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersElection.Carried

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open ActionProfile SolvedWitnesses HandReadersA

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192

inductive Kind where | fresh | backed | contained | agree

def column : Kind → Classes.StepBranch
  | .fresh => .carried_of_chain_certificate_fresh
  | .backed => .carried_of_chain_certificate_backed
  | .contained => .carried_of_chain_agreement_inl
  | .agree => .carried_of_chain_agreement_inr

def cut (kind : Kind) (log : List Entry) (commit : Nat) (l : List Entry) (b : Nat) : Bool :=
  match kind with
  | .fresh => b == 0
  | .backed | .contained => true
  | .agree => l.take (max b commit) == log.take (max b commit)

def reader (kind : Kind) : Reader := fun cfg before act after past =>
  Election.reader cfg before act after past &&
    actorRead (fun _ pre _ post =>
      let hist := before :: past
      let keys := CommitKeys.keys (cfg.min?.getD 0) hist
      Facts.any cfg hist fun l k b i =>
        decide (k < post.currentTerm ∧ (k,l.take i) ∈ keys) && cut kind pre.log pre.commitIndex l b)
      cfg before act after past

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

abbrev ElectedHere := ElectStep f t c.actor c.post.currentTerm c.pre.log c.pre.commitIndex

abbrev Evidence (kind : Kind) := ElectedHere c ∧ ∃ l k b i, CommitFacts f.logs l k b i ∧
  (k < c.post.currentTerm ∧ f.logs.committed k (l.take i)) ∧
  cut kind c.pre.log c.pre.commitIndex l b = true

omit [Config.InitialConfiguration] in
private theorem shorten {l log : List Entry} {b commit k : Nat}
    (h : l.take k = log.take k) (hb : b ≤ k) (hc : commit ≤ k) :
    cut .agree log commit l b = true := by
  apply beq_iff_eq.mpr
  simpa only [List.take_take, Nat.min_eq_left (Nat.max_le.mpr ⟨hb,hc⟩)] using
    congrArg (List.take (max b commit)) h

set_option maxHeartbeats 2000000 in
private theorem necessary (kind : Kind) (h : sig c (column kind)) : Evidence c kind := by
  cases kind
  all_goals
    repeat' (change _ ∨ _ at h; rcases h with h | h)
  all_goals
    obtain ⟨n,later,log,commit,_,_,site,rest⟩ := h
    have elect : ElectStep f t n later log commit := site.2.2.1
    obtain ⟨rfl,rfl,rfl,_,rfl,_⟩ := c.electStep elect
    refine ⟨elect,?_⟩
    first
    | obtain ⟨l,k,i,facts,old,lt,tail⟩ := rest
      refine ⟨l,k,0,i,facts,⟨lt,old⟩,?_⟩
      first | rfl | obtain ⟨j,eq,hb,hc⟩ := tail.1; exact shorten eq hb hc
    | obtain ⟨l,k,b,i,_,_,facts,_,_,_,_,_,old,lt,tail⟩ := rest
      refine ⟨l,k,b,i,facts,⟨lt,old⟩,?_⟩
      first | rfl | obtain ⟨j,eq,hb,hc⟩ := tail.1; exact shorten eq hb hc

private theorem sufficient (kind : Kind) (h : Evidence c kind) : sig c (column kind) := by
  obtain ⟨elect,l,k,b,i,facts,⟨lt,old⟩,guard⟩ := h
  have root := DeepCarriedCases.source c old lt elect
  have camp := root.2.2.2.2
  have chain := c.inv.commitChains _ _ old
  have back : c.pre.commitIndex = 0 ∨ ∃ e p, f.logs.committed e p ∧ c.pre.log.take c.pre.commitIndex <+: p :=
    (c.elect_backed elect).imp_right fun ⟨e,p,m,_,sub⟩ => ⟨e,p,m,sub⟩
  have sub := c.old_in_new elect old lt
  have high (_ : b < c.pre.commitIndex) : ∃ q, c.pre.log.take c.pre.commitIndex <+: q ∧
      (l.take i <+: q ∨ q <+: l.take i) :=
    ⟨_,List.take_prefix _ _,.inl sub⟩
  have carry {l' : List Entry} {t' b' i' : Nat} (_ : CommitFacts f.logs l' t' b' i')
      (m : f.logs.committed t' (l'.take i')) (earlier : t' < c.post.currentTerm)
      (_ : c.pre.commitIndex ≤ b' → l'.take b' <+: c.pre.log) := c.old_in_new elect m earlier
  have prior := fun (m : f.logs.committed k (l.take i)) (le : k < c.post.currentTerm) =>
    c.old_in_new elect m le
  have within := take_prefix_take l facts.baseLe
  cases kind
  case fresh =>
    obtain rfl : b = 0 := beq_iff_eq.mp guard
    iterate 8 right
    exact ⟨_,_,_,_,_,_,root,l,k,i,facts,old,lt,camp,lt,@carry,back,chain,old⟩
  case backed =>
    iterate 8 right
    exact ⟨_,_,_,_,_,_,root,l,k,b,i,k,l.take i,facts,old,chain,Nat.le_refl _,within,prior,
      old,lt,camp,back,lt,@carry,chain,old⟩
  case contained =>
    iterate 17 right
    exact ⟨_,_,_,_,_,_,root,l,k,b,i,k,l.take i,facts,old,chain,Nat.le_refl _,within,prior,
      old,lt,sub,camp,back,lt,high,chain,old⟩
  case agree =>
    let j := max b c.pre.commitIndex
    have eq : l.take j = c.pre.log.take j := beq_iff_eq.mp guard
    have wit := And.intro eq (And.intro (Nat.le_max_left b c.pre.commitIndex) (Nat.le_max_right b c.pre.commitIndex))
    iterate 17 right
    exact ⟨_,_,_,_,_,_,root,l,k,b,i,k,l.take i,facts,old,chain,Nat.le_refl _,within,prior,
      old,lt,⟨j,wit⟩,j,wit,eq,wit.2,wit.2.1,wit.2.2,camp,back,lt,high,chain,old⟩
end

def exactReader (kind : Kind) : Exact (column kind) where
  eval := reader kind
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    have election := Bool.eq_iff_iff.mp (Election.exactReader.eq_label s)
    rw [label_true,holds,sig_iff] at election
    change step_led_after_elected_after_inr _ _ s.context ↔
      Election.reader s.cfg s.before s.act s.after s.past = true at election
    rw [Election.iff_election] at election
    apply Bool.eq_iff_iff.mpr
    simp only [label_true,holds,sig_iff,reader,Bool.and_eq_true,← election,actorRead_at,Facts.any_iff,
      decide_eq_true_eq,CommitKeys.step_mem]
    exact ⟨necessary s.context kind,sufficient s.context kind⟩

end ConsensusCoverage.HandReadersElection.Carried
