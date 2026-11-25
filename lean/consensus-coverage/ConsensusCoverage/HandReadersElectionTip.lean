module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersElectionPairs
import all ConsensusCoverage.HandReadersElectionCarried
import all ConsensusCoverage.HandReadersAFacts
import all ConsensusCoverage.DeepCarriedCases
import all ConsensusCoverage.BackingArms
import all ConsensusCoverage.CommitKeys
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersElection.Tip

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety Ledger
open ActionProfile SolvedWitnesses HandReadersA
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192

def column (fresh : Bool) : Classes.StepBranch := if fresh then .tip_chain_fresh else .tip_chain_backed

def reader (fresh : Bool) : Reader := fun cfg before act after past =>
  (Carried.reader .backed cfg before act after past ||
    Pairs.reader (Pairs.test .large) cfg before act after past) &&
    Facts.any cfg (before :: past) fun l k b i =>
      (!fresh || b == 0) && (CommitKeys.keys (cfg.min?.getD 0) (before :: past)).contains (k,l.take i)

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

abbrev Gate := Carried.Evidence c .backed ∨ Pairs.Evidence c (Pairs.test .large)
abbrev Slice (fresh : Bool) := ∃ l k b i, CommitFacts f.logs l k b i ∧
  (fresh = false ∨ b = 0) ∧ Committed f k (l.take i)

include c in
theorem not_old_leader {n m k l d} (elect : ElectStep f t n k l d) (led : Led f m k) : False := by
  obtain rfl := c.new_old_unique elect led
  obtain ⟨rfl,_,_,phase,ht,_⟩ := c.electStep elect
  have old := c.old_led_actor (ht ▸ led)
  rcases phase with lt | ⟨_,role⟩
  · omega
  · exact old.2 role

private theorem fromElection {n later log d k p} (elect : ElectStep f t n later log d)
    (lt : k < later) (old : Committed f k p) : Gate c := by
  obtain ⟨rfl,rfl,rfl,_,rfl,_⟩ := c.electStep elect
  left
  refine ⟨elect,?_⟩
  cases c.inv.commitChains k p old with
  | fresh facts => exact ⟨_,_,_,_,facts,⟨lt,old⟩,rfl⟩
  | backed facts _ _ _ _ => exact ⟨_,_,_,_,facts,⟨lt,old⟩,rfl⟩

local macro "along " h:term : tactic => `(tactic| {
  have spine := $h
  repeat' first | exact spine | exact spine.1
                | change _ ∧ _ at spine; obtain ⟨_,spine⟩ := spine
                | change Exists _ at spine; obtain ⟨_,spine⟩ := spine })

local macro "classify " c:ident src:term : tactic => `(tactic| {
  have h := $src
  repeat' (change _ ∨ _ at h; rcases h with h | h)
  all_goals first
    | obtain ⟨leader,st,k,b,i,site,later,_,n,log,d,win,lt,bd,rest⟩ := h
      have ticket := (Pairs.ticket_iff $c).mp site
      exact .inr ⟨_,_,_,_,_,_,.inr ⟨leader,st,n,later,ticket,rfl,win,lt⟩,decide_eq_true bd⟩
    | obtain ⟨k,later,d,n,p,log,_,elect,_,lt,old⟩ := h
      exact fromElection $c elect lt old
    | obtain ⟨n,m,k,d,log,_,rest⟩ := h
      apply False.elim
      apply not_old_leader $c (n := n) (m := m) (k := k) (l := log) (d := d) <;> along rest })

local macro "fromRoot " c:ident src:term : tactic => `(tactic| {
  have h := $src
  rcases h with ⟨call,old⟩ | ⟨call,chain⟩
  · exact ⟨by classify $c call,old⟩
  · repeat' (change _ ∨ _ at call; rcases call with call | call)
    all_goals first
      | obtain ⟨call,old⟩ := call
        exact ⟨by classify $c call,old⟩
      | obtain ⟨leader,st,k,b,i,site,later,_,n,log,d,win,lt,bd,_,_,pack,_⟩ := call
        exact ⟨.inr ⟨_,_,_,_,_,_,.inr ⟨leader,st,n,later,(Pairs.ticket_iff $c).mp site,rfl,win,lt⟩,
          decide_eq_true bd⟩,pack.1⟩ })

set_option maxHeartbeats 2000000 in
private theorem necessary (fresh : Bool) (h : sig c (column fresh)) :
    Gate c ∧ Slice (f := f) fresh := by
  cases fresh
  all_goals repeat' (change _ ∨ _ at h; rcases h with h | h)
  all_goals
    obtain ⟨k,p,root,rest⟩ := h
    have ⟨gate,old⟩ : Gate c ∧ Committed f k p := by fromRoot c root
    first
    | obtain ⟨l,i,facts,_,rfl,_⟩ := rest
      exact ⟨gate,l,k,0,i,facts,.inr rfl,old⟩
    | obtain ⟨l,b,i,_,_,facts,tail⟩ := rest
      obtain rfl : p = l.take i := by along tail
      exact ⟨gate,l,k,b,i,facts,.inl rfl,old⟩

private theorem call (gate : Gate c) : (reach% step_tip_chain_fresh[0,0]) f t c := by
  have fromOld {k p} (elect : Carried.ElectedHere c) (old : Committed f k p) (lt : k < c.post.currentTerm) :
      (reach% step_tip_chain_fresh[0,0]) f t c := by
    have r := (DeepCarriedCases.source c old lt elect).1
    exact .inr (.inr ⟨_,_,_,_,_,_,r.1,elect,r.2.2.2.1,lt,old⟩)
  rcases gate with ⟨elect,_,_,_,_,_,⟨lt,old⟩,_⟩ | ⟨l,k,b,i,log,d,pair,bd⟩
  · exact fromOld elect old lt
  · rcases pair with ⟨elect,_,_,_,old,lt⟩ | ⟨n,st,node,later,ticket,rfl,win,lt⟩
    · exact fromOld elect old lt
    · have bd : b < d := of_decide_eq_true bd
      obtain ⟨step,back,_⟩ := id ticket
      have facts := BackingArms.commitFacts c step
      have key : Committed (f.advance t) k (st.log.take i) := .inr ⟨_,_,_,_,step,rfl,back⟩
      have sub := c.completeness _ _ _ _ _ _ key win lt
      obtain zero | ⟨e,p,old,earlier,part⟩ := (c.previousBacking win).backing
      · omega
      have pack := And.intro old (And.intro earlier part)
      exact .inl ⟨n,st,k,b,i,(Pairs.ticket_iff c).mpr ticket,later,
        (fun m _ node log d w lt => c.completeness _ _ node m log d key w lt),node,log,d,win,lt,bd,
        ⟨e,p,pack⟩,e,⟨p,pack⟩,p,pack,old,pack.2,earlier,part,win,c.rankedElections _ _ _ _ win,
        (fun e a above _ canon => c.inv_step.later _ e _ a key canon above),
        (fun _ => (take_prefix_take st.log facts.baseLe).trans sub),step,back,facts.floor,facts,
        take_signature facts.signature⟩

private theorem sufficient (fresh : Bool) (h : Gate c ∧ Slice (f := f) fresh) : sig c (column fresh) := by
  obtain ⟨gate,l,k,b,i,facts,side,old⟩ := h
  have root : (reach% step_tip_chain_fresh[0]) f t c k (l.take i) := .inl ⟨call c gate,old⟩
  have chain := c.inv.commitChains _ _ old
  cases fresh
  · left
    exact ⟨_,_,root,l,b,i,k,l.take i,facts,old,chain,Nat.le_refl _,take_prefix_take l facts.baseLe,
      facts,Nat.le_refl _,rfl,chain,proof_irrel_heq _ _,chain⟩
  · obtain rfl := side.resolve_left (by decide)
    left
    exact ⟨_,_,root,l,i,facts,facts,rfl,chain,proof_irrel_heq _ _,chain⟩
end

def exactReader (fresh : Bool) : Exact (column fresh) where
  eval := reader fresh
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    have carried := Bool.eq_iff_iff.mp ((Carried.exactReader .backed).eq_label s)
    rw [label_true,holds,sig_iff] at carried
    change sig s.context (Carried.column .backed) ↔ Carried.reader .backed s.cfg s.before s.act s.after s.past = true at carried
    have ce := carried.symm.trans (Iff.intro (Carried.necessary s.context .backed) (Carried.sufficient s.context .backed))
    apply Bool.eq_iff_iff.mpr
    simp only [label_true,holds,sig_iff,reader,Bool.and_eq_true,Bool.or_eq_true,ce,Pairs.reader_iff,
      Facts.any_iff,Bool.not_eq_true',beq_iff_eq,List.contains_iff_mem,CommitKeys.step_mem]
    exact ⟨necessary s.context fresh,sufficient s.context fresh⟩

end ConsensusCoverage.HandReadersElection.Tip
