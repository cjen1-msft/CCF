module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersElectionPairs
import all ConsensusCoverage.HandReadersElectionCarried
import all ConsensusCoverage.DeepCarriedCases
import all ConsensusCoverage.BackingArms
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersElection.Agreement

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety Ledger
open ActionProfile SolvedWitnesses HandReadersA
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192

def column (small : Bool) : Classes.StepBranch := if small then .agree_or_contained_lt_or_ge_inl
  else .agree_or_contained_lt_or_ge_inr
def test (small : Bool) := Pairs.test (if small then .small else .large)

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private abbrev Site (l : List Entry) (b i : Nat) (log : List Entry) (d : Nat) :=
  (reach% step_agree_or_contained_lt_or_ge_inl[0]) f t c l log b i d ∨
  (reach% step_agree_or_contained_lt_or_ge_inl[1]) f t c l log b i d ∨
  (reach% step_agree_or_contained_lt_or_ge_inl[2]) f t c l log b i d ∨
  (reach% step_agree_or_contained_lt_or_ge_inl[3]) f t c l log b i d ∨
  (reach% step_agree_or_contained_lt_or_ge_inl[4]) f t c l log b i d ∨
  (reach% step_agree_or_contained_lt_or_ge_inl[5]) f t c l log b i d ∨
  (reach% step_agree_or_contained_lt_or_ge_inl[6]) f t c l log b i d ∨
  (reach% step_agree_or_contained_lt_or_ge_inl[7]) f t c l log b i d ∨
  (reach% step_agree_or_contained_lt_or_ge_inl[8]) f t c l log b i d

local macro "along " h:term : tactic => `(tactic| {
  have spine := $h
  repeat' first | exact spine | exact spine.1
                | change _ ∧ _ at spine; obtain ⟨_,spine⟩ := spine
                | change Exists _ at spine; obtain ⟨_,spine⟩ := spine })

theorem pair_of_site {l b i log d} (site : Site c l b i log d) :
    ∃ k, Pairs.Pair c l k b i log d := by
  rcases site with h | h | h | h | h | h | h | h | h
  all_goals repeat' (change _ ∨ _ at h; rcases h with h | h)
  all_goals
    first
    | obtain ⟨leader,st,k,src,later,_,node,win,lt,rest⟩ := h
      exact ⟨k,.inr ⟨leader,st,node,later,(Pairs.ticket_iff c).mp src,by along rest,win,lt⟩⟩
    | obtain ⟨n,later,_,_,src,rest⟩ := h
      have elect : ElectStep f t n later log d := src.2.2.1
      obtain ⟨rfl,rfl,rfl,_,rfl,_⟩ := c.electStep elect
      first
      | obtain ⟨k,facts,old,lt,tail⟩ := rest
        obtain rfl : b = 0 := by along tail
        exact ⟨k,.inl ⟨elect,rfl,rfl,facts,old,lt⟩⟩
      | obtain ⟨k,_,_,facts,_,_,_,_,_,old,lt,_⟩ := rest
        exact ⟨k,.inl ⟨elect,rfl,rfl,facts,old,lt⟩⟩

set_option maxHeartbeats 1200000 in
private theorem necessary (small : Bool) (h : sig c (column small)) : Pairs.Evidence c (test small) := by
  cases small
  all_goals repeat' (change _ ∨ _ at h; rcases h with h | h)
  all_goals
    obtain ⟨l,log,b,i,d,site,first,rest⟩ := h
    obtain ⟨k,pair⟩ := pair_of_site c (l := l) (log := log) (b := b) (i := i) (d := d) (by
      repeat' first | exact site | exact Or.inl site | apply Or.inr)
    refine ⟨l,k,b,i,log,d,pair,?_⟩
    first | exact decide_eq_true first
          | exact decide_eq_true (Nat.le_trans first rest.1)
          | apply decide_eq_true; along rest

private abbrev Common (l : List Entry) (b i : Nat) (log : List Entry) (d : Nat) :=
  b ≤ i ∧ i ≤ l.length ∧ d ≤ log.length ∧ l.take i <+: log

theorem site_of_pair {l k b i log d} (pair : Pairs.Pair c l k b i log d) :
    ((reach% step_agree_or_contained_lt_or_ge_inl[0]) f t c l log b i d ∨
      (reach% step_agree_or_contained_lt_or_ge_inl[8]) f t c l log b i d) ∧ Common l b i log d := by
  rcases pair with ⟨elect,rfl,rfl,facts,old,lt⟩ | ⟨n,st,node,later,ticket,rfl,win,lt⟩
  · have root := DeepCarriedCases.source c old lt elect
    have camp := root.2.2.2.2
    have back : c.pre.commitIndex = 0 ∨ ∃ e q, f.logs.committed e q ∧ c.pre.log.take c.pre.commitIndex <+: q :=
      (c.elect_backed elect).imp_right fun ⟨e,q,m,_,pref⟩ => ⟨e,q,m,pref⟩
    have sub := c.old_in_new elect old lt
    have high (_ : b < c.pre.commitIndex) : ∃ q, c.pre.log.take c.pre.commitIndex <+: q ∧
        (l.take i <+: q ∨ q <+: l.take i) := ⟨_,List.take_prefix _ _,.inl sub⟩
    have chain := c.inv.commitChains _ _ old
    exact ⟨.inr (.inr ⟨_,_,_,_,root,k,k,l.take i,facts,old,chain,Nat.le_refl _,
      take_prefix_take l facts.baseLe,(fun m h => c.old_in_new elect m h),old,lt,camp,back,lt,high,
      chain,old⟩),facts.baseLe,facts.indexLe,camp.frontier,sub⟩
  · obtain ⟨step,back,_⟩ := (id ticket)
    have root := (Pairs.ticket_iff c).mpr ticket
    have key : Committed (f.advance t) k (st.log.take i) := .inr ⟨_,_,_,_,step,rfl,back⟩
    have facts := BackingArms.commitFacts c step
    have camp := c.rankedElections _ _ _ _ win
    have sub := c.completeness _ _ _ _ _ _ key win lt
    have low (_ : d ≤ b) := (take_prefix_take st.log facts.baseLe).trans sub
    have high (_ : b < d) : ∃ q, log.take d <+: q ∧ (st.log.take i <+: q ∨ q <+: st.log.take i) :=
      ⟨_,List.take_prefix _ _,.inl sub⟩
    exact ⟨.inl (.inl ⟨n,st,k,root,later,(fun m _ n l d w lt => c.completeness _ _ n m l d key w lt),
      node,win,lt,step,back,facts,take_signature facts.signature,win,camp,
      (fun e a above _ canon => c.inv_step.later _ e _ a key canon above),low,high,facts.floor,rfl⟩),
      facts.baseLe,facts.indexLe,camp.frontier,sub⟩

private theorem sufficient (small : Bool) (h : Pairs.Evidence c (test small)) : sig c (column small) := by
  obtain ⟨l,k,b,i,log,d,pair,guard⟩ := h
  obtain ⟨sites,bi,il,dl,sub⟩ := site_of_pair c pair
  have low (_ : d ≤ b) := (take_prefix_take l bi).trans sub
  have high (_ : b < d) : ∃ q, log.take d <+: q ∧ (l.take i <+: q ∨ q <+: l.take i) :=
    ⟨_,List.take_prefix _ _,.inl sub⟩
  cases small
  case false =>
    have bd : b < d := of_decide_eq_true guard
    rcases sites with site | site
    · left; exact ⟨_,_,_,_,_,site,bd,bi,dl,low,high,il⟩
    · iterate 8 right
      left; exact ⟨_,_,_,_,_,site,bd,bi,dl,low,high,il⟩
  case true =>
    have di : d ≤ i := of_decide_eq_true guard
    by_cases db : d ≤ b
    · rcases sites with site | site
      · left; exact ⟨_,_,_,_,_,site,db,bi,dl,low,high,il⟩
      · iterate 8 right
        left; exact ⟨_,_,_,_,_,site,db,bi,dl,low,high,il⟩
    · have bd := Nat.lt_of_not_ge db
      have pack := And.intro (List.take_prefix d log) (Or.inl (b := log <+: l.take i) sub)
      rcases sites with site | site
      · iterate 9 right
        left; exact ⟨_,_,_,_,_,site,bd,log,pack,pack.1,pack.2,di,bi,il,dl,low,high,
          List.length_take_of_le dl,dl,List.length_take_of_le il⟩
      · iterate 17 right
        exact ⟨_,_,_,_,_,site,bd,log,pack,pack.1,pack.2,di,bi,il,dl,low,high,
          List.length_take_of_le dl,dl,List.length_take_of_le il⟩
end

def exactReader (small : Bool) : Exact (column small) where
  eval := Pairs.reader (test small)
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    apply Bool.eq_iff_iff.mpr
    rw [Pairs.reader_iff,label_true,holds,sig_iff]
    exact ⟨necessary s.context small,sufficient s.context small⟩

end ConsensusCoverage.HandReadersElection.Agreement
