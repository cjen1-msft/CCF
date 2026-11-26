module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersElectionCore
import all ConsensusCoverage.HandReadersElectionCoreSites
import all ConsensusCoverage.HandReadersElectionPairs
import all ConsensusCoverage.CanonicalLogs
import all ConsensusCoverage.StutterProfile
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ReachPath
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersElectionB.Anchor

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety Ledger
open HandReadersElection ActionProfile SolvedWitnesses HandReadersA
set_option maxRecDepth 8192
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

abbrev Direction (forward : Bool) (a b : List Entry) := if forward then a <+: b else b <+: a
private def test (forward : Bool) (keys : List (Nat × List Entry)) : Pairs.Test := fun l k b i r d =>
  Pairs.test .tied l k b i r d && keys.any fun (term,a) =>
    let j := max d (maxCommittableIndex r)
    decide (term = k ∧ j ≤ a.length ∧ r.take j = a.take j ∧ Direction forward a l)

def reader (forward : Bool) : Reader := fun cfg pre act post past =>
  Pairs.reader (test forward (CanonicalLogs.keys (cfg.min?.getD 0) (post :: pre :: past))) cfg pre act post past

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)
abbrev Evidence (forward : Bool) :=
  ∃ l k b i log d, Pairs.Pair c l k b i log d ∧ Pairs.test .tied l k b i log d ∧
    ∃ a, Canon (f.advance t) k a ∧ max d (maxCommittableIndex log) ≤ a.length ∧
      log.take (max d (maxCommittableIndex log)) = a.take (max d (maxCommittableIndex log)) ∧ Direction forward a l

local macro "along " h:ident : tactic => `(tactic| {
  have spine := $h
  repeat' first | exact spine | exact spine.1
                | change _ ∧ _ at spine; obtain ⟨_,spine⟩ := spine
                | change Exists _ at spine; obtain ⟨_,spine⟩ := spine })

theorem generation {g n k b i later d bound j l r} (h : CoreSites.Sites c g n k b i later d bound j l r) :
    g = (f.advance t).logs ∨ (g = f.logs ∧ ElectStep f t n later r d) := by
  rcases h with h | h | h | h | h | h | h | h | h
  all_goals repeat' (change _ ∨ _ at h; rcases h with h | h)
  all_goals first
    | obtain ⟨_,_,src,rest⟩ := h
      have elect : ElectStep f t n later r d := src.2.2.1
      exact .inr ⟨by along rest,elect⟩
    | exact .inl (by along h)

theorem necessary {g n k b i later d bound j l r a forward}
    (site : CoreSites.Sites c g n k b i later d bound j l r)
    (gap : ¬ i ≤ d) (same : k = termAt r (max d (maxCommittableIndex r)))
    (within : i ≤ max d (maxCommittableIndex r)) (canon : g.canon (termAt r (max d (maxCommittableIndex r))) a)
    (fits : max d (maxCommittableIndex r) ≤ a.length)
    (agrees : r.take (max d (maxCommittableIndex r)) = a.take (max d (maxCommittableIndex r)))
    (dir : Direction forward a l) : Evidence c forward := by
  obtain ⟨pair,eq⟩ := CoreSites.necessary c site
  refine ⟨l,k,b,i,r,d,pair,?_,a,?_,fits,agrees,dir⟩
  · simpa only [Pairs.test,Bool.and_eq_true,beq_iff_eq,decide_eq_true_eq] using
      And.intro eq ⟨Nat.lt_of_not_ge gap,same,within⟩
  · rw [←same] at canon
    obtain rfl | ⟨rfl,_⟩ := generation c site
    · exact canon
    · exact Or.inl canon
end

theorem reader_iff (s : Step) (forward) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    reader forward s.cfg s.before s.act s.after s.past = true ↔ Evidence s.context forward := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have can (k : Nat) (l : List Entry) :
      (k,l) ∈ CanonicalLogs.keys (s.cfg.min?.getD 0) (s.after :: s.before :: s.past) ↔
      Canon (s.frame.advance s.after) k l := by
    change (k,l) ∈ CanonicalLogs.keys Config.INITIAL_PRIMARY _ ↔ _
    rw [CanonicalLogs.mem_keys]
    change _ ↔ (StateCoverage.frame s.after (s.before :: s.past)).logs.canon _ _
    rw [StateCoverage.frame_logs,(Historical.logFacts_correct _).canon]
  simp only [reader,Pairs.reader_iff,Pairs.Evidence,test,Bool.and_eq_true,List.any_eq_true,Prod.exists,
    can,decide_eq_true_eq,Evidence]
  constructor
  · rintro ⟨l,k,b,i,r,d,pair,tied,_,a,ca,rfl,rest⟩
    exact ⟨l,_,b,i,r,d,pair,tied,a,ca,rest⟩
  · rintro ⟨l,k,b,i,r,d,pair,tied,a,ca,rest⟩
    exact ⟨l,k,b,i,r,d,pair,tied,k,a,ca,rfl,rest⟩

theorem sufficient (s : Step) (forward) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    Evidence s.context forward → sig s.context (if forward then .take_eq_take_of_comparable_comparable_inl
      else .take_eq_take_of_comparable_comparable_inr) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  rintro ⟨l,k,b,i,log,d,pair,tied,anchor,cNext,aLength,aTake,dir⟩
  simp only [Pairs.test,Bool.and_eq_true,beq_iff_eq,decide_eq_true_eq] at tied
  obtain ⟨eq,gap,same,ij⟩ := tied
  obtain ⟨⟨g,n,later,bound,site,facts,camp,lt,clean,chains,window,_⟩⟩ := CoreSites.ready c pair eq
  let j := max d (maxCommittableIndex log)
  have canon : g.canon k anchor := by
    have src : CoreSites.Sites c g n k b i later d bound (max b d) l log := by
      rcases site with h | h
      all_goals repeat' first | exact h | exact Or.inl h | apply Or.inr
    obtain rfl | ⟨rfl,win⟩ := generation c src
    · exact cNext
    · rcases c.canon_after cNext with old | ⟨m,st,cn,rfl⟩
      · exact old
      · rcases c.now_after cn.1 with ⟨rfl,rfl⟩ | ⟨other,was⟩
        · have term := (c.electStep win).2.2.2.2.1
          exact (Nat.ne_of_lt lt (cn.2.1.symm.trans term)).elim
        · exact StutterProfile.currentCanon s.folded ⟨was,cn.2.1,cn.2.2.1,c.led_other other cn.2.2.2⟩
  obtain ⟨xs,q,acks⟩ := facts.acks
  obtain ⟨ys,q',voters⟩ := camp.voters
  have base := Nat.le_max_left b d
  have commit := Nat.le_max_right b d
  have pos : 0 < j := Nat.lt_of_lt_of_le (signature_pos facts.signature) ij
  obtain ⟨v,a,b'⟩ := quorums_intersect_bounded Config.GENESIS_configured facts.rooted camp.rooted
    eq base commit facts.baseLe (Nat.le_of_lt gap) (signature_pos facts.signature) q q'
  obtain ⟨p,seen,held⟩ := acks v a
  have len := List.length_take_of_le facts.indexLe
  have last : termAt (l.take i) i = k := by rw [termAt_take (Nat.le_refl _),facts.termAtIndex]
  have atI : termAt p i = k := by rw [termAt_of_prefix held (Nat.le_of_eq len.symm),last]
  have signed := isSignatureAt_of_prefix held (isSignatureAt_take_of_le (Nat.le_refl _) facts.signature)
  have lower := (camp.anchor pos).1
  have ca : g.canon (termAt log j) anchor := same ▸ canon
  have data := And.intro ca (And.intro aLength aTake)
  have rank : k < termAt log j ∨ k = termAt log j ∧ i ≤ j := .inr ⟨same,ij⟩
  have cmp := chains _ _ _ canon facts.canon
  have fit := Nat.le_trans ij aLength
  have short := congrArg (List.take i) aTake
  simp only [List.take_take,Nat.min_eq_left ij] at short
  have root : (reach% step_take_eq_take_of_comparable_comparable_inl[7]) _ _ c anchor l i := by
    rcases site with site | site
    all_goals
      repeat' first
        | exact Or.inl ⟨g,n,k,b,later,d,bound,max b d,log,site,xs,⟨q,acks⟩,q,acks,ys,⟨q',voters⟩,
            q',voters,Nat.not_le_of_gt gap,v,⟨a,b'⟩,a,b',p,⟨seen,held⟩,seen,held,lower,⟨_,data⟩,data,ca,data.2,
            aLength,aTake,lower,ca,aTake,same,facts,camp,lt,eq,commit,clean,len,last,atI,signed,rank,
            Nat.le_of_eq same,pos,ij,cmp,fit,short,chains,window,base⟩
        | exact ⟨g,n,k,b,later,d,bound,max b d,log,site,xs,⟨q,acks⟩,q,acks,ys,⟨q',voters⟩,
            q',voters,Nat.not_le_of_gt gap,v,⟨a,b'⟩,a,b',p,⟨seen,held⟩,seen,held,lower,⟨_,data⟩,data,ca,data.2,
            aLength,aTake,lower,ca,aTake,same,facts,camp,lt,eq,commit,clean,len,last,atI,signed,rank,
            Nat.le_of_eq same,pos,ij,cmp,fit,short,chains,window,base⟩
        | apply Or.inr
  cases forward
  all_goals
    iterate 7 right
    exact Or.inl ⟨anchor,l,i,root,dir,cmp,fit,facts.indexLe⟩

end ConsensusCoverage.HandReadersElectionB.Anchor
