module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersElectionCoreSites
import all ConsensusCoverage.HandReadersElectionPairs
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersElection.Core

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety Ledger
open ActionProfile SolvedWitnesses HandReadersA
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192

inductive Kind where | covered | uncovered | ahead | tied | strict | equal

def column : Kind → Classes.StepBranch
  | .covered => .core_covered_pos
  | .uncovered => .core_covered_neg
  | .ahead => .core_rank_bound_inl
  | .tied => .core_rank_bound_inr
  | .strict => .core_lt_or_eq_of_le_inl
  | .equal => .core_lt_or_eq_of_le_inr

def test : Kind → Pairs.Test
  | .covered => Pairs.test .covered
  | .uncovered => Pairs.test .uncovered
  | .ahead | .strict => Pairs.test .ahead
  | .tied | .equal => Pairs.test .tied

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

local macro "along " h:term : tactic => `(tactic| {
  have spine := $h
  repeat' first | exact spine | exact spine.1
                | change _ ∧ _ at spine; obtain ⟨_,spine⟩ := spine
                | change Exists _ at spine; obtain ⟨_,spine⟩ := spine })

set_option maxHeartbeats 6000000 in
theorem necessary (kind : Kind) (h : sig c (column kind)) : Pairs.Evidence c (test kind) := by
  cases kind
  all_goals repeat' (change _ ∨ _ at h; rcases h with h | h)
  all_goals
    obtain ⟨g,n,k,b,i,later,d,bound,j,l,log,site,_,_,_,_,_,_,_,_,cond,rest⟩ := h
    have root : CoreSites.Sites c g n k b i later d bound j l log := by
      repeat' first | exact site | exact Or.inl site | apply Or.inr
    obtain ⟨pair,eq⟩ := CoreSites.necessary c root
    refine ⟨l,k,b,i,log,d,pair,?_⟩
    simp only [test,Pairs.test,Bool.and_eq_true,beq_iff_eq,decide_eq_true_eq]
    refine ⟨eq,?_⟩
    first
    | exact cond
    | exact Nat.lt_of_not_ge cond
    | refine ⟨Nat.lt_of_not_ge cond,?_⟩
      first
      | along rest
      | have same : k = termAt log (max d (maxCommittableIndex log)) := by along rest
        have rank : k < termAt log (max d (maxCommittableIndex log)) ∨
            k = termAt log (max d (maxCommittableIndex log)) ∧ i ≤ max d (maxCommittableIndex log) := by along rest
        exact (rank.resolve_left (Nat.not_lt_of_ge (Nat.le_of_eq same.symm)))

set_option maxHeartbeats 1200000 in
private theorem sufficient (kind : Kind) (h : Pairs.Evidence c (test kind)) : sig c (column kind) := by
  obtain ⟨l,k,b,i,log,d,pair,cut⟩ := h
  have eq : l.take (max b d) = log.take (max b d) := by
    cases kind <;> simp only [test,Pairs.test,Bool.and_eq_true,beq_iff_eq] at cut <;> exact cut.1
  obtain ⟨⟨g,n,later,bound,site,facts,camp,lt,clean,chains,window,sub⟩⟩ := CoreSites.ready c pair eq
  have base := Nat.le_max_left b d
  have commit := Nat.le_max_right b d
  obtain ⟨xs,q,acks⟩ := facts.acks
  obtain ⟨ys,q',voters⟩ := camp.voters
  cases kind
  case covered | uncovered =>
    simp only [test,Pairs.test,Bool.and_eq_true,beq_iff_eq,decide_eq_true_eq] at cut
    rcases site with root | root
    all_goals
      first
      | left; refine ⟨g,n,k,b,i,later,d,bound,_,l,log,root,?_⟩
      | iterate 8 right
        refine ⟨g,n,k,b,i,later,d,bound,_,l,log,root,?_⟩
      refine ⟨xs,⟨q,acks⟩,q,acks,ys,⟨q',voters⟩,q',voters,?_,facts,camp,commit,clean,chains,lt,window,eq,base⟩
      first | exact cut.2 | exact Nat.not_le_of_gt cut.2
  case ahead | tied | strict | equal =>
    simp only [test,Pairs.test,Bool.and_eq_true,beq_iff_eq,decide_eq_true_eq] at cut
    have uncovered := Nat.not_le_of_gt cut.2.1
    let j := max d (maxCommittableIndex log)
    have rank : k < termAt log j ∨ k = termAt log j ∧ i ≤ j := by first | exact .inl cut.2.2 | exact .inr cut.2.2
    have le := rank.elim Nat.le_of_lt (fun h => Nat.le_of_eq h.1)
    have pos : 0 < j := by
      apply Nat.pos_of_ne_zero
      intro eqj
      rw [eqj,termAt_zero] at le
      exact (by have := facts.floor; omega)
    obtain ⟨v,a,b'⟩ := quorums_intersect_bounded Config.GENESIS_configured facts.rooted camp.rooted
      eq base commit facts.baseLe (Nat.le_of_lt cut.2.1) (signature_pos facts.signature) q q'
    obtain ⟨p,seen,held⟩ := acks v a
    have len := List.length_take_of_le facts.indexLe
    have last : termAt (l.take i) i = k := by rw [termAt_take Nat.le.refl,facts.termAtIndex]
    have atI : termAt p i = k := by rw [termAt_of_prefix held (Nat.le_of_eq len.symm),last]
    have signed := isSignatureAt_of_prefix held (isSignatureAt_take_of_le Nat.le.refl facts.signature)
    obtain ⟨lower,anchor,canon,length,take⟩ := camp.anchor pos
    have data := And.intro canon (And.intro length take)
    have via (_ : i ≤ j) (_ : l.take i = anchor.take i) := sub
    rcases site with root | root
    all_goals
      first
      | iterate 17 right
        refine ⟨g,n,k,b,i,later,d,bound,_,l,log,root,?_⟩
      | iterate 9 right
        left; refine ⟨g,n,k,b,i,later,d,bound,_,l,log,root,?_⟩
      | iterate 8 right
        refine ⟨g,n,k,b,i,later,d,bound,_,l,log,root,?_⟩
      | left; refine ⟨g,n,k,b,i,later,d,bound,_,l,log,root,?_⟩
      refine ⟨xs,⟨q,acks⟩,q,acks,ys,⟨q',voters⟩,q',voters,uncovered,v,⟨a,b'⟩,a,b',p,⟨seen,held⟩,
        seen,held,lower,⟨_,data⟩,_,data,canon,data.2,length,take,lower,canon,take,?_⟩
      first
      | exact ⟨cut.2.2,facts,camp,lt,eq,commit,clean,len,last,atI,signed,rank,pos,via,chains,window,base⟩
      | exact ⟨cut.2.2,cut.2.2.1,cut.2.2.2,facts,camp,lt,eq,commit,clean,len,last,atI,signed,rank,pos,via,chains,window,base⟩
      | exact ⟨cut.2.2,facts,camp,lt,eq,commit,clean,len,last,atI,signed,rank,le,pos,via,chains,window,base⟩
      | exact ⟨cut.2.2.1,facts,camp,lt,eq,commit,clean,len,last,atI,signed,rank,le,pos,via,chains,window,base⟩
end

def exactReader (kind : Kind) : Exact (column kind) where
  eval := Pairs.reader (test kind)
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    apply Bool.eq_iff_iff.mpr
    rw [Pairs.reader_iff,label_true,holds,sig_iff]
    exact ⟨necessary s.context kind,sufficient s.context kind⟩

end ConsensusCoverage.HandReadersElection.Core
