module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.DeepCarriedCases
import all ConsensusCoverage.DeepHistoryCases
import all ConsensusCoverage.QueueSamplesA
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ReachPath
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.DeepCoreCases

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open Consensus.Proofs.Ledger
open ReadersAtoms GuardedDomain SolvedWitnesses ActionProfile QueueSamplesA

set_option maxRecDepth 8192

inductive Case where | ahead | tied | strict | equal

def column : Case → Classes.StepBranch
  | .ahead => .core_rank_bound_inl
  | .tied => .core_rank_bound_inr
  | .strict => .core_lt_or_eq_of_le_inl
  | .equal => .core_lt_or_eq_of_le_inr

private def guard (k : Case) (e j t i : Nat) : Prop :=
  match k with
  | .ahead | .strict => e < t
  | .tied | .equal => e = t ∧ i ≤ j

private instance (k : Case) (e j t i : Nat) : Decidable (guard k e j t i) :=
  by cases k <;> unfold guard <;> infer_instance

private def check (s : Step) (k : Case) (e i : Nat) : Bool :=
  (ofXAction s.cfg s.before s.after s.past s.act).any fun x =>
    let pre := x.base.pre
    let j := max pre.commitIndex (maxCommittableIndex pre.log)
    decide (pre.role ≠ .primary ∧ x.base.post.role = .primary ∧ e < x.base.post.currentTerm ∧
      ¬ i ≤ pre.commitIndex ∧ 0 < j ∧ guard k e j (termAt pre.log j) i) &&
    ((x.base.before :: x.base.past).flatMap fun a => a.nodes.map (fun p => p.2.log)).any fun l =>
      decide ((e,l.take i) ∈ x.committedBefore ∧ l.take pre.commitIndex = pre.log.take pre.commitIndex) &&
        DeepHistoryCases.oldFacts x l e 0 i

theorem sound (s : Step) (k : Case) (e i : Nat) (passed : check s k e i = true) :
    label s (.step (column k)) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  obtain ⟨x,made,ok⟩ := ofXAction_matches s
  simp only [check,made,Option.any_some,Bool.and_eq_true,decide_eq_true_eq,List.any_eq_true] at passed
  obtain ⟨⟨pre,post,lt,uncovered,jPos,cond⟩,l,_,⟨mem,agree⟩,facts⟩ := passed
  rw [← View.pre_eq ok.1] at pre uncovered jPos cond agree
  rw [← View.post_eq ok.1] at post lt
  have elect := c.wins_elect ((Summary.leader c.sum post).resolve_left fun old => pre old.1)
  have m := (X.committed_before ok e (l.take i)).mpr mem
  have f := DeepHistoryCases.oldFacts_sound ok facts
  have root := DeepCarriedCases.source c m lt elect
  have camp := root.2.2.2.2
  have back : c.pre.commitIndex = 0 ∨ ∃ a p, s.frame.logs.committed a p ∧
      c.pre.log.take c.pre.commitIndex <+: p :=
    (c.elect_backed elect).imp_right fun ⟨a,p,m,_,sub⟩ => ⟨a,p,m,sub⟩
  have sub := c.old_in_new elect m lt
  have high (_ : 0 < c.pre.commitIndex) : ∃ q, c.pre.log.take c.pre.commitIndex <+: q ∧
      (l.take i <+: q ∨ q <+: l.take i) := ⟨_,List.take_prefix _ _,.inl sub⟩
  have wit := And.intro agree (And.intro (Nat.zero_le c.pre.commitIndex) (Nat.le_refl c.pre.commitIndex))
  have ready : (reach% step_core_covered_pos[8]) _ _ c s.frame.logs c.actor e 0 i
      c.post.currentTerm c.pre.commitIndex c.post.currentTerm c.pre.commitIndex l c.pre.log :=
    Or.inl ⟨e,l.take i,root,f,m,lt,⟨_,wit⟩,wit,agree,wit.2,wit.2.1,wit.2.2,camp,back,lt,
      high,c.inv.commitChains _ _ m,m,rfl,rfl,rfl⟩
  obtain ⟨xs,q,acks⟩ := f.acks
  obtain ⟨ys,q',votes⟩ := camp.voters
  obtain ⟨v,a,b⟩ := quorums_intersect_bounded Config.GENESIS_configured f.rooted camp.rooted
    agree wit.2.1 wit.2.2 f.baseLe (Nat.le_of_lt (Nat.lt_of_not_le uncovered))
    (Nat.lt_of_le_of_lt (Nat.zero_le _) (Nat.lt_of_not_le uncovered)) q q'
  obtain ⟨p,seen,held⟩ := acks v a
  have len := List.length_take_of_le f.indexLe
  have last : termAt (l.take i) i = e := by rw [termAt_take Nat.le.refl,f.termAtIndex]
  have stamp : termAt p i = e := by rw [termAt_of_prefix held (Nat.le_of_eq len.symm), last]
  have signed := isSignatureAt_of_prefix held (isSignatureAt_take_of_le Nat.le.refl f.signature)
  obtain ⟨lower,anchor,canon,length,take⟩ := camp.anchor jPos
  have data := And.intro canon (And.intro length take)
  have clean := fun t a above (_ : t ≤ c.post.currentTerm) canon => c.inv.later e t _ a m canon above
  have rank : e < termAt c.pre.log (max c.pre.commitIndex (maxCommittableIndex c.pre.log)) ∨
      e = termAt c.pre.log (max c.pre.commitIndex (maxCommittableIndex c.pre.log)) ∧
      i ≤ max c.pre.commitIndex (maxCommittableIndex c.pre.log) := by
    cases k <;> first | exact .inl cond | exact .inr cond
  have le := rank.elim Nat.le_of_lt (fun h => Nat.le_of_eq h.1)
  have via (_ : i ≤ max c.pre.commitIndex (maxCommittableIndex c.pre.log)) (_ : l.take i = anchor.take i) := sub
  apply (label_true s _).mpr
  apply (sig_iff c _).mpr
  cases k with
  | ahead | tied | strict | equal =>
    first | (iterate 17 right) | (iterate 8 right)
    refine ⟨_,_,_,_,_,_,_,_,_,_,_,ready,xs,⟨q,acks⟩,q,acks,ys,⟨q',votes⟩,q',votes,uncovered,
      v,⟨a,b⟩,a,b,p,⟨seen,held⟩,seen,held,lower,⟨_,data⟩,_,data,canon,data.2,length,take,lower,canon,take,?_⟩
    first
    | exact ⟨cond,f,camp,lt,agree,wit.2.2,clean,len,last,stamp,signed,rank,jPos,via,c.inv.chains,Nat.sub_le _ _,wit.2.1⟩
    | exact ⟨cond,cond.1,cond.2,f,camp,lt,agree,wit.2.2,clean,len,last,stamp,signed,rank,jPos,via,
        c.inv.chains,Nat.sub_le _ _,wit.2.1⟩
    | exact ⟨cond,f,camp,lt,agree,wit.2.2,clean,len,last,stamp,signed,rank,le,jPos,via,
        c.inv.chains,Nat.sub_le _ _,wit.2.1⟩
    | exact ⟨cond.1,f,camp,lt,agree,wit.2.2,clean,len,last,stamp,signed,rank,le,jPos,via,
        c.inv.chains,Nat.sub_le _ _,wit.2.1⟩

open FrontierRows DeepSchedules in
local macro "core_at " k:term:arg sc:term:arg offset:num e:num i:num : term =>
  `(checked (column $k) (selected $sc (by unfold Run.valid; decide) $offset)
    (check · $k $e $i) (by decide +kernel) (sound · $k $e $i))

open DeepSchedules in
def certificates : List Certificate :=
  [core_at .ahead rankGap 16 2 3,core_at .tied divergent 8 2 2,
   core_at .strict rankGap 16 2 3,core_at .equal divergent 8 2 2]

end ConsensusCoverage.DeepCoreCases
