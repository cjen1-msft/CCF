module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersElectionAgreement
import all ConsensusCoverage.HandReadersElectionPairs
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ReachPath
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersElectionB.Comparable

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open HandReadersElection ActionProfile SolvedWitnesses
set_option maxRecDepth 8192

private def test : Pairs.Test := fun _ _ base index _ commit => decide (base < commit ∧ commit ≤ index)

/-- A generalized comparable extension need not be enumerated: on the
agreement route the committed prefix itself witnesses either direction. -/
theorem both [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)
    (pair : Pairs.Evidence c test) :
    sig c .take_eq_take_of_comparable_comparable_inl ∧ sig c .take_eq_take_of_comparable_comparable_inr := by
  obtain ⟨l,k,b,i,log,d,pair,guard⟩ := pair
  obtain ⟨lt,le⟩ := of_decide_eq_true (p := b < d ∧ d ≤ i) guard
  obtain ⟨site,bi,il,dl,sub⟩ := Agreement.site_of_pair c pair
  have len := List.length_take_of_le il
  have bound : d ≤ (l.take i).length := by simpa only [len] using le
  have contained : log.take d <+: l.take i := by
    have same := (List.prefix_iff_eq_take.mp sub)
    rw [same]
    exact take_prefix_take log bound
  have cmp : l.take i <+: l.take i ∨ l.take i <+: l.take i := .inl (List.prefix_refl _)
  have low (_ : d ≤ b) := (take_prefix_take l bi).trans sub
  have high (_ : b < d) : ∃ p, log.take d <+: p ∧ (l.take i <+: p ∨ p <+: l.take i) :=
    ⟨_,contained,cmp⟩
  have pack := And.intro contained cmp
  rcases site with site | site
  all_goals
    have seed : (reach% step_take_eq_take_of_comparable_comparable_inl[7]) f t c (l.take i) (l.take i) d := by
      repeat' first | exact .inl ⟨l,log,b,i,site,lt,pack,contained,cmp,le,bi,il,dl,low,high,
          List.length_take_of_le dl,bound,len,rfl⟩ | apply Or.inr
    all_goals
      constructor
      all_goals
        repeat' first | exact Or.inl ⟨_,_,_,seed,List.prefix_refl _,cmp,bound,bound⟩ | apply Or.inr

def agreementReader := Pairs.reader test

theorem agreement_sound (s : Step) (h : agreementReader s.cfg s.before s.act s.after s.past = true) :
    label s (.step .take_eq_take_of_comparable_comparable_inl) = true ∧
      label s (.step .take_eq_take_of_comparable_comparable_inr) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have ⟨l,r⟩ := both s.context ((Pairs.reader_iff s test).mp h)
  exact ⟨(label_true s _).mpr ((sig_iff s.context _).mpr l),
    (label_true s _).mpr ((sig_iff s.context _).mpr r)⟩

end ConsensusCoverage.HandReadersElectionB.Comparable
