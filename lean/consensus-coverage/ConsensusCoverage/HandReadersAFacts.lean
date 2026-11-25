module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersAPreBacking
import all ConsensusCoverage.CanonicalLogs
import all ConsensusCoverage.CommitKeys
import all ConsensusCoverage.CommitMonitor
import all ConsensusCoverage.StateCoverage
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersA.Facts

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety ActionProfile SolvedWitnesses
set_option maxRecDepth 8192
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

abbrev Test := List Entry → Nat → Nat → Nat → Bool

def any (cfg : FullProfile.Configuration) (history : List State) (test : Test) : Bool :=
  (CanonicalLogs.keys (cfg.min?.getD 0) history).any fun (k,l) =>
    decide (2 ≤ k) && (List.range (l.length + 1)).any fun i =>
      isSignatureAt l i && (termAt l i == k) && (List.range (i+1)).any fun b =>
        test l k b i && CommitMonitor.quorum ((activeConfigurations l b).filter (·.index ≤ i))
          (CommitKeys.acknowledges history k (l.take i))

def reader : Reader := fun cfg before act after past =>
  PreBacking.reader .covered cfg before act after past &&
    actorRead (fun _ pre _ post => any cfg (before :: past) fun l k b i =>
      decide (post.currentTerm - 1 < k ∧ b ≤ pre.commitIndex ∧ pre.log.take pre.commitIndex <+: l.take i))
      cfg before act after past

theorem any_iff (s : Step) (p : Test) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    any s.cfg (s.before :: s.past) p = true ↔
      ∃ l k b i, CommitFacts s.frame.logs l k b i ∧ p l k b i = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let h := s.before :: s.past
  have logs : s.frame.logs = Historical.logFacts h := StateCoverage.frame_logs _ _
  have can (k l) : (k,l) ∈ CanonicalLogs.keys (s.cfg.min?.getD 0) h ↔ s.frame.logs.canon k l := by
    rw [logs,(Historical.logFacts_correct _).canon]
    exact CanonicalLogs.mem_keys h k l
  have ack (k part v) : CommitKeys.acknowledges h k part v = true ↔ ∃ l, s.frame.logs.seen v k l ∧ part <+: l := by
    rw [CommitKeys.acknowledges_iff,logs]
    simp only [(Historical.logFacts_correct _).seen]
    constructor
    · rintro ⟨st,seen,term,sub⟩
      exact ⟨_,⟨st,seen,term,rfl⟩,sub⟩
    · rintro ⟨_,⟨st,seen,term,rfl⟩,sub⟩
      exact ⟨st,seen,term,sub⟩
  change any s.cfg h p = true ↔ _
  simp only [any,List.any_eq_true,Prod.exists,Bool.and_eq_true,decide_eq_true_eq,beq_iff_eq,
    List.mem_range,Nat.lt_succ_iff,can,CommitMonitor.quorum_iff,ack]
  constructor
  · rintro ⟨k,l,canon,floor,i,index,⟨signature,term⟩,b,base,yes,acks⟩
    have copy := s.context.inv.copyLog canon
    exact ⟨l,k,b,i,⟨canon,copy.rooted,copy.sorted,floor,base,index,signature,term,acks⟩,yes⟩
  · rintro ⟨l,k,b,i,facts,yes⟩
    exact ⟨k,l,facts.canon,facts.floor,i,facts.indexLe,⟨facts.signature,facts.termAtIndex⟩,
      b,facts.baseLe,yes,facts.acks⟩

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private abbrev High (term : Nat) := ∃ l k b i, CommitFacts f.logs l k b i ∧
  term - 1 < k ∧ b ≤ c.pre.commitIndex ∧ PreBacking.Part c <+: l.take i

local macro "along " h:term : tactic => `(tactic| {
  have tail := $h
  repeat' first | exact tail | exact tail.1 | obtain ⟨_,tail⟩ := tail })

private theorem equiv : step_pre_split_backing_inr f t c ↔
    step_pre_split_pre_backed_inr f t c ∧ High c c.post.currentTerm := by
  constructor
  · intro yes
    rcases yes with h | h | h | h | h | h | h | h | h | h | h | h | h | h
    all_goals
      obtain ⟨term,origin,_,_,w,_,covered,tail⟩ := h
      have new : PreBacking.Gate c ∧ term = c.post.currentTerm := by
        first | exact PreBacking.local_site c origin
              | exact ⟨⟨by along origin,.inr (by along origin)⟩,by along origin⟩
      have high : High c term := by along tail
      rw [new.2] at high
      obtain ⟨e,p,commit,_,sub⟩ := covered
      exact ⟨PreBacking.sufficient c .covered new.1 ⟨e,p,commit,sub⟩,high⟩
  · rintro ⟨enabled,high⟩
    obtain ⟨gate,e,p,old,sub⟩ := PreBacking.necessary c .covered enabled
    have backed := c.inv.commit_backed c.actor c.pre c.pre_now
    have higher := gate.1
    have pack := And.intro old (And.intro (Nat.le_refl e) sub)
    obtain origin | origin := PreBacking.sources c gate
    all_goals
      first | left; refine ⟨_,origin,backed.1,backed.2,?_⟩
            | iterate 5 right
              left
              refine ⟨_,origin,backed.1,backed.2,?_⟩
      obtain ⟨l,k,b,i,cut⟩ := high
      exact ⟨e,.inr ⟨e,p,pack⟩,⟨e,p,pack⟩,e,⟨p,pack⟩,p,pack,old,pack.2,pack.2.1,sub,
        ⟨l,k,b,i,cut⟩,l,⟨k,b,i,cut⟩,k,⟨b,i,cut⟩,b,⟨i,cut⟩,i,cut,cut.1,cut.2,cut.2.1,cut.2.2,
        cut.2.2.1,cut.2.2.2,higher,old,.inr ⟨l,k,b,i,cut⟩⟩
end

def exactReader : Exact .pre_split_backing_inr where
  eval := reader
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    let c := s.context
    have earlier := Bool.eq_iff_iff.mp ((PreBacking.exactReader .covered).eq_label s)
    rw [label_true,holds,sig_iff] at earlier
    change step_pre_split_pre_backed_inr _ _ c ↔ PreBacking.reader .covered s.cfg s.before s.act s.after s.past = true at earlier
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff,reader,Bool.and_eq_true,actorRead_at,any_iff,←earlier]
    change step_pre_split_backing_inr _ _ c ↔ _
    rw [equiv]
    simp only [High,PreBacking.Part,decide_eq_true_eq,c]

end ConsensusCoverage.HandReadersA.Facts
