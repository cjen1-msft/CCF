module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersABase
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersA.SeenRows

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety ActionProfile SolvedWitnesses
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

def reader : Reader := fun cfg before act after past =>
  (GuardedDomain.ofAction cfg before after past act).any (·.changed)

inductive Branch where | old | post | actor

def column : Branch → Classes.StepBranch
  | .old => .seen_after_seen_inl
  | .post => .seen_after_seen_inr
  | .actor => .seen_after_now_after_inl

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private abbrev Delta (n : NodeID) (o : Observation) :=
  (reach% step_seen_after_seen_inl[0]) f t c n o

private theorem direct {n o} (p : Delta c n o) : ¬ Now f c.actor c.post := by
  rintro old
  obtain ⟨st,now,seen,new⟩ := p
  apply new
  constructor
  · rcases c.now_after now with ⟨rfl,rfl⟩ | ⟨_,listed⟩
    · exact old
    · exact listed
  · rcases c.seen_after seen with prior | ⟨rfl,rfl⟩
    · exact prior
    · exact c.inv.observed _ _ old

private theorem signed {n o} (p : (reach% step_seen_after_seen_inl[1]) f t c n o) : Delta c n o := by
  rcases p with ⟨i,⟨now,seen,sig_,new,_⟩,_,_,_,_,_,_,rfl⟩ | ⟨st,i,⟨now,seen,sig_,new,_⟩,_⟩
  all_goals exact ⟨_,now,seen,fun h => new ⟨h.1,h.2,sig_⟩⟩

private theorem iff_changed (k : Branch) : sig c (column k) ↔ ¬ Now f c.actor c.post := by
  constructor
  · intro h
    cases k
    case old | post =>
      rcases h with ⟨_,_,p,_⟩ | ⟨_,_,p,_⟩
      · exact direct c p
      · exact direct c (signed c p)
    case actor =>
      rcases h with ⟨⟨st,now,seen,new,_⟩,_⟩ | ⟨p,_⟩
      · exact direct c ⟨st,now,seen,new⟩
      · rcases p with ⟨i,⟨now,seen,sig_,new,_⟩,_⟩ | ⟨st,i,⟨now,seen,sig_,new,_⟩,_⟩
        all_goals exact direct c ⟨_,now,seen,fun h => new ⟨h.1,h.2,sig_⟩⟩
  · intro fresh
    have delta (o : Observation) (seen : Seen (f.advance t) c.actor o) : Delta c c.actor o :=
      ⟨c.post,c.post_now,seen,fun h => fresh h.1⟩
    have old := c.inv.observed _ _ c.pre_now
    cases k
    case old => exact .inl ⟨_,_,delta (observe c.pre) (.inl old),old,.inl old⟩
    case post =>
      exact .inl ⟨_,_,delta _ c.post_seen,⟨c.post,c.post_now,rfl,rfl⟩,
        c.post,⟨c.post_now,rfl,rfl⟩,c.post_now,⟨rfl,rfl⟩,rfl,rfl,c.post_seen⟩
    case actor =>
      exact .inl ⟨⟨c.post,c.post_now,c.post_seen,fun h => fresh h.1,rfl⟩,
        ⟨c.post,c.post_now,rfl,rfl⟩,⟨c.post_now,rfl,rfl⟩,c.post_now,⟨rfl,rfl⟩,rfl,rfl,
        c.post_now,rfl,rfl,c.post_now,c.post_seen⟩
end

def exactReader (k : Branch) : Exact (column k) where
  eval := reader
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    obtain ⟨v,made,ok⟩ := GuardedDomain.ofAction_matches s
    apply Bool.eq_iff_iff.mpr
    rw [label_true, show holds s (.step (column k)) ↔ sig s.context (column k) from sig_iff _ _,
      iff_changed, GuardedDomain.View.old_post ok, Bool.not_eq_false, reader, made, Option.any_some]

end ConsensusCoverage.HandReadersA.SeenRows
