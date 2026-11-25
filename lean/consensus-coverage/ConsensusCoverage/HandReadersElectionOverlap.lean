module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersElectionCoreSites
import all ConsensusCoverage.HandReadersElectionPairs
import all ConsensusCoverage.HandReadersElectionTip
import all ConsensusCoverage.HandReadersAPreBacking
import all ConsensusCoverage.HandReadersAFacts
import all ConsensusCoverage.CommitMonitor
import all ConsensusCoverage.ReachPath
public meta import ConsensusCoverage.ReachPath
public meta import Lean
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersElection.Overlap

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety Ledger
open ActionProfile SolvedWitnesses HandReadersA
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192

abbrev Test := List Entry → List Entry → Nat → Nat → Bool

def reader (p : Test) : Reader := fun cfg before act after past =>
  Pairs.reader (fun l _ b i log d => decide (d < i ∧ l.take (max b d) = log.take (max b d)) && p l log b d)
    cfg before act after past ||
  (PreBacking.reader .covered cfg before act after past &&
    actorRead (fun _ pre _ post =>
      CommitMonitor.quorum (activeConfigurations pre.log pre.commitIndex) (fun _ => true) &&
      Facts.any cfg (before :: past) fun l k b i =>
        decide (post.currentTerm - 1 < k ∧ b ≤ pre.commitIndex ∧
          pre.log.take pre.commitIndex <+: l.take i) && p l pre.log b pre.commitIndex)
      cfg before act after past)

open Lean Elab Term Meta in
local elab "rootSites% " a:term:arg* : term => do
  let root := ``step_rooted_overlap_eq_zero_or_pos_inl
  let names := ReachPath.children root.getPrefix (← getConstInfo root).value!
  let mut arms := #[]
  for site in names do
    let name := mkIdent site
    arms := arms.push (← elabTerm (← `($name $a*)) (some (.sort .zero)))
  return arms.pop.foldr (mkApp2 (mkConst ``Or)) arms.back!

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

abbrev Sites (l r : List Entry) (b d j : Nat) := rootSites% f t c l r b d j

abbrev FromCore (l r : List Entry) (b d : Nat) :=
  ∃ k i, Pairs.Pair c l k b i r d ∧ d < i ∧ l.take (max b d) = r.take (max b d)

abbrev FromCampaign (l r : List Entry) (b d : Nat) :=
  PreBacking.Gate c ∧ PreBacking.Condition c .covered ∧ r = c.pre.log ∧ d = c.pre.commitIndex ∧
  (∃ vs, hasQuorum (activeConfigurations r d) vs) ∧
  ∃ k i, CommitFacts f.logs l k b i ∧ c.post.currentTerm-1 < k ∧ b ≤ d ∧ r.take d <+: l.take i

abbrev Enabled (l r : List Entry) (b d : Nat) := FromCore c l r b d ∨ FromCampaign c l r b d
abbrev Evidence (p : Test) := ∃ l r b d, Enabled c l r b d ∧ p l r b d

omit [Config.InitialConfiguration] in
theorem reader_iff (s : Step) (p : Test) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    reader p s.cfg s.before s.act s.after s.past = true ↔ Evidence s.context p := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have before := Bool.eq_iff_iff.mp ((PreBacking.exactReader .covered).eq_label s)
  rw [label_true,holds,sig_iff] at before
  change sig c (PreBacking.column .covered) ↔ PreBacking.reader .covered s.cfg s.before s.act s.after s.past = true at before
  have ce := before.symm.trans (Iff.intro (PreBacking.necessary c .covered)
    (fun h => PreBacking.sufficient c .covered h.1 h.2))
  simp only [reader,Bool.or_eq_true,Bool.and_eq_true,Pairs.reader_iff,Pairs.Evidence,decide_eq_true_eq,ce,
    actorRead_at,Facts.any_iff,CommitMonitor.quorum_iff,implies_true,and_true]
  constructor
  · rintro (⟨l,k,b,i,r,d,pair,⟨gap,eq⟩,yes⟩ | ⟨⟨gate,covered⟩,vs,l,k,b,i,facts,⟨lt,le,sub⟩,yes⟩)
    · exact ⟨_,_,_,_,.inl ⟨k,i,pair,gap,eq⟩,yes⟩
    · exact ⟨_,_,_,_,.inr ⟨gate,covered,rfl,rfl,vs,k,i,facts,lt,le,sub⟩,yes⟩
  · rintro ⟨l,r,b,d,enabled,yes⟩
    rcases enabled with ⟨k,i,pair,gap,eq⟩ | ⟨gate,covered,rfl,rfl,vs,k,i,facts,lt,le,sub⟩
    · exact .inl ⟨l,k,b,i,r,d,pair,⟨gap,eq⟩,yes⟩
    · exact .inr ⟨⟨gate,covered⟩,vs,l,k,b,i,facts,⟨lt,le,sub⟩,yes⟩

local macro "along " h:term : tactic => `(tactic| {
  have spine := $h
  repeat' first | exact spine | exact spine.1
                | change _ ∧ _ at spine; obtain ⟨_,spine⟩ := spine
                | change Exists _ at spine; obtain ⟨_,spine⟩ := spine })

set_option maxHeartbeats 2000000 in
theorem necessary {l r b d j} (h : Sites c l r b d j) : Enabled c l r b d := by
  rcases h with h | h | h | h | h | h | h | h | h | h | h
  all_goals repeat' (change _ ∨ _ at h; rcases h with h | h)
  all_goals
    first
    | obtain ⟨i,xs,ys,src,rest⟩ := h
      repeat' (change _ ∨ _ at src; rcases src with src | src)
      all_goals first
        | obtain ⟨g,n,k,later,bound,site,_,_,_,_,_,_,gap,_⟩ := src
          have sites : CoreSites.Sites c g n k b i later d bound j l r := by
            repeat' first | exact site | exact Or.inl site | apply Or.inr
          obtain ⟨pair,eq⟩ := CoreSites.necessary c sites
          exact .inl ⟨k,i,pair,Nat.lt_of_not_ge gap,eq⟩
        | obtain ⟨term,caller,_,_,w,_,⟨e,p,m,_,sub⟩,tail⟩ := src
          have source : PreBacking.Gate c ∧ term = c.post.currentTerm := by
            first | exact PreBacking.local_site c caller
                  | exact ⟨⟨by along caller,.inr (by along caller)⟩,by along caller⟩
          obtain ⟨gate,rfl⟩ := source
          obtain rfl : r = c.pre.log := by along tail
          obtain rfl : d = c.pre.commitIndex := by along tail
          have q : hasQuorum (activeConfigurations c.pre.log c.pre.commitIndex) ys := by along tail
          refine .inr ⟨gate,⟨e,p,m,sub⟩,rfl,rfl,⟨ys,q⟩,?_⟩
          repeat' first
            | exact ⟨_,i,tail.1,tail.2.1⟩
            | change _ ∧ _ at tail; obtain ⟨_,tail⟩ := tail
            | change Exists _ at tail; obtain ⟨_,tail⟩ := tail
    | obtain ⟨xs,ys,src,_⟩ := h
      obtain ⟨n,m,k,parent,_⟩ := src
      repeat' (change _ ∨ _ at parent; rcases parent with parent | parent)
      all_goals exact (Tip.not_old_leader c parent.2.2.2.2.1 parent.2.2.2.2.2.1).elim

structure Seed (l r : List Entry) (b d : Nat) where
  pivot : Nat
  site : (reach% step_rooted_overlap_eq_zero_or_pos_inl[0]) f t c l r b d pivot ∨
    (reach% step_rooted_overlap_eq_zero_or_pos_inl[3]) f t c l r b d pivot ∨
    (reach% step_rooted_overlap_eq_zero_or_pos_inl[5]) f t c l r b d pivot
  left : Rooted Config.GENESIS l
  right : Rooted Config.GENESIS r
  leftNE : l ≠ []
  rightNE : r ≠ []
  same : l.take pivot = r.take pivot
  leftLe : b ≤ pivot
  rightLe : d ≤ pivot
  least : pivot = max b d

theorem sufficient {l r b d} (enabled : Enabled c l r b d) : Nonempty (Seed c l r b d) := by
  rcases enabled with ⟨k,i,pair,gap,eq⟩ | ⟨gate,⟨e,p,m,sub⟩,rfl,rfl,⟨ys,q'⟩,k,i,facts,gt,le,pref⟩
  · obtain ⟨⟨g,n,later,bound,site,facts,camp,lt,clean,chains,window,_⟩⟩ := CoreSites.ready c pair eq
    obtain ⟨xs,q,acks⟩ := facts.acks
    obtain ⟨ys,q',votes⟩ := camp.voters
    have before : (reach% step_rooted_overlap_eq_zero_or_pos_inl[5,0]) f t c l r b d (max b d) i xs ys := by
      rcases site with site | site
      · right; right; left
        exact ⟨_,_,_,_,_,site,⟨q,acks⟩,q,acks,⟨q',votes⟩,q',votes,Nat.not_le_of_gt gap,facts,camp,
          eq,Nat.le_max_left _ _,Nat.le_max_right _ _,clean,chains,lt,window⟩
      · right; right; right
        exact ⟨_,_,_,_,_,site,⟨q,acks⟩,q,acks,⟨q',votes⟩,q',votes,Nat.not_le_of_gt gap,facts,camp,
          eq,Nat.le_max_left _ _,Nat.le_max_right _ _,clean,chains,lt,window⟩
    have pos := signature_pos facts.signature
    have ne := List.length_pos_iff.mp (Nat.lt_of_lt_of_le pos facts.indexLe)
    exact ⟨⟨_,.inr (.inr (.inl ⟨i,xs,ys,before,facts.rooted,camp.rooted,eq,Nat.le_max_left _ _,Nat.le_max_right _ _,
      facts.baseLe,Nat.le_of_lt gap,q,q',ne,pos⟩)),facts.rooted,camp.rooted,ne,hasQuorum_nonempty q',
      eq,Nat.le_max_left _ _,Nat.le_max_right _ _,rfl⟩⟩
  · have ⟨xs,q,acks⟩ := facts.acks
    have ⟨old,active⟩ := c.inv.commit_backed _ _ c.pre_now
    have pack := And.intro m (And.intro (Nat.le_refl e) sub)
    have hi := And.intro facts (And.intro gt (And.intro le pref))
    have len := List.length_take_of_le c.frontier_pre
    have ln := List.length_take_of_le facts.indexLe
    have ge := pref.length_le
    have bound := len ▸ ln ▸ ge
    have eq := List.prefix_iff_eq_take.mp pref
    have same := eq
    rw [len,List.take_take,Nat.min_eq_left bound] at same
    have pos := signature_pos facts.signature
    have ne := List.length_pos_iff.mp (Nat.lt_of_lt_of_le pos facts.indexLe)
    have right := c.inv.rooted _ _ c.pre_now
    refine ⟨⟨_,?_,facts.rooted,right,ne,hasQuorum_nonempty q',same.symm,le,Nat.le_refl _,(Nat.max_eq_right le).symm⟩⟩
    obtain origin | origin := PreBacking.sources c gate
    case' inl => left
    case' inr => right; left
    all_goals
      refine ⟨i,xs,ys,?_,facts.rooted,right,same.symm,le,Nat.le_refl _,facts.baseLe,bound,q,q',ne,pos⟩
      exact ⟨_,origin,old,active,e,.inr ⟨e,p,pack⟩,⟨e,p,pack⟩,e,⟨p,pack⟩,p,pack,m,pack.2,pack.2.1,sub,
        ⟨l,k,b,i,hi⟩,⟨k,b,i,hi⟩,k,⟨b,i,hi⟩,⟨i,hi⟩,hi,facts,hi.2,gt,hi.2.2,le,pref,q',⟨q,acks⟩,q,acks,
        gate.1,m,.inr ⟨l,k,b,i,hi⟩,len,ln,ge,eq,rfl,rfl,rfl⟩
end

end ConsensusCoverage.HandReadersElection.Overlap
