module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersElectionBKeys
import all ConsensusCoverage.HandReadersElectionTables
import all ConsensusCoverage.CensusBallots
import all ConsensusCoverage.DeltaSupport
public meta import ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersElectionB.Find

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open ActionProfile SolvedWitnesses HandReadersA
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192

open Lean Meta Elab Term in
local elab "lookupSites% " xs:term:arg* : term => do
  let n := ``step_find_of_mem_here_pos
  let children := fun k => do return ReachPath.children n.getPrefix (← getConstInfo k).value!
  let mut sites := #[]
  for a in ← children n do
    let b := (← children a)[0]!
    let k := mkIdent (← children b)[0]!
    sites := sites.push (← elabTerm (← `($k $xs*)) (some (.sort .zero)))
  return sites.pop.foldr (mkApp2 (mkConst ``Or)) sites.back!

open Lean Meta Elab Tactic in
local elab "ballotCase " h:ident : tactic => withMainContext do
  let p ← (← getFVarId h).getType
  unless p.getAppNumArgs == 4 do throwUnsupportedSyntax
  let n := p.getAppFn.constName!
  let kids := ReachPath.children n.getPrefix (← getConstInfo n).value!
  let ds := (#[n] ++ kids).map mkIdent
  evalTactic (← `(tactic| simp only [$[$ds:ident],*] at $h:ident))

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)
abbrev Sites (s : State) (n : NodeID) (x y : NodeState) := lookupSites% f t c s n x y

private theorem election_change {n k l i} (win : ElectStep f t n k l i) : ¬ Now f c.actor c.post := by
  intro old
  have same := c.now_pre old
  exact DeltaSupport.stableElection c (by simp [DeltaSupport.sameRoleTerm,same]) _ _ _ _ win

local macro "injectSite " h:term : tactic => `(tactic|
  repeat' first | exact $h | exact Or.inl $h | apply Or.inr)

set_option maxHeartbeats 2000000 in
theorem gate_of_sites {s n x y} (h : Sites c s n x y) : Keys.Gate c := by
  rcases h with h | h | h | h | h | h | h | h | h | h | h | h | h | h | h
  all_goals repeat' (change _ ∨ _ at h; rcases h with h | h)
  all_goals first
    | obtain ⟨site,now,nc,led,_⟩ := h
      exact .inr ⟨by injectSite site,_,_,now,nc,led⟩
    | obtain ⟨site,node,now,nc,led,_⟩ := h
      exact .inr ⟨by injectSite site,node,_,now,nc,led⟩
    | exact .inl (Keys.observation_change c h.1)
    | exact .inl (Keys.message_change c h.1)
    | obtain ⟨k,i,l,_,phase,_⟩ := h
      exact .inl (election_change c (n := n) (k := k) (l := l) (i := i) ⟨y,phase⟩)
    | obtain ⟨parent,_⟩ := h
      repeat' (change _ ∨ _ at parent; rcases parent with parent | parent)
      all_goals
        obtain ⟨k,i,l,_,phase,_⟩ := parent
        exact .inl (election_change c (n := c.actor) (k := k) (l := l) (i := i) ⟨x,phase⟩)
    | obtain ⟨p,_⟩ := h
      ballotCase p
      exfalso
      have failed := @CensusBallots.never_reelect _ _ _ c
      have old := @CensusBallots.old_vote _ _ _ c
      have next := @CensusBallots.new_vote _ _ _ c
      grind only

theorem necessary (h : sig c .find_of_mem_here_pos) : Keys.Gate c := by
  repeat' (change _ ∨ _ at h; rcases h with h | h)
  all_goals
    obtain ⟨_,_,_,⟨_,dirs,_,_,_⟩,_⟩ := h
    rcases dirs with ⟨_,site,_⟩ | ⟨_,site,_⟩
    all_goals exact gate_of_sites c (by injectSite site)

private theorem lookup {n st} (now : Now (f.advance t) n st) (h : Sites c t n st st) :
    sig c .find_of_mem_here_pos := by
  change step_find_of_mem_here_pos _ _ _
  simp only [step_find_of_mem_here_pos,HandReadersElection.Tables.findHead]
  rcases h with h | h | h | h | h | h | h | h | h | h | h | h | h | h | h
  all_goals
    repeat' first
      | exact ⟨t.nodes,n,st,⟨t,.inl ⟨st,h,now,now,c.keys_after⟩,c.keys_after,now,rfl⟩,now,c.keys_after⟩
      | exact Or.inl ⟨t.nodes,n,st,⟨t,.inl ⟨st,h,now,now,c.keys_after⟩,c.keys_after,now,rfl⟩,now,c.keys_after⟩
      | apply Or.inr

theorem sufficient (h : Keys.Gate c) : sig c .find_of_mem_here_pos := by
  rcases h with fresh | ⟨site,n,st,now,nc,led⟩
  · apply lookup c c.post_now
    iterate 4 right
    left
    exact ⟨⟨c.post_now,c.post_seen,c.post_now,c.post_seen,c.post_seen,fun old => fresh old.1,rfl⟩,
      c.post_now,rfl,rfl,rfl⟩
  · have cn : CanonNow (f.advance t) n st st.currentTerm := ⟨now,rfl,nc,led⟩
    have canon : Canon (f.advance t) st.currentTerm st.log := .inr ⟨_,_,cn,rfl⟩
    have top := Keys.current c now nc led
    apply lookup c now
    rcases site with site | site | site | site
    all_goals
      first
      | have _ : (reach% step_canon_mono_now_after_inl[0]) f t c c := site
        left
      | have _ : (reach% step_canon_mono_now_after_inl[1]) f t c c := site
        right; left
      | have _ : (reach% step_canon_mono_now_after_inl[2]) f t c c := site
        right; right; left
      | iterate 3 right
        left
    all_goals
      rcases c.now_after now with ⟨rfl,rfl⟩ | ⟨other,old⟩
      · exact .inl ⟨site,now,nc,led,now,led,nc,top,now,led,_,canon,⟨_,_,cn,rfl⟩,⟨_,cn,rfl⟩,
          ⟨cn,rfl⟩,cn,rfl,canon,now,rfl,nc,led,now,led,Keys.fromOld c,rfl,rfl,rfl⟩
      · exact .inr (.inl ⟨site,n,now,nc,led,⟨other,old⟩,other,old,_,canon,⟨_,_,cn,rfl⟩,⟨_,cn,rfl⟩,
          ⟨cn,rfl⟩,cn,rfl,canon,now,rfl,nc,led,now,led,c.led_other other led,rfl,rfl⟩)
end

def positive : Exact .find_of_mem_here_pos where
  eval := Keys.reader
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff,Keys.reader_iff]
    exact ⟨necessary s.context,sufficient s.context⟩

def negative : Exact .find_of_mem_here_neg where
  eval := Keys.reader
  eq_label s := (HandReadersElection.Tables.find_arms_eq s).symm.trans (positive.eq_label s)

end ConsensusCoverage.HandReadersElectionB.Find
