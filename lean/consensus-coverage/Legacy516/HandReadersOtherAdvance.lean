module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersOtherSites
import all ConsensusCoverage.NoBackingWitness
import all ConsensusCoverage.ReadersShapes
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersOther.Advance

open CCF Consensus Model Model.Node Proofs Safety ActionProfile SolvedWitnesses HandReadersA

set_option maxRecDepth 8192
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

inductive Kind where | identity | growth | retained | retired | self | peer deriving Repr

def column : Kind → Classes.StepBranch
  | .identity => .advance_backed_advance_inl
  | .growth => .advance_backed_advance_inr
  | .retained => .advance_backed_postRole_inl
  | .retired => .advance_backed_postRole_inr
  | .self => .advance_backed_self_pos
  | .peer => .advance_backed_self_neg

def test (k : Kind) (nodes : List (NodeID × NodeState)) (self : NodeID) (pre : NodeState)
    (_ : Event) (post : NodeState) : Bool :=
  match k with
  | .identity => pre.commitIndex == post.commitIndex
  | .growth | .self => decide (pre.commitIndex < post.commitIndex)
  | .retained => decide (pre.commitIndex < post.commitIndex ∧ post.role = .primary)
  | .retired => decide (pre.commitIndex < post.commitIndex ∧ post.role = .none)
  | .peer => decide (pre.commitIndex < post.commitIndex) && nodes.any fun (v,_) =>
    decide (v ≠ self ∧ post.commitIndex ≤ post.matchIndex v)

def reader (k : Kind) : Reader := fun cfg before act after past =>
  actorRead (test k before.nodes) cfg before act after past && source cfg before act after past

private theorem present (s : Step) : letI : Config.InitialConfiguration := ⟨s.cfg⟩
    ∀ {v o}, v ≠ s.context.actor → Seen (s.frame.advance s.after) v o → ∃ st, (v,st) ∈ s.before.nodes := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  intro v o other seen
  have old := (s.context.seen_after seen).resolve_right (fun h => other h.1)
  change (StateCoverage.frame s.before s.past).logs.seen v o.currentTerm o.log at old
  rw [StateCoverage.frame_logs,(Historical.logFacts_correct _).seen] at old
  obtain ⟨_,⟨snap,hist,h⟩,_⟩ := old
  have key := List.mem_map_of_mem (f := Prod.fst) h
  rw [NoBackingWitness.run_keys s.run snap hist,←NoBackingWitness.run_keys s.run s.before List.mem_cons_self] at key
  obtain ⟨⟨_,st⟩,mem,rfl⟩ := List.mem_map.mp key
  exact ⟨st,mem⟩

local macro "along " h:term : tactic => `(tactic| {
  have tail := $h
  repeat' first | exact tail | exact tail.1 | obtain ⟨_,tail⟩ := tail })

local macro "shift " h:term : tactic => `(tactic| {
  repeat' first | exact $h | exact Or.inl $h | apply Or.inr })

private theorem necessary (s : Step) (k : Kind) : letI : Config.InitialConfiguration := ⟨s.cfg⟩
    let c := s.context
    sig c (column k) → test k s.before.nodes c.actor c.pre c.event c.post ∧ Source c := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  change sig c (column k) → test k s.before.nodes c.actor c.pre c.event c.post ∧ Source c
  intro h
  cases k
  case identity =>
    rcases h with h | h | h | h
    all_goals
      have site : Site c c.post := by shift h.1
      obtain ⟨src,eq⟩ := of_site c site
      exact ⟨beq_iff_eq.mpr eq.symm,src⟩
  all_goals
    rcases h with h | h | h | h
    all_goals
      obtain ⟨m,path,fields,rest⟩ := h
      have site : Site c m := by shift path
      obtain ⟨src,index⟩ := of_site c site
      have growth : c.pre.commitIndex < c.post.commitIndex := index ▸ fields.2.2.2.2.2.2.1
      refine ⟨?_,src⟩
      first
      | exact decide_eq_true growth
      | have role : c.post.role = m.role := by along rest
        have leader : m.role = .primary := by along rest
        exact decide_eq_true ⟨growth,role.trans leader⟩
      | have role : c.post.role = .none := by along rest
        exact decide_eq_true ⟨growth,role⟩
      | refine Bool.and_eq_true_iff.mpr ⟨decide_eq_true growth,?_⟩
        obtain ⟨_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,voters,_,_,eligible,
          v,mem,other,a,_,_,_,acks,_⟩ := rest
        have bound := (eligible v mem).resolve_left other
        have ge : c.post.commitIndex ≤ c.post.matchIndex v := by
          rw [a.matchIndex,fields.2.2.2.2.2.2.2.1]; exact bound
        obtain ⟨o,seen,_⟩ := acks v other (a.matchIndex ▸ (Nat.zero_lt_of_lt (Nat.lt_of_lt_of_le growth ge)))
        obtain ⟨st,hm⟩ := present s other seen
        exact List.any_eq_true.mpr ⟨(v,st),hm,decide_eq_true ⟨other,ge⟩⟩

private theorem sufficient (s : Step) (k : Kind) : letI : Config.InitialConfiguration := ⟨s.cfg⟩
    let c := s.context
    test k s.before.nodes c.actor c.pre c.event c.post ∧ Source c → sig c (column k) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  change test k s.before.nodes c.actor c.pre c.event c.post ∧ Source c → sig c (column k)
  rintro ⟨cut,src⟩
  obtain ⟨m,site,a,index,back,led,role,acks⟩ := ready c src
  cases k
  case identity =>
    have same : c.post = m := a.resolve_right fun h =>
      (Nat.ne_of_lt (index ▸ h.2.2.2.2.2.2.1)) (beq_iff_eq.mp cut)
    subst m
    rcases site with site | site | site | site
    all_goals shift ⟨site,a,back,led,role,acks⟩
  all_goals
    simp only [test,decide_eq_true_eq,Bool.and_eq_true,List.any_eq_true,Prod.exists] at cut
    have inc : m.commitIndex < c.post.commitIndex := by rw [index]; first | exact cut | exact cut.1
    have h := a.resolve_left fun eq => (Nat.ne_of_gt inc) (congrArg NodeState.commitIndex eq)
    have eq := h.2.2.2.2.2.2.2.1
    have ahead : m.commitIndex < highestCommittableIndex m c.actor := eq ▸ inc
    have ⟨b,spec⟩ := highestCommittableIndex_spec m c.actor ahead
    let base := m.activeMembers.filter (fun v => v = c.actor ∨ m.matchIndex v ≥ highestCommittableIndex m c.actor)
    have noCand : c.post.role ≠ .candidate := by
      rcases h.2.2.2.2.2.2.2.2 with e | e <;> first | rw [e,role]; decide | rw [e]; decide
    let v : NodeID := by
      first | exact Classical.choose cut.2 | exact c.actor
    have eligible : v = c.actor ∨ m.matchIndex v ≥ highestCommittableIndex m c.actor := by
      first | exact .inl rfl
            | obtain ⟨_,_,_,ge⟩ := Classical.choose_spec cut.2
              exact .inr (eq ▸ a.matchIndex ▸ ge)
    let voters := insert v base
    have quorum := ReadersShapes.quorum_mono (b := voters) (fun _ mem => Finset.mem_insert.mpr (.inr mem)) spec.2.2
    have members : ∀ p ∈ voters, p = c.actor ∨ m.matchIndex p ≥ highestCommittableIndex m c.actor := by
      intro p mem
      rcases Finset.mem_insert.mp mem with rfl | mem
      · exact eligible
      · exact (Finset.mem_filter.mp mem).2
    have vm : v ∈ voters := Finset.mem_insert.mpr (.inl rfl)
    rcases site with site | site | site | site
    all_goals
      repeat' first
        | exact Or.inl ⟨m,site,h,h.1,h.2,h.2.1,h.2.2,h.2.2.1,h.2.2.2,h.2.2.2.1,h.2.2.2.2,
            h.2.2.2.2.1,h.2.2.2.2.2,h.2.2.2.2.2.1,h.2.2.2.2.2.2,inc,h.2.2.2.2.2.2.2,eq,h.2.2.2.2.2.2.2.2,a,back,led,role,acks⟩
        | exact ⟨m,site,h,h.1,h.2,h.2.1,h.2.2,h.2.2.1,h.2.2.2,h.2.2.2.1,h.2.2.2.2,
            h.2.2.2.2.1,h.2.2.2.2.2,h.2.2.2.2.2.1,h.2.2.2.2.2.2,inc,h.2.2.2.2.2.2.2,eq,h.2.2.2.2.2.2.2.2,a,back,led,role,acks⟩
        | apply Or.inl; refine ⟨m,site,?_⟩
        | refine ⟨m,site,?_⟩
        | apply Or.inr
      all_goals
        refine ⟨h,h.1,h.2,h.2.1,h.2.2,h.2.2.1,h.2.2.2,h.2.2.2.1,h.2.2.2.2,
          h.2.2.2.2.1,h.2.2.2.2.2,h.2.2.2.2.2.1,h.2.2.2.2.2.2,inc,h.2.2.2.2.2.2.2,eq,h.2.2.2.2.2.2.2.2,
          b,spec,spec.1,spec.2,spec.2.1,spec.2.2,voters,⟨quorum,members⟩,quorum,members,?_⟩
        first
        | exact ⟨cut.2.trans role.symm,a,back,led,role,acks,ahead⟩
        | exact ⟨cut.2,a,back,led,role,acks,ahead⟩
        | exact ⟨vm,a,back,led,role,acks,ahead,noCand⟩
        | obtain ⟨_,_,other,_⟩ := Classical.choose_spec cut.2
          exact ⟨v,vm,other,a,back,led,role,acks,ahead,noCand⟩

def exactReader (k : Kind) : Exact (column k) where
  eval := reader k
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff,reader,Bool.and_eq_true,actorRead_at,source_iff]
    exact ⟨necessary s k,sufficient s k⟩

end ConsensusCoverage.HandReadersOther.Advance
