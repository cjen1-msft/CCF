module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersABase
import all ConsensusCoverage.NoBackingWitness
import all ConsensusCoverage.Readers
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersA.OtherPeer

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety ActionProfile SolvedWitnesses
set_option maxRecDepth 8192
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

def test (nodes : List (NodeID × NodeState)) (self : NodeID) (pre : NodeState) (ev : Event) (_ : NodeState) :=
  match ev with
  | .receive src (.appendEntriesResponse _) => nodes.any fun (id,_) =>
    decide (id ≠ self ∧ id ≠ src ∧ 0 < pre.matchIndex id)
  | _ => false

def reader : Reader := fun cfg before act after past =>
  actorRead (test before.nodes) cfg before act after past &&
    (Readers.read? (Readers.read cfg before act after past) .commit_backed_kind_ack).getD false

private theorem present (s : Step) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    ∀ {peer}, s.context.pre.role = .primary → peer ≠ s.context.actor →
      0 < s.context.pre.matchIndex peer → ∃ st, (peer,st) ∈ s.before.nodes := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  intro peer primary other positive
  obtain ⟨o,_,seen,_⟩ := s.context.inv.match_ack _ _ _ s.context.pre_now primary other positive
  change (StateCoverage.frame s.before s.past).logs.seen peer o.currentTerm o.log at seen
  rw [StateCoverage.frame_logs,(Historical.logFacts_correct _).seen] at seen
  obtain ⟨st,⟨snap,hist,h⟩,_⟩ := seen
  have key := List.mem_map_of_mem (f := Prod.fst) h
  rw [NoBackingWitness.run_keys s.run snap hist,←NoBackingWitness.run_keys s.run s.before List.mem_cons_self] at key
  obtain ⟨⟨_,st⟩,mem,rfl⟩ := List.mem_map.mp key
  exact ⟨st,mem⟩

private theorem iff_peer (s : Step) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    let c := s.context
    step_commit_backed_fromSource_neg s.frame s.after c ↔
      test s.before.nodes c.actor c.pre c.event c.post = true ∧ step_commit_backed_kind_ack s.frame s.after c := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  constructor
  · rintro (h | h | h | h)
    all_goals
      obtain ⟨root,now,now',n,q,ev,primary,success,term,adv,eq,voters⟩ := h
      first
      | obtain ⟨(p : NodeID),notActor,positive,other,_⟩ := voters
      | obtain ⟨_,_,p,notActor,positive,other,_⟩ := voters
      change 0 < CCF.Function.update c.pre.matchIndex n (max (c.pre.matchIndex n) q.lastLogIndex) p at positive
      rw [CCF.Function.update_of_ne other] at positive
      obtain ⟨st,mem⟩ := present s primary notActor positive
      constructor
      · change test _ _ _ c.event _ = true
        rw [ev]
        exact List.any_eq_true.mpr ⟨(p,st),mem,decide_eq_true ⟨notActor,other,positive⟩⟩
      · first
        | exact .inl ⟨root,now,now',n,q,ev,primary,success,term,adv,eq,now,fun b => ⟨⟨_,b⟩,fun _ _ => b⟩⟩
        | exact .inr ⟨root,now,now',n,q,ev,primary,success,term,adv,eq,now,fun b => ⟨⟨_,b⟩,fun _ _ => b⟩⟩
  · rintro ⟨yes,h | h⟩
    all_goals
      obtain ⟨root,now,now',n,q,ev,primary,success,term,adv,eq,_⟩ := h
      change test _ _ _ c.event _ = true at yes
      rw [ev] at yes
      obtain ⟨⟨p,st⟩,_,cut⟩ := List.any_eq_true.mp yes
      obtain ⟨notActor,other,positive⟩ := of_decide_eq_true cut
      first
      | refine Or.inl ⟨root,now,now',n,q,ev,primary,success,term,adv,eq,p,notActor,?_,other,now,adv.log,adv.term⟩
      | refine Or.inr (Or.inl ⟨root,now,now',n,q,ev,primary,success,term,adv,eq,p,notActor,?_,other,now,adv.log,adv.term⟩)
      change 0 < CCF.Function.update c.pre.matchIndex n (max (c.pre.matchIndex n) q.lastLogIndex) p
      rwa [CCF.Function.update_of_ne other]

def exactReader : Exact .commit_backed_fromSource_neg where
  eval := reader
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    have ack := Readers.read?_at s (b := .commit_backed_kind_ack) (by decide +kernel)
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff,reader,ack,Option.getD_some,Bool.and_eq_true,actorRead_at,
      label_true,holds,sig_iff]
    exact iff_peer s

end ConsensusCoverage.HandReadersA.OtherPeer
