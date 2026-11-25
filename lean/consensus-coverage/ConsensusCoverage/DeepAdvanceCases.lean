module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.QueueSamplesA
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ReachPath
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.DeepAdvanceCases

open CCF Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety Ledger
open ReadersAtoms GuardedDomain SolvedWitnesses ActionProfile QueueSamplesA

set_option maxRecDepth 8192

inductive Case where | noAdvance | advance | keepBack | stays | retires | self | peer

def column : Case → Classes.StepBranch
  | .noAdvance => .facts_advance_inl
  | .advance => .facts_advance_inr
  | .keepBack => .advance_backed_advance_inl
  | .stays => .advance_backed_postRole_inl
  | .retires => .advance_backed_postRole_inr
  | .self => .advance_backed_self_pos
  | .peer => .advance_backed_self_neg

private def contents : Event → List AppendEntryInput
  | .internal (.append xs) => xs
  | _ => []

private def guard (k : Case) (pre post : NodeState) (self other : NodeID) : Prop :=
  let members := configurationMembers (activeConfigurations post.log pre.commitIndex)
  match k with
  | .noAdvance | .keepBack => pre.commitIndex = post.commitIndex
  | .advance => pre.commitIndex < post.commitIndex
  | .stays => pre.commitIndex < post.commitIndex ∧ post.role = .primary
  | .retires => pre.commitIndex < post.commitIndex ∧ post.role = .none
  | .self => pre.commitIndex < post.commitIndex ∧ self ∈ members
  | .peer => pre.commitIndex < post.commitIndex ∧ other ≠ self ∧ other ∈ members ∧ post.commitIndex ≤ pre.matchIndex other

private instance (k : Case) (pre post : NodeState) (self other : NodeID) : Decidable (guard k pre post self other) :=
  by cases k <;> unfold guard <;> infer_instance

private def check (s : Step) (k : Case) (peer : Nat) : Bool :=
  (ofXAction s.cfg s.before s.after s.past s.act).any fun x =>
    decide (x.base.changed = true ∧ x.event = .internal (.append (contents x.event)) ∧
      x.base.pre.role = .primary ∧ x.base.post.role ≠ .follower ∧ x.base.post.log ≠ x.base.pre.log ∧
      x.base.pre.currentTerm = x.base.post.currentTerm ∧ guard k x.base.pre x.base.post x.base.actor peer)

private theorem sound (s : Step) (k : Case) (peer : Nat) (pass : check s k peer = true) :
    label s (.step (column k)) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  obtain ⟨x,made,ok⟩ := ofXAction_matches s
  simp only [check,made,Option.any_some,decide_eq_true_eq] at pass
  obtain ⟨changed,ev,leader,notF,diff,same,cond⟩ := pass
  rw [← View.pre_eq ok.1] at leader diff same cond
  rw [← View.post_eq ok.1] at notF diff same cond
  rw [← View.actor_eq ok.1] at cond
  have event := (X.event_eq ok).trans ev
  have fresh : ¬ Now s.frame c.actor c.post := fun h =>
    Bool.noConfusion (changed.symm.trans ((View.old_post ok.1).mp h))
  have delta : (reach% step_advance_backed_advance_inl[0,0]) _ _ c c c.actor c.post := ⟨c.post_now,fresh,rfl⟩
  have app : ∃ xs sent, (∀ e ∈ xs, e.term = c.pre.currentTerm) ∧
      Advance c.actor {c.pre with log := c.pre.log ++ xs,sentIndex := sent} c.post := by
    cases Summary.kind c.sum with
    | same h _ => exact (diff h).elim
    | append xs sent _ terms adv => exact ⟨xs,sent,terms,adv⟩
    | ack _ _ _ _ _ _ adv => exact (diff (Advance.facts adv).1).elim
    | accept _ _ received _ => rw [event] at received; contradiction
    | install _ _ _ _ _ _ _ _ h => exact (notF h).elim
    | elect wins =>
      rcases (c.electStep (c.wins_elect wins)).2.2.2.1 with hi | ⟨_,cand⟩
      · exact ((Nat.ne_of_lt hi) same).elim
      · rw [leader] at cand; contradiction
  obtain ⟨xs,sent,terms,adv⟩ := app
  let mid := {c.pre with log := c.pre.log ++ xs,sentIndex := sent}
  have a : Advance c.actor mid c.post := adv
  have log : c.post.log = c.pre.log ++ xs := (Advance.facts a).1
  have stamp : c.post.currentTerm = c.pre.currentTerm := (Advance.facts a).2.1
  have role : mid.role = .primary := leader
  have c1 : (reach% step_advance_backed_advance_inl[0]) _ _ c c mid :=
    Or.inl ⟨delta,c.post_now,c.post_now,xs,sent,leader,terms,a,Subsingleton.elim _ _,c.post_now,log,stamp,rfl,rfl⟩
  have c2 : (reach% step_facts_advance_inr[0]) _ _ c c.actor mid c.post :=
    Or.inl ⟨delta,c.post_now,c.post_now,xs,sent,leader,terms,a,Subsingleton.elim _ _,c.post_now,stamp,rfl,rfl,rfl⟩
  have led : Led (s.frame.advance s.after) c.actor c.post.currentTerm := stamp ▸ (c.pre_led leader).mono s.after
  have backed : Backed s.frame c.post.log mid.commitIndex c.post.currentTerm :=
    c.pre_backed (by rw [log]; exact List.take_append_of_le_length c.frontier_pre) (by rw [leader]; simp) (c.pre_led leader)
  have acks (v : NodeID) (different : v ≠ c.actor) (pos : 0 < mid.matchIndex v) :
      ∃ st, Seen (s.frame.advance s.after) v st ∧ st.currentTerm = c.post.currentTerm ∧
        c.post.log.take (mid.matchIndex v) <+: st.log := by
    obtain ⟨st,seen,t,b,sub⟩ := c.match_pre leader different pos
    refine ⟨st,seen,t.trans stamp.symm,?_⟩
    rw [log,List.take_append_of_le_length b]
    exact sub
  apply (label_true s _).mpr
  apply (sig_iff c _).mpr
  cases k with
  | noAdvance | keepBack =>
    have id_ : c.post = mid := a.resolve_right fun h => (Nat.ne_of_lt h.2.2.2.2.2.2.1) cond
    first | exact Or.inl ⟨_,_,id_ ▸ c2,id_ ▸ a⟩
          | exact Or.inl ⟨id_ ▸ c1,id_ ▸ a,id_ ▸ backed,led,id_ ▸ role,id_ ▸ acks⟩
  | advance | stays | retires | self | peer =>
    have inc : mid.commitIndex < c.post.commitIndex := by first | exact cond | exact cond.1
    have h := a.resolve_left fun e => (Nat.ne_of_lt inc) (congrArg NodeState.commitIndex e).symm
    first
    | exact Or.inl ⟨_,_,_,c2,h,h.1,h.2,h.2.1,h.2.2,h.2.2.1,h.2.2.2,h.2.2.2.1,h.2.2.2.2,
        h.2.2.2.2.1,h.2.2.2.2.2,h.2.2.2.2.2.1,h.2.2.2.2.2.2,inc,h.2.2.2.2.2.2.2,
        h.2.2.2.2.2.2.2.1,h.2.2.2.2.2.2.2.2,a⟩
    | have eq := h.2.2.2.2.2.2.2.1
      have ahead : mid.commitIndex < highestCommittableIndex mid c.actor := eq ▸ inc
      obtain ⟨b,spec⟩ := highestCommittableIndex_spec mid c.actor ahead
      let voters := mid.activeMembers.filter (fun n => n = c.actor ∨ mid.matchIndex n ≥ highestCommittableIndex mid c.actor)
      have hits : ∀ v ∈ voters, v = c.actor ∨ mid.matchIndex v ≥ highestCommittableIndex mid c.actor :=
        fun _ vm => (Finset.mem_filter.mp vm).2
      have noCand : c.post.role ≠ .candidate := by
        rcases h.2.2.2.2.2.2.2.2 with same | retired <;> first | rw [same,role]; decide | rw [retired]; decide
      left
      refine ⟨mid,c1,h,h.1,h.2,h.2.1,h.2.2,h.2.2.1,h.2.2.2,h.2.2.2.1,h.2.2.2.2,
        h.2.2.2.2.1,h.2.2.2.2.2,h.2.2.2.2.2.1,h.2.2.2.2.2.2,inc,h.2.2.2.2.2.2.2,eq,
        h.2.2.2.2.2.2.2.2,b,spec,spec.1,spec.2,spec.2.1,spec.2.2,voters,⟨spec.2.2,hits⟩,spec.2.2,hits,?_⟩
      first
      | exact ⟨cond.2.trans role.symm,a,backed,led,role,acks,ahead⟩
      | exact ⟨cond.2,a,backed,led,role,acks,ahead⟩
      | have vm : c.actor ∈ mid.activeMembers := by
          change c.actor ∈ configurationMembers (activeConfigurations mid.log c.pre.commitIndex)
          rw [← h.1]; exact cond.2
        exact ⟨Finset.mem_filter.mpr ⟨vm,Or.inl rfl⟩,a,backed,led,role,acks,ahead,noCand⟩
      | have vm : peer ∈ mid.activeMembers := by
          change peer ∈ configurationMembers (activeConfigurations mid.log c.pre.commitIndex)
          rw [← h.1]; exact cond.2.2.1
        have mi : highestCommittableIndex mid c.actor ≤ mid.matchIndex peer := eq ▸ cond.2.2.2
        exact ⟨peer,Finset.mem_filter.mpr ⟨vm,Or.inr mi⟩,cond.2.1,a,backed,led,role,acks,ahead,noCand⟩

open DeepSchedules FrontierRows in
private def solo : Script := ⟨{0},[0],[.input 0 (.append [{content := .signature}])]⟩

open DeepSchedules FrontierRows in
local macro "advance_at " k:term:arg sc:term:arg i:num : term =>
  `(checked (column $k) (selected $sc (by unfold Run.valid; decide) $i)
    (check · $k 1) (by decide +kernel) (sound · $k 1))

open DeepSchedules in
def certificates : List Certificate :=
  [advance_at .noAdvance divergent 0,advance_at .advance solo 0,advance_at .keepBack divergent 0,
   advance_at .stays solo 0,advance_at .retires retireOnAppend 10,
   advance_at .self solo 0,advance_at .peer retireOnAppend 10]

end ConsensusCoverage.DeepAdvanceCases
