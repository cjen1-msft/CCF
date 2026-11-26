module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.DeepSchedules
import all ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.QueueSamplesA
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.DeepListCases

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open ActionProfile ReadersAtoms GuardedDomain SolvedWitnesses QueueSamplesA

set_option maxRecDepth 8192

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)
  (fresh : ¬ Now f c.actor c.post)
include fresh

private theorem lookup (primary : c.post.role = .primary) :
    step_find_of_mem_here_pos f t c ∧ step_find_of_mem_here_neg f t c := by
  have now := c.post_now
  have nc : c.post.role ≠ .candidate := by rw [primary]; decide
  have led := c.leader_led c.actor c.post now primary
  have cn : CanonNow (f.advance t) c.actor c.post c.post.currentTerm := ⟨now,rfl,nc,led⟩
  have canon : Canon (f.advance t) c.post.currentTerm c.post.log := Or.inr ⟨_,_,cn,rfl⟩
  have top : ∀ n st, CanonNow (f.advance t) n st c.post.currentTerm → st.log <+: c.post.log :=
    fun n st h => (c.canon_mono _ _ now nc led).1 _ (Or.inr ⟨n,st,h,rfl⟩)
  have old (h : Led f c.actor c.post.currentTerm) := c.old_led_actor h
  have base : (reach% step_find_of_mem_here_pos[0,0,0]) f t c t c.actor c.post c.post := by
    left
    refine ⟨⟨_,_,now,nc,led, fun h => fresh h.1,rfl⟩,now,nc,led,now,led,nc,top,now,led,
      c.post.log,canon,⟨_,_,cn,rfl⟩,⟨_,cn,rfl⟩,⟨cn,rfl⟩,cn,rfl,canon,now,rfl,nc,led,now,led,
      ?_,rfl,rfl,rfl⟩
    intro h
    obtain ⟨eq,nc⟩ := old h
    exact ⟨c.keep_log eq.symm nc (eq ▸ h),c.inv.canon_mono,eq,nc⟩
  have origin : (reach% step_find_of_mem_here_pos[0]) f t c t.nodes c.actor c.post :=
    ⟨t,Or.inl ⟨_,base,now,now,c.keys_after⟩,c.keys_after,now,rfl⟩
  let pair := (c.actor,c.post)
  let other := (c.actor+1,c.post)
  constructor
  · left
    exact ⟨_,_,_,origin,pair,[],(fun _ h => (List.not_mem_nil h).elim),
      by simp,by simp [pair],c.post,by simp,by simp,now,c.keys_after⟩
  · left
    refine ⟨_,_,_,origin,other,[pair],?_,?_,?_,c.actor+1,c.post,?_,?_,Nat.succ_ne_self _,now,c.keys_after⟩
    all_goals simp [pair,other]

private theorem replaced :
    step_mem_replaceNode_here_pos f t c := by
  have now := c.post_now
  have origin : (reach% step_mem_replaceNode_here_pos[0]) f t c c.actor c.actor c.post c.post :=
    ⟨t,c.tr,⟨⟨now,fresh,rfl⟩,now,rfl,HEq.rfl⟩,now,rfl,rfl⟩
  left
  have mem : (c.actor,c.post) ∈ Concrete.replaceNode f.current.nodes c.actor c.post :=
    c.tr.nodesEq ▸ c.tr.post_mem
  exact ⟨_,_,_,_,origin,(c.actor,c.pre),⟨c.pre_now,by simp⟩,c.pre,⟨c.pre_now,by simp⟩,
    c.pre_now,by simp,mem⟩

private theorem notReplaced {n : NodeID} {st : NodeState} (old : (n,st) ∈ f.current.nodes)
    (other : n ≠ c.actor) (entry : Entry) (listed : entry ∈ st.log) :
    step_mem_replaceNode_here_neg f t c := by
  have mapped : (if (n == c.actor) = true then (c.actor,c.post) else (n,st)) = (n,st) := by
    simp [other]
  have mem : (n,st) ∈ Concrete.replaceNode f.current.nodes c.actor c.post :=
    List.mem_map.mpr ⟨(n,st),old,mapped⟩
  have now : Now (f.advance t) n st := by
    change (n,st) ∈ t.nodes
    rwa [c.tr.nodesEq]
  have origin : (reach% step_mem_replaceNode_here_neg[2]) f t c c.actor n c.post st :=
    ⟨t,c.tr,⟨⟨⟨_,_,c.post_now,fresh,rfl⟩,now,entry,listed,rfl⟩,now,rfl,HEq.rfl⟩,now,rfl,rfl⟩
  right; right; left
  exact ⟨_,_,_,_,origin,(n,st),⟨old,mapped⟩,n,st,⟨old,mapped⟩,old,mapped,other,mem⟩
end

inductive Kind where | here | further | changed | peer

def Kind.column : Kind → Classes.StepBranch
  | .here => .find_of_mem_here_pos
  | .further => .find_of_mem_here_neg
  | .changed => .mem_replaceNode_here_pos
  | .peer => .mem_replaceNode_here_neg

private def test (x : XView) : Kind → Bool
  | .here | .further => decide (x.base.post.role = .primary)
  | .changed => true
  | .peer => x.base.before.nodes.any fun (n,st) => decide (n ≠ x.base.actor ∧ st.log ≠ [])

private def check (s : Step) (k : Kind) : Bool :=
  (ofXAction s.cfg s.before s.after s.past s.act).any fun x => x.base.changed && test x k

private theorem correct (s : Step) (k : Kind) (yes : check s k = true) : label s (.step k.column) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  obtain ⟨x, made, ok⟩ := ofXAction_matches s
  simp only [check, made, Option.any_some, Bool.and_eq_true] at yes
  obtain ⟨changed,yes⟩ := yes
  have fresh : ¬ Now s.frame c.actor c.post := fun was =>
    Bool.noConfusion (changed.symm.trans ((View.old_post ok.1).mp was))
  refine (label_true s _).mpr ((sig_iff c _).mpr ?_)
  cases k with
  | here => exact (lookup c fresh ((View.post_eq ok.1).symm ▸ of_decide_eq_true yes)).1
  | further => exact (lookup c fresh ((View.post_eq ok.1).symm ▸ of_decide_eq_true yes)).2
  | changed => exact replaced c fresh
  | peer =>
    obtain ⟨⟨n,st⟩,mem,g⟩ := List.any_eq_true.mp yes
    obtain ⟨different,nonempty⟩ := of_decide_eq_true (p := n ≠ x.base.actor ∧ st.log ≠ []) g
    rw [← View.before_eq ok.1] at mem
    rw [← View.actor_eq ok.1] at different
    obtain ⟨e,he⟩ := List.exists_mem_of_ne_nil st.log nonempty
    exact notReplaced c fresh mem different e he

open FrontierRows DeepSchedules in
local macro "list_at " k:term:arg sc:term:arg i:num : term =>
  `(checked (Kind.column $k) (selected $sc (by unfold Run.valid; decide) $i)
    (check · $k) (by decide +kernel) (correct · $k))

open DeepSchedules in
def certificates : List Certificate :=
  [list_at .here divergent 0,list_at .further divergent 0,
   list_at .changed installLater 1,list_at .peer installLater 1]

end ConsensusCoverage.DeepListCases
