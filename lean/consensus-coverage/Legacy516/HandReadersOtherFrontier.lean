module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersAObserve
import all ConsensusCoverage.AssistAcceptedA
import all ConsensusCoverage.FollowerFoldCasesB
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersOther.Frontier

open Consensus Model Model.Node Proofs Safety ActionProfile SolvedWitnesses HandReadersA
open FollowerFoldCasesB

set_option maxRecDepth 8192
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private def working (pre : NodeState) (q : AppendEntriesRequest) : NodeState :=
  let w := AssistAcceptedA.base pre q
  match firstTermConflictIndex w q with
  | none => w
  | some i => {w with log := w.log.take (i-1), isNewFollower := false}

private def accept (pre : NodeState) (q : AppendEntriesRequest) : Prop :=
  let z := prepared pre q
  ¬ (q.term < z.currentTerm ∨ ¬appendEntryMatchesLog z q) ∧
    ¬ (q.prevLogIndex < z.commitIndex ∨
      (firstTermConflictIndex (AssistAcceptedA.base pre q) q).isSome = true ∧ (!z.isNewFollower) = true)

private instance (pre : NodeState) (q : AppendEntriesRequest) : Decidable (accept pre q) := by
  unfold accept; infer_instance

private def kind (grow : Bool) : AssistAcceptedA.Case :=
  if grow then .advance else .retain

private def test (grow : Bool) (self : NodeID) (pre : NodeState) (ev : Event) : Bool :=
  match ev with
  | .receive _ (.appendEntriesRequest q) =>
    decide (accept pre q) && AssistAcceptedA.guard (kind grow) self (working pre q) q
  | _ => false

def reader (grow : Bool) : Reader := fun cfg before act after past =>
  (GuardedDomain.ofAction cfg before after past act).any fun v =>
    v.changed && test grow v.actor v.pre (ReadersAtoms.eventOf act)

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private abbrev Seed (self : NodeID) (st : NodeState) (q : AppendEntriesRequest) :=
  (reach% step_advance_le_total_inl[0,0]) f t c self st q

private theorem seed_only {self st q} (h : Seed c self st q) :
    ¬Now f c.actor c.post ∧ ∃ n, c.event = .receive n (.appendEntriesRequest q) ∧
      self = c.actor ∧ accept c.pre q ∧ st = working c.pre q := by
  rcases h with ⟨_,call,a,b,clear,_,_,_,_,rfl⟩ | ⟨_,call,a,b,i,hit,_,_,_,_,_,rfl⟩
  all_goals
    obtain ⟨_,src,_,recv,_,rfl,_,_,_,rfl⟩ := call
    obtain ⟨fresh,rfl,rfl,ev⟩ := (Observe.receive_iff c).mp recv
    refine ⟨fresh,src,ev,rfl,⟨a,b⟩,?_⟩
    first | rw [working,show firstTermConflictIndex (AssistAcceptedA.base c.pre q) q = none from clear]
          | rw [working,show firstTermConflictIndex (AssistAcceptedA.base c.pre q) q = some i from hit]

private theorem seed_of {src q} (fresh : ¬Now f c.actor c.post)
    (ev : c.event = .receive src (.appendEntriesRequest q)) (a : accept c.pre q) :
    Seed c c.actor (working c.pre q) q ∧ Direct.CommitFrontier (working c.pre q) := by
  have fr := c.inv.frontier _ _ c.pre_now
  have seen : Direct.CommitFrontier (observed c.pre q) :=
    fr.of_log (Concrete.observeTerm_log ..) (Concrete.observeTerm_commitIndex ..)
  have ready : Direct.CommitFrontier (prepared c.pre q) := by
    unfold prepared; dsimp only; split <;> exact seen
  have call : (reach% step_advance_le_total_inl[0,0,0]) f t c c.actor (observed c.pre q) q :=
    ⟨c.pre,src,_,(Observe.receive_iff c).mpr ⟨fresh,rfl,rfl,ev⟩,fun h => Bool.noConfusion h.1,
      rfl,fun h => Bool.noConfusion h.1,fr,seen,rfl⟩
  have safe := Nat.le_of_not_lt (fun h => a.2 (.inl h))
  unfold working; dsimp only
  cases found : firstTermConflictIndex (AssistAcceptedA.base c.pre q) q with
  | none => exact ⟨.inl ⟨_,call,a.1,a.2,found,found,seen,ready,safe,rfl⟩,ready⟩
  | some i =>
    have lo := Ledger.firstTermConflictIndex_ge found
    exact ⟨.inr ⟨_,call,a.1,a.2,i,found,found,seen,ready,safe,lo,rfl⟩,
      (ready.keep (count := i-1) (Nat.le_trans safe (Nat.le_sub_of_add_le lo)) (suffix := [])).of_log
        (by simp) rfl⟩

private theorem iff_test (grow : Bool) :
    sig c (AssistAcceptedA.column (kind grow)) ↔ ¬Now f c.actor c.post ∧ test grow c.actor c.pre c.event := by
  constructor
  · intro h
    cases grow
    all_goals
      obtain ⟨_,_,_,⟨self,q,seed,_,_,_,_,_,_,_,_,_,rfl,rfl⟩,pos,order,_⟩ := h
      obtain ⟨fresh,n,ev,rfl,ok,rfl⟩ := seed_only c seed
      refine ⟨fresh,?_⟩
      rw [ev]; exact Bool.and_eq_true_iff.mpr ⟨decide_eq_true ok,decide_eq_true ⟨pos,order⟩⟩
  · rintro ⟨fresh,h⟩
    cases ev : c.event with
    | internal => simp [test,ev] at h
    | receive n m =>
      cases m <;> simp only [ev,test,Bool.and_eq_true,decide_eq_true_eq] at h <;> try contradiction
      obtain ⟨seed,fr⟩ := seed_of c fresh ev h.1
      exact AssistAcceptedA.branches (kind grow) seed fr h.2
end

def exactReader (grow : Bool) : Exact (AssistAcceptedA.column (kind grow)) where
  eval := reader grow
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    obtain ⟨v,made,ok⟩ := GuardedDomain.ofAction_matches s
    have ev : ReadersAtoms.eventOf s.act = s.context.event := by
      rw [← (s.context_eq s.context).mpr rfl]
      change ReadersAtoms.eventOf (ActionContext.encode s.context.tr.actor s.context.tr.event) = s.context.tr.event
      cases s.context.tr.event <;> rfl
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff,iff_test,reader,made,Option.any_some,Bool.and_eq_true,
      GuardedDomain.View.old_post ok,Bool.not_eq_false,ev,GuardedDomain.View.actor_eq ok,GuardedDomain.View.pre_eq ok]

end ConsensusCoverage.HandReadersOther.Frontier
