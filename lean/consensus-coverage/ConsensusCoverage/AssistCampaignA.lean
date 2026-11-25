module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.ReceiveCasesB
import all ConsensusCoverage.DeepSchedules
import all ConsensusCoverage.QueueSamplesA
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.AssistCampaignA

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open ActionProfile ReadersAtoms GuardedDomain SolvedWitnesses QueueSamplesA
set_option maxRecDepth 8192

inductive Case where | oldCampaign | committed | uncommitted
def column : Case → Classes.StepBranch
  | .oldCampaign => .campaign_summary_campaign_inr
  | .committed => .promotedLog_committed_pos
  | .uncommitted => .promotedLog_committed_neg

private abbrev candidate (s : NodeState) (v : NodeID) := {s with votesGranted := insert v s.votesGranted}
private def guard (k : Case) (self : NodeID) (st : NodeState) : Bool :=
  match k with
  | .oldCampaign => true
  | .committed => decide (hasQuorum st.activeConfigurations st.votesGranted ∧ ¬st.isRetiredCommitted self ∧ 0 < st.commitIndex)
  | .uncommitted => decide (hasQuorum st.activeConfigurations st.votesGranted ∧ ¬st.isRetiredCommitted self ∧ ¬0 < st.commitIndex)

private instance (s : NodeState) : Decidable (Direct.CommitFrontier s) := by unfold Direct.CommitFrontier; infer_instance
private def check (s : Step) (k : Case) : Bool :=
  (ofXAction s.cfg s.before s.after s.past s.act).any fun x =>
    match x.event with
    | .receive n (.requestVoteResponse q) =>
      let st := x.base.pre
      decide (x.base.changed = true ∧ n ∈ eligiblePeers st x.base.actor ∧
        st.role = .candidate ∧ q.term = st.currentTerm ∧ q.voteGranted = true ∧ Direct.CommitFrontier st) &&
        guard k x.base.actor (candidate st n)
    | _ => false

private theorem casesOf [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}
    (k : Case) {x : XView} (ok : x.Matches c) {n q}
    (ev : x.event = .receive n (.requestVoteResponse q)) (changed : x.base.changed = true)
    (peer : n ∈ eligiblePeers x.base.pre x.base.actor) (role : x.base.pre.role = .candidate)
    (term : q.term = x.base.pre.currentTerm) (grant : q.voteGranted = true)
    (fr : Direct.CommitFrontier x.base.pre) (cond : guard k x.base.actor (candidate x.base.pre n) = true) :
    sig c (column k) := by
  let self := x.base.actor
  let st := x.base.pre
  let z := candidate st n
  let m := Message.requestVoteResponse q
  let event := Event.receive n m
  have pass : ¬(True ∧ ¬n ∈ eligiblePeers st self) := fun h => h.2 peer
  obtain raised | obs := observe_bumping st (message := m) trivial
  · exact absurd raised.1 (Nat.not_lt_of_ge (Nat.le_of_eq term))
  have g := And.intro role (And.intro term grant)
  cases k with
  | oldCampaign =>
    have caller : (reach% step_elect_result_elected_inl[6,1]) f t c self st n q :=
      ⟨x.event,⟨t,c.tr,ReceiveCasesB.changedSummary ok changed,(X.tr_actor_eq ok).symm,
        (X.tr_pre_eq ok).symm,(X.tr_event_eq ok).symm⟩,_,ev,ev,rfl⟩
    have kept : st.role = .candidate ∧ z.currentTerm = st.currentTerm ∧
        (z.votedFor = st.votedFor ∨ st.votedFor = none) ∧ ∀ v ∈ z.votesGranted, v ∈ st.votesGranted ∨
          ∃ p, event = .receive v (.requestVoteResponse p) ∧ p.term = st.currentTerm ∧ p.voteGranted = true := by
      refine ⟨role,rfl,.inl rfl,?_⟩
      intro v member
      rcases CCF.Finset.mem_insert.mp member with rfl | old
      · exact .inr ⟨q,rfl,term,grant⟩
      · exact .inl old
    have camp : Campaign self st event z := ⟨role,rfl,rfl,.inr kept⟩
    have entry : (reach% step_campaign_summary_campaign_inr[6]) f t c self st z z event [] := by
      right; right; right; left
      exact ⟨n,q,caller,pass,obs,obs.1,obs.2,g,.inl ⟨rfl,rfl⟩,camp,rfl,rfl⟩
    have empty {P : Model.Envelope → Prop} : ∀ e ∈ ([] : List Model.Envelope), P e :=
      fun _ h => (List.not_mem_nil h).elim
    have notPrimary : st.role = .primary → z.currentTerm = st.currentTerm → False := by simp [role,st]
    have preserve (_ : z.currentTerm = st.currentTerm) (v) (h : st.votedFor = some v) : z.votedFor = some v := h
    iterate 6 right
    left
    exact ⟨_,_,_,_,_,entry,empty,empty,camp,Nat.le_refl _,notPrimary,preserve,empty,kept,camp,
      .inl ⟨rfl,empty⟩,by simp [Engaged,st,role],notPrimary,preserve⟩
  | committed | uncommitted =>
    have start : (reach% step_fromLeader_loop_entries_cons[0,0,0,0,0,0]) f t c self st x.event x.base.post x.outputs :=
      ⟨c.post_now,c.post_now,c.post_now,fun old => Bool.noConfusion (changed.symm.trans ((View.old_post ok.1).mp old)),
        (X.tr_actor_eq ok).symm,(X.tr_pre_eq ok).symm,(X.tr_event_eq ok).symm,(X.tr_post_eq ok).symm,(X.outputs_eq ok).symm⟩
    have recv : (reach% step_fromLeader_loop_entries_cons[0,0,0,0,0]) f t c self st n m :=
      ⟨x.event,x.base.post,x.outputs,start,ev,X.run_for ok ev.symm,fr,X.run_eq ok⟩
    have cast : (reach% step_promotedLog_committed_pos[0,0,0]) f t c self z := by
      left
      refine ⟨st,n,m,recv,fun h => h.2 peer,q,rfl,fun h => h.2 peer,?_,fr,?_,?_⟩ <;>
        rw [obs.2] <;> first | exact g | exact fr | rfl
    simp only [guard,decide_eq_true_eq] at cond
    have primary : (reach% step_promotedLog_committed_pos[0,0]) f t c z :=
      ⟨self,cast,⟨role,cond.1,cond.2.1⟩,fr⟩
    left
    exact ⟨z,⟨primary,fr⟩,cond.2.2,fr⟩

private theorem sound (s : Step) (k : Case) (yes : check s k = true) : label s (.step (column k)) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨x,made,ok⟩ := ofXAction_matches s
  simp only [check,made,Option.any_some] at yes
  split at yes <;> try contradiction
  rename_i n q ev
  simp only [Bool.and_eq_true,decide_eq_true_eq] at yes
  obtain ⟨⟨changed,peer,role,term,grant,fr⟩,g⟩ := yes
  exact (label_true _ _).mpr ((sig_iff _ _).mpr (casesOf k ok ev changed peer role term grant fr g))

open DeepSchedulesB in
def certificates : List Certificate :=
  [checked (column .oldCampaign) (doomed.atStep 11) (check · .oldCampaign) (by decide +kernel) (sound · .oldCampaign),
   checked (column .committed) (selected DeepSchedules.lateCopy (by unfold FrontierRows.Run.valid; decide) 13)
     (check · .committed) (by decide +kernel) (sound · .committed),
   checked (column .uncommitted) (campaign.atStep 5) (check · .uncommitted) (by decide +kernel) (sound · .uncommitted)]

end ConsensusCoverage.AssistCampaignA
