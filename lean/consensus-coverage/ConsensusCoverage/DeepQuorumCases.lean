module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.QueueSamplesA
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.ReadersAtoms
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.DeepQuorumCases

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses
open ActionProfile ReadersAtoms GuardedDomain QueueSamplesA

set_option maxRecDepth 8192

private def votes (st : NodeState) (n : NodeID) (r : RequestVoteResponse) :=
  let z := observeTerm st (.requestVoteResponse r)
  { z with votesGranted := insert n z.votesGranted }

private abbrev elected (st : NodeState) (self : NodeID) :=
  st.role = .candidate ∧ hasQuorum st.activeConfigurations st.votesGranted ∧ ¬st.isRetiredCommitted self

private def check (s : Step) (yes : Bool) : Bool :=
  (ofXAction s.cfg s.before s.after s.past s.act).any fun x => x.base.changed &&
    match x.event with
    | .receive n (.requestVoteResponse r) =>
      let st := x.base.pre
      let z := observeTerm st (.requestVoteResponse r)
      decide (n ∈ eligiblePeers st x.base.actor ∧ z.role = .candidate ∧ r.term = z.currentTerm ∧
        r.voteGranted = true ∧ decide (elected (votes st n r) x.base.actor) = yes)
    | _ => false

private def column (yes : Bool) : Classes.StepBranch := if yes then .ite__condition_pos else .ite__condition_neg

private theorem sound (s : Step) (yes : Bool) (passed : check s yes = true) :
    label s (.step (column yes)) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  obtain ⟨x,made,ok⟩ := ofXAction_matches s
  simp only [check,made,Option.any_some,Bool.and_eq_true] at passed
  obtain ⟨changed,hit⟩ := passed
  split at hit <;> try contradiction
  rename_i n r ev
  rw [← View.pre_eq ok.1,← View.actor_eq ok.1] at hit
  obtain ⟨peer,role,term,vote,cond⟩ := of_decide_eq_true hit
  let msg := Message.requestVoteResponse r
  let st := votes c.pre n r
  let caps : Caps := CCF.Capabilities.record c.actor
  have event : c.event = .receive n msg := (X.event_eq ok).trans ev
  have fresh : ¬ Now s.frame c.actor c.post := fun h =>
    Bool.noConfusion (changed.symm.trans ((View.old_post ok.1).mp h))
  have fr := c.inv.frontier _ _ c.pre_now
  have obs : Direct.CommitFrontier (observeTerm c.pre msg) :=
    fr.of_log (Concrete.observeTerm_log _ _) (Concrete.observeTerm_commitIndex _ _)
  have kept : Direct.CommitFrontier st := obs.of_log rfl rfl
  have input : (reach% step_ite__condition_pos[0,0]) _ _ c caps c.actor c.pre n msg := by
    exact ⟨c.event,c.post,c.tr.outputs,⟨c.post_now,c.post_now,c.post_now,fresh,rfl,rfl,rfl,rfl,rfl⟩,
      event,event ▸ c.tr.ran,fr,c.tr.ran,rfl⟩
  have effect : (reach% step_ite__condition_pos[0,3]) _ _ c caps c.actor st := by
    exact Or.inl ⟨c.pre,n,msg,input,fun h => h.2 peer,r,rfl,fun h => h.2 peer,
      ⟨role,term,vote⟩,fr,obs,rfl⟩
  have root : (reach% step_ite__condition_pos[0]) _ _ c (elected st c.actor)
      (becomePrimary caps c.actor st) (pure st) := by
    iterate 13 right
    exact ⟨caps,c.actor,st,effect,kept,rfl,rfl,rfl⟩
  apply (label_true s _).mpr
  apply (sig_iff c _).mpr
  cases yes <;> left <;> refine ⟨_,_,_,root,?_,fun _ => kept.becomePrimary caps c.actor,fun _ => Direct.Keeps.pure' kept⟩
  · exact of_decide_eq_false cond
  · exact of_decide_eq_true cond

open DeepSchedules FrontierRows in
def certificates : List Certificate :=
  [checked (column true) (selected divergent (by unfold Run.valid; decide) 8) (check · true)
    (by decide +kernel) (sound · true),
   checked (column false) (selected lateCopy (by unfold Run.valid; decide) 11) (check · false)
    (by decide +kernel) (sound · false)]

end ConsensusCoverage.DeepQuorumCases
