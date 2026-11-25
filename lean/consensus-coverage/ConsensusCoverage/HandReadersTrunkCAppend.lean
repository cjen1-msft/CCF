module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkCExtension
import all ConsensusCoverage.HandReadersTrunkABatch
import all ConsensusCoverage.HandReadersABatch
import all ConsensusCoverage.AdvanceArmsB
import all ConsensusCoverage.DeepBatchCases
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersBFactor

namespace ConsensusCoverage.HandReadersTrunkC.Batch

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses
open HandReadersA ActionProfile

set_option maxRecDepth 16384
set_option maxHeartbeats 1400000

open Lean Elab Command in
run_cmd liftTermElabM do
  HandReadersBFactor.compile ``step_appendBatch_summary_role_inr

private abbrev Good [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t) :=
  (∃ xs, c.event = .internal (.append xs)) ∧ c.pre.commitIndex < highestCommittableIndex (AdvanceArmsB.appended c.pre) c.actor

private theorem needed [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)
    {mid post : NodeState} {sent : List Model.Envelope} (primary : c.pre.role = .primary)
    (batch : BatchState c.actor c.pre mid sent) (a : Advance c.actor mid post) (retired : post.role = .none) :
    c.pre.commitIndex < highestCommittableIndex (AdvanceArmsB.appended c.pre) c.actor := by
  obtain ⟨⟨xs,m,eq,_⟩,_⟩ := batch
  rcases a with same | h
  · rw [same,eq] at retired
    exact Role.noConfusion (primary.symm.trans retired)
  · exact Extension.normalize c primary xs m mid eq (h.2.2.2.2.2.2.2.1 ▸ h.2.2.2.2.2.2.1)

private theorem supply [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)
    (g : Good c) : step_appendBatch_summary_role_inr f t c := by
  obtain ⟨⟨xs,ev⟩,ahead⟩ := g
  let s := HandReadersTrunkA.Batch.seed c ev
  let m := AdvanceArmsB.appended c.pre
  let post := DeepBatchCases.endState c.actor m
  let e := DeepBatchCases.sent c.actor m
  let suffix : List Entry := [⟨c.pre.currentTerm,.signature⟩]
  have terms : ∀ x ∈ suffix, x.term = c.pre.currentTerm := by simp [suffix]
  have ae : AEFrom c.actor c.pre.currentTerm c.pre.commitIndex m.log e := DeepBatchCases.fromState _ _
  have batch : BatchState c.actor c.pre m [e] := ⟨⟨suffix,c.pre.sentIndex,rfl,terms⟩,SelfQuorumCasesB.singleton ae⟩
  have adv : Advance c.actor m post := DeepBatchCases.ends c.actor m ahead
  have fromPost : AEFrom c.actor post.currentTerm post.commitIndex post.log e :=
    adv.term.symm ▸ (DeepBatchCases.fromState c.actor m).extend (adv.log ▸ List.prefix_refl _) adv.commit_le
  obtain ⟨q,payload,ok⟩ := fromPost.ok
  have empty : ∀ a ∈ ([] : List Model.Envelope), a.source = c.actor ∧ a.payload = .proposeRequestVoteRequest m.currentTerm := by simp
  iterate 44 right
  left
  refine ⟨c.actor,c.pre,xs,?_,s.guards,s.guards.1,s.guards.2,s.guards,m,[e],batch,post,[],⟨adv,empty⟩,
    adv,empty,batch.1,batch.2,suffix,⟨_,rfl,terms⟩,c.pre.sentIndex,⟨rfl,terms⟩,rfl,terms,
    e,.head _, .head _,q,⟨payload,ok⟩,payload,ok,rfl,adv.term,adv.log,adv.commit_le,fromPost,BatchArmsB.start s⟩
  refine ⟨c.event,⟨t,c.tr,DeepInputCases.summary c (fun old => ?_),rfl,rfl,rfl⟩,_,ev,ev,rfl⟩
  have ran : (appendBatch (CCF.Capabilities.record c.actor) c.actor c.pre xs).run {} = some (c.post,c.tr.outputs) := by
    change (step _ _ _ (.internal (.append xs))).run {} = _
    rw [←ev]; exact c.tr.ran
  have ⟨_,_,grows⟩ := LeaderEffect.appendBatch_grows c.actor c.pre xs _ _ _ ran
  exact (Nat.lt_irrefl _) ((c.now_pre old) ▸ grows)

private theorem necessary (s : Step) : letI : Config.InitialConfiguration := ⟨s.cfg⟩
    step_appendBatch_summary_role_inr _ _ s.context → Good s.context := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  intro h
  have x := ((HandReadersBFactor.Exact.step_appendBatch_summary_role_inr _ _ _ (HandReadersBGate.quiet s)).mp h).2
  rcases x with x | x | x
  all_goals
    obtain ⟨_,_,xs,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,_,primary,_,_,mid,_,batch,post,_,_,adv,
      _,_,_,_,_,_,_,_,_,rest⟩ := x
    apply And.intro ⟨xs,ev⟩
    apply needed s.context primary batch adv
    first | exact rest.2.1 | obtain ⟨_,_,_,_,_,_,_,gone,_⟩ := rest; exact gone

def exactOfGood (b : Classes.StepBranch) (h : ∀ s : Step, letI : Config.InitialConfiguration := ⟨s.cfg⟩
    sig s.context b ↔ Good s.context) : Exact b where
  eval := actorRead fun n st ev _ => match ev with
    | .internal (.append _) => decide (st.commitIndex < highestCommittableIndex (AdvanceArmsB.appended st) n)
    | _ => false
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff,h,actorRead_at]
    unfold Good
    cases s.context.event with
    | internal i => cases i <;> simp
    | receive _ _ => simp

def retired := exactOfGood .appendBatch_summary_role_inr fun s =>
  ⟨necessary s,fun h => @supply ⟨s.cfg⟩ _ _ s.context h⟩

end ConsensusCoverage.HandReadersTrunkC.Batch
