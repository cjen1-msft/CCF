module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.AssistReplyA
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReadersCorpus
import all ConsensusCoverage.QueueSamplesA
import all ConsensusCoverage.DeepSchedulesB
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ReachPath
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.AssistReplyBranchesA

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open ActionProfile ReadersAtoms GuardedDomain SolvedWitnesses QueueSamplesA AssistReplyA
set_option maxRecDepth 8192
set_option maxHeartbeats 700000

structure Fields (z : NodeState) (r : AppendEntriesRequest) : Prop where
  term : (prepared z r).currentTerm = z.currentTerm
  log : (prepared z r).log = z.log
  commit : (prepared z r).commitIndex = z.commitIndex
  vote : (prepared z r).votedFor = z.votedFor
  match_ : (prepared z r).matchIndex = z.matchIndex
  role : (prepared z r).role = z.role ∨ (prepared z r).role = .follower
  cand : (prepared z r).role = .candidate → prepared z r = z
  stays : r.term = z.currentTerm → (prepared z r).role ≠ .candidate

theorem fields (z : NodeState) (r : AppendEntriesRequest) : Fields z r := by
  by_cases h : stepsDown z r
  · have e := h.1
    have eq : prepared z r = becomeAwareOfNewTerm z r.term := ite_eq_left h
    constructor <;> rw [eq] <;> simp [becomeAwareOfNewTerm,e]
  · constructor <;> simp [prepared,h]
    intro same role
    exact h ⟨same,.inl role⟩

inductive Case where | down | keep | role | same | follower
def column : Case → Classes.StepBranch
  | .down => .aeReply_stepDown_pos
  | .keep => .aeReply_stepDown_neg
  | .role => .aeReply_role_inl
  | .same => .aeReply_wRole_inl
  | .follower => .aeReply_wRole_inr

private def guard (k : Case) (z : NodeState) (r : AppendEntriesRequest) : Bool :=
  match k with
  | .down => decide (stepsDown z r)
  | .keep => decide (¬ stepsDown z r)
  | .role => true
  | .same => decide ((prepared z r).role = z.role)
  | .follower => decide ((prepared z r).role = .follower)

private def check (s : Step) (k : Case) : Bool :=
  (ofXAction s.cfg s.before s.after s.past s.act).any fun x =>
    match x.event with
    | .receive _ (.appendEntriesRequest r) =>
      let z := observed x.base.pre r
      let w := prepared z r
      decide (x.base.changed = true ∧ (r.term < w.currentTerm ∨ ¬appendEntryMatchesLog w r) ∧
        (r.term < w.currentTerm ∨ termAt w.log r.prevLogIndex = 0)) && guard k z r
    | _ => false

private theorem rejection [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}
    (k : Case) {self src r z} (call : (reach% step_aeReply_conflict_none[15]) f t c self src z r)
    (lo : r.term ≤ z.currentTerm) (rej : r.term < (prepared z r).currentTerm ∨ ¬appendEntryMatchesLog (prepared z r) r)
    (missing : r.term < (prepared z r).currentTerm ∨ termAt (prepared z r).log r.prevLogIndex = 0)
    (test : guard k z r = true) : sig c (column k) := by
  have p := fields z r
  cases k <;> (iterate 15 right) <;> left
  all_goals first
    | exact ⟨self,src,z,r,call,rej,missing,of_decide_eq_true test,lo,p.log,p.commit,p.vote,p.match_,p.role,p.cand,p.stays⟩
    | exact ⟨self,src,z,r,call,rej,missing,lo,p.term,p.log,p.commit,p.vote,p.match_,p.role,p.cand,p.stays⟩
    | exact ⟨self,src,z,r,call,rej,missing,of_decide_eq_true test,lo,p.term,p.log,p.commit,p.vote,p.match_,p.role,p.cand,p.stays⟩

private theorem sound (s : Step) (k : Case) (yes : check s k = true) : label s (.step (column k)) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨x,made,ok⟩ := ofXAction_matches s
  simp only [check,made,Option.any_some] at yes
  split at yes <;> try contradiction
  rename_i n r ev
  simp only [Bool.and_eq_true,decide_eq_true_eq] at yes
  obtain ⟨⟨fresh,rej,missing⟩,test⟩ := yes
  obtain ⟨call,_,lo,_⟩ := seed ok fresh ev
  exact (label_true _ _).mpr ((sig_iff _ _).mpr (rejection k call lo rej missing test))

-- Deliver the fourth index before the third, immediately after a pre-vote timeout.
private def missingAfterTimeout : DeepSchedulesB.Replay :=
  ⟨⟨{0,1},[0,1],[.input 0 (.append [{content := .signature,flushes := [(1,2)]}]),.deliver 0 1,
    .input 0 (.append [{content := .signature,flushes := [(1,3)]}]),
    .input 0 (.append [{content := .signature,flushes := [(1,4)]}]),.input 1 (.timeout .election),.deliver 0 1]⟩,
   [(5,2)],by unfold FrontierRows.Run.valid; decide⟩

local macro "at_rejection " k:term:arg s:term:arg : term =>
  `(checked (column $k) $s (check · $k) (by decide +kernel) (sound · $k))

def certificates : List Certificate :=
  [at_rejection .down (missingAfterTimeout.atStep 5),at_rejection .keep (ReadersCorpus.stepAt 21 1),
   at_rejection .role (ReadersCorpus.stepAt 21 1),at_rejection .same (ReadersCorpus.stepAt 21 1),
   at_rejection .follower (missingAfterTimeout.atStep 5)]

end ConsensusCoverage.AssistReplyBranchesA
