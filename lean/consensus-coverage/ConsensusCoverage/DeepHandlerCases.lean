module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.DeepSchedules
import all ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.JointWitnesses
import all ConsensusCoverage.QueueSamplesA
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ReachPath
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.DeepHandlerCases

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open ActionProfile ReadersAtoms GuardedDomain SolvedWitnesses QueueSamplesA

set_option maxRecDepth 8192
set_option maxHeartbeats 500000

def sender : Event → NodeID
  | .receive n _ => n
  | _ => 0

def request : Event → AppendEntriesRequest
  | .receive _ (.appendEntriesRequest r) => r
  | _ => ⟨0,0,0,[],0⟩

def observed (x : XView) := observeTerm x.base.pre (.appendEntriesRequest (request x.event))

private def current (st : NodeState) (r : AppendEntriesRequest) :=
  if r.term = st.currentTerm ∧ (st.role = .candidate ∨ st.role = .preVoteCandidate)
    then becomeAwareOfNewTerm st r.term else st

theorem origin [Config.InitialConfiguration] {f : Frame} {t : State} {c : Ctx f t} {x : XView}
    (ok : x.Matches c) (changed : x.base.changed = true)
    (ev : x.event = .receive (sender x.event) (.appendEntriesRequest (request x.event))) :
    (reach% step_handleAppendEntriesRequest_conflict_none[0]) f t c (observed x) (request x.event) ∧
    Direct.CommitFrontier (observed x) ∧ Direct.CommitFrontier (current (observed x) (request x.event)) := by
  let n := sender x.event
  let q := request x.event
  let m := Message.appendEntriesRequest q
  have event : c.event = .receive n m := (X.event_eq ok).trans ev
  have fresh : ¬ Now f c.actor c.post := fun h =>
    Bool.noConfusion (changed.symm.trans ((View.old_post ok.1).mp h))
  have fr := c.inv.frontier _ _ c.pre_now
  have fr' : Direct.CommitFrontier (observeTerm c.pre m) :=
    fr.of_log (Concrete.observeTerm_log _ _) (Concrete.observeTerm_commitIndex _ _)
  have base : (reach% step_handleAppendEntriesRequest_conflict_none[0,0]) f t c c.actor c.pre n m :=
    ⟨c.event,c.post,c.tr.outputs,⟨c.post_now,c.post_now,c.post_now,fresh,rfl,rfl,rfl,rfl,rfl⟩,
      event,event ▸ c.tr.ran,fr,c.tr.ran⟩
  have p : (reach% step_handleAppendEntriesRequest_conflict_none[0]) f t c (observeTerm c.pre m) q :=
    ⟨_,_,_,_,base,fun h => Bool.noConfusion h.1,rfl,fun h => Bool.noConfusion h.1,fr,fr',rfl⟩
  have view : observed x = observeTerm c.pre m := by rw [View.pre_eq ok.1]; rfl
  rw [view]
  exact ⟨p,fr',by unfold current; split <;> first | exact fr' | exact fr'.of_log rfl rfl⟩

inductive Case where | down | stay | none | some

def column : Case → Classes.StepBranch
  | .down => .handleAppendEntriesRequest_stepDown_pos
  | .stay => .handleAppendEntriesRequest_stepDown_neg
  | .none => .handleAppendEntriesRequest_conflict_none
  | .some => .handleAppendEntriesRequest_conflict_some

private def conflict (st : NodeState) (q : AppendEntriesRequest) :=
  firstTermConflictIndex {current st q with primaryKnown := true} q

private def selectedBranch (st : NodeState) (q : AppendEntriesRequest) (ci : Option Nat) : Case → Prop
  | .down => ci = none ∧ q.term = st.currentTerm ∧ (st.role = .candidate ∨ st.role = .preVoteCandidate)
  | .stay => ci = none ∧ ¬(q.term = st.currentTerm ∧ (st.role = .candidate ∨ st.role = .preVoteCandidate))
  | .none => ci = none
  | .some => ci = some 3

private instance (st : NodeState) (q : AppendEntriesRequest) (ci : Option Nat) (k : Case) :
    Decidable (selectedBranch st q ci k) := by cases k <;> unfold selectedBranch <;> infer_instance

private def guard (x : XView) (k : Case) : Bool :=
  let q := request x.event
  let st := observed x
  let cur := current st q
  let ci := conflict st q
  decide (x.base.changed = true ∧ x.event = .receive (sender x.event) (.appendEntriesRequest q) ∧
    ¬(q.term < cur.currentTerm ∨ ¬appendEntryMatchesLog cur q) ∧
    ¬(q.prevLogIndex < cur.commitIndex ∨ (ci.isSome ∧ !cur.isNewFollower)) ∧
    selectedBranch st q ci k)

private def check (s : Step) (k : Case) : Bool :=
  (ofXAction s.cfg s.before s.after s.past s.act).any (guard · k)

private theorem correct (s : Step) (k : Case) (p : check s k = true) :
    label s (.step (column k)) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨x,found,ok⟩ := ofXAction_matches s
  simp only [check,found,Option.any_some,guard,decide_eq_true_eq] at p
  obtain ⟨changed,ev,first_,second_,branch⟩ := p
  obtain ⟨root,ff,cur⟩ := origin ok changed ev
  have within := Nat.le_of_not_lt fun h => second_ (Or.inl h)
  apply (label_true s _).mpr
  apply (sig_iff s.context _).mpr
  cases k with
  | down | stay =>
    iterate 4 right
    exact Or.inl ⟨_,_,root,first_,second_,branch.1,branch.1,branch.2,ff,within⟩
  | none => exact ⟨_,_,root,first_,second_,branch,branch,ff,cur,within⟩
  | some => exact ⟨_,_,root,first_,second_,3,branch,branch,ff,cur,within⟩

open FrontierRows DeepSchedules in
local macro "recorded " sc:term:arg i:num : term => `(selected $sc (by unfold Run.valid; decide) $i)

local macro "handler " k:term:arg chosen:term:arg : term =>
  `(checked (column $k) $chosen (check · $k) (by decide +kernel) (correct · $k))

open FrontierRows in
private def candidateAppend : Run := ⟨{0,1},[0,1],[
  .input 0 (.append [{content := .transaction 1 {configuration := some {0}}},
    {content := .signature,flushes := [(1,3)]},{content := .signature}]),
  .deliver 0 1,.deliver 1 0,.input 1 (.timeout .election),.input 1 (.timeout .election),
  .deliver 1 0,.input 0 (.sendEntries 1 4),.deliver 0 1,.deliver 0 1]⟩

open FrontierRows in
private def candidateStep : Option Step := do
  let steps ← JointWitnesses.recordedAt candidateAppend (by unfold Run.valid; decide) []
  return (← steps[8]?).val

open DeepSchedules in
def certificates : List Certificate :=
  [handler .down candidateStep, handler .stay (recorded installLater 1),
   handler .none (recorded installLater 1), handler .some (recorded divergent 11)]

end ConsensusCoverage.DeepHandlerCases
