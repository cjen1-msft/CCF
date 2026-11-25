module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ReceiveCasesB
import all ConsensusCoverage.ReceiveCasesB
import all ConsensusCoverage.DeepSchedulesB
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.AckComparisonB

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open ActionProfile ReadersAtoms SolvedWitnesses DeepSchedulesB

set_option maxRecDepth 8192
set_option maxHeartbeats 600000

public def questions : List Classes.StepBranch :=
  [.appendEntriesResponse_summary_same_pos, .appendEntriesResponse_summary_same_neg,
   .appendEntriesResponse_summary_max_eq_or_inl, .appendEntriesResponse_summary_max_eq_or_inr]

private theorem casesOf [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}
    (x : XView) (ok : x.Matches c) (changed : x.base.changed = true)
    (source : NodeID) (q : AppendEntriesResponse) (ev : x.event = .receive source (.appendEntriesResponse q))
    (peer : source ∈ eligiblePeers x.base.pre x.base.actor) (leader : x.base.pre.role = .primary)
    (term : q.term = x.base.pre.currentTerm) (success : q.success = true)
    (tie : x.base.pre.matchIndex source = q.lastLogIndex)
    {b : Classes.StepBranch} (mem : b ∈ questions) : sig c b := by
  let self := x.base.actor
  let before := x.base.pre
  let event := Event.receive source (.appendEntriesResponse q)
  let mid := {before with
    matchIndex := CCF.Function.update before.matchIndex source (max (before.matchIndex source) q.lastLogIndex)}
  have caller : (reach% step_appendEntriesResponse_summary_same_pos[15]) f t c self before source q :=
    ⟨x.event, ⟨t, c.tr, ReceiveCasesB.changedSummary ok changed, (X.tr_actor_eq ok).symm,
      (X.tr_pre_eq ok).symm, (X.tr_event_eq ok).symm⟩, _, ev, ev, rfl⟩
  have passed : ¬(True ∧ ¬source ∈ eligiblePeers before self) := fun h => h.2 peer
  obtain bump | same := observe_response before q
  · exact absurd bump.2.1 (Nat.not_lt_of_ge (Nat.le_of_eq term))
  have notOther : ¬(before.role != .primary) = true := by simp [before, leader]
  have quiet (a : NodeState) (r : a.role = before.role) (t' : a.currentTerm = before.currentTerm)
      (l : a.log = before.log) (k : a.commitIndex = before.commitIndex) (v : a.votedFor = before.votedFor)
      (vs : a.votesGranted = before.votesGranted) (mi : a.matchIndex = before.matchIndex) :
      Summary self before event a [] :=
    quiet_summary r t' l k v vs mi no_bumping_sends (by simp)
  have adv : Advance self mid mid := Or.inl rfl
  have empty : ∀ e ∈ ([] : List Model.Envelope), e.source = self ∧
      e.payload = .proposeRequestVoteRequest mid.currentTerm := by simp
  have notCandidate : mid.role ≠ .candidate := by simp [mid, before, leader]
  simp only [questions, List.mem_cons, List.not_mem_nil, or_false] at mem
  rcases mem with rfl | rfl | rfl | rfl
  all_goals iterate 15 right
  all_goals left
  all_goals refine ⟨self, before, source, q, caller, passed, same, same.1, same.2, notOther,
    success, term, mid, [], ⟨adv, empty⟩, adv, empty, leader, leader, rfl, ?_⟩
  · exact ⟨quiet, notCandidate⟩
  · exact ⟨source+1, Nat.succ_ne_self _, quiet, notCandidate⟩
  · exact ⟨passed, quiet, ⟨adv, empty⟩, adv, empty, Nat.max_eq_left (Nat.le_of_eq tie.symm), quiet, notCandidate⟩
  · exact ⟨passed, quiet, ⟨adv, empty⟩, adv, empty, Nat.max_eq_right (Nat.le_of_eq tie), quiet, notCandidate⟩

public theorem occurs {b : Classes.StepBranch} (mem : b ∈ questions) :
    ∃ s : Step, label s (.step b) = true := by
  let a := ReceiveCasesB.asSample duplicate 5 (by decide +kernel) (by decide +kernel)
  letI : Config.InitialConfiguration := ⟨a.s.cfg⟩
  have witness := casesOf (c := a.s.context) a.x a.ok (by decide +kernel) (ReceiveCasesB.src a.x.event)
    (ReceiveCasesB.ack (ReceiveCasesB.msg a.x.event)) (by decide +kernel) (by decide +kernel)
    (by decide +kernel) (by decide +kernel) (by decide +kernel) (by decide +kernel) mem
  exact ⟨a.s, (label_true a.s _).mpr ((sig_iff a.s.context _).mpr witness)⟩

end ConsensusCoverage.AckComparisonB
