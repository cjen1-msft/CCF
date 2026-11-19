module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.Projection
import all ConsensusCoverage.FrontierRows
import all ConsensusCoverage.Projection
import all ConsensusCoverage.StateCoverage

namespace ConsensusCoverage.HistoryCollision

open Consensus Consensus.Model Consensus.Model.Node

private abbrev cfg : CCF.Finset NodeID := {0, 1, 2}
private abbrev nodes : List NodeID := [0, 1, 2]
private abbrev sys := transitionSystem cfg nodes

private def initial : Model.State :=
  {nodes := nodes.map fun n => (n, initialNodeState cfg n)}

private theorem initialized : sys.init initial := by
  refine ⟨⟨0, by decide⟩, ?_, ?_⟩ <;> simp [initial, protocol]

private def appendToOne : Model.Action :=
  .deliver ⟨0, 1, .appendEntriesRequest ⟨2, 0, 0,
    [{term := 2, content := .transaction 0 {configuration := some cfg}},
     {term := 2, content := .signature}], 0⟩⟩

private def acceptPreVote : Model.Action :=
  .deliver ⟨2, 0, .requestPreVoteResponse ⟨2, true⟩⟩

private def consumeAck : Model.Action :=
  .deliver ⟨1, 0, .appendEntriesResponse ⟨2, true, 2⟩⟩

private def commonSchedule : List Model.Action :=
  [.local 0 (.append [{content := .signature}]), .local 0 (.sendEntries 1 2),
   .local 0 (.timeout .checkQuorum), .local 0 (.timeout .election),
   .deliver ⟨0, 2, .requestPreVoteRequest ⟨2, 2, 2⟩⟩]

-- Swapping these two deliveries puts the replication on either side of node 0
-- becoming a term-3 candidate. The term-2 ack is consumed only after both.
private def earlySchedule : List Model.Action :=
  commonSchedule ++ [appendToOne, acceptPreVote, consumeAck]
private def lateSchedule : List Model.Action :=
  commonSchedule ++ [acceptPreVote, appendToOne, consumeAck]

private def replay (s : Model.State) (past : List Model.State) :
    List Model.Action → Option (Model.State × List Model.State)
  | [] => some (s, past)
  | act :: rest => do
    let t ← networkStep cfg s act
    replay t (s :: past) rest

private theorem replay_run {s past acts result} (prior : StateCoverage.Run cfg nodes s past)
    (ran : replay s past acts = some result) : StateCoverage.Run cfg nodes result.1 result.2 := by
  induction acts generalizing s past with
  | nil => cases ran; exact prior
  | cons act rest ih =>
    simp only [replay, Option.bind_eq_bind, Option.bind_eq_some_iff] at ran
    obtain ⟨t, step, tail⟩ := ran
    exact ih (.step prior step) tail

set_option maxRecDepth 8192

private theorem early_ok : (replay initial [] earlySchedule).isSome := by decide +kernel
private theorem late_ok : (replay initial [] lateSchedule).isSome := by decide +kernel

private def early := (replay initial [] earlySchedule).get early_ok
private def late := (replay initial [] lateSchedule).get late_ok

-- This is kernel equality of the complete states: the queue is ordered, and
-- both Nat -> Nat fields of every node agree by reduction, not by sampling.
set_option maxHeartbeats 500000 in
private theorem same : early.1 = late.1 := by rfl'

private theorem early_run : StateCoverage.Run cfg nodes early.1 early.2 :=
  replay_run (.initial initialized) (acts := earlySchedule) (Option.some_get _).symm

private theorem late_run : StateCoverage.Run cfg nodes early.1 late.2 :=
  same.symm ▸ replay_run (.initial initialized) (acts := lateSchedule) (Option.some_get _).symm

private def next : Model.Action := .deliver ⟨0, 2, .requestVoteRequest ⟨3, 2, 2⟩⟩

private theorem next_ok : (sys.step early.1 next).isSome := by decide +kernel
private def after : Model.State := (networkStep cfg early.1 next).get next_ok
private theorem next_step : sys.step early.1 next = some after := (Option.some_get _).symm

private theorem early_row : FrontierRows.historyLabel cfg early.1 after early.2 =
    ⟨true, true, false, true, true⟩ := by decide +kernel

private theorem late_row : FrontierRows.historyLabel cfg early.1 after late.2 =
    ⟨true, false, false, true, false⟩ := by decide +kernel

/-- Two initialized histories reach the very same `Model.State` and take the
same next action. The `StateCoverage.read` backing bit (the second and fifth
columns of `historyLabel`) differs both before and after that action. -/
public theorem replay_collision :
    ∃ (cfg : CCF.Finset NodeID) (nodes : List NodeID) (s t : Model.State)
      (earlyPast latePast : List Model.State) (act : Model.Action),
      StateCoverage.Run cfg nodes s earlyPast ∧ StateCoverage.Run cfg nodes s latePast ∧
      (transitionSystem cfg nodes).step s act = some t ∧
      FrontierRows.historyLabel cfg s t earlyPast = ⟨true, true, false, true, true⟩ ∧
      FrontierRows.historyLabel cfg s t latePast = ⟨true, false, false, true, false⟩ :=
  ⟨cfg, nodes, early.1, after, early.2, late.2, next, early_run, late_run,
    next_step, early_row, late_row⟩

open FullProfile in
/-- Both projected rows are supported by complete compatible profiles of one
raw state pair, not by taking coordinates from unrelated histories or pairs. -/
public theorem observe_collision :
    ∃ (s t : Model.State) (p q : Profile),
      p ∈ observe s t ∧ q ∈ observe s t ∧ p ≠ q ∧
      Projection.project p = ⟨true, true, false, true, true⟩ ∧
      Projection.project q = ⟨true, false, false, true, false⟩ := by
  obtain ⟨c, ns, s, t, hp, hq, act, runP, runQ, step, rowP, rowQ⟩ := replay_collision
  have witness {past} (run : StateCoverage.Run c ns s past) :
      ∃ p, p ∈ observe s t ∧ Projection.project p = FrontierRows.historyLabel c s t past := by
    let f := @StateCoverage.frame ⟨c⟩ s past
    exact ⟨frameProfile c f t,
      ⟨c, ns, f, act, Projection.run_folded run, @StateCoverage.frame_current ⟨c⟩ s past, step, rfl⟩,
      Projection.project_frame run step⟩
  obtain ⟨p, memP, projP⟩ := witness runP
  obtain ⟨q, memQ, projQ⟩ := witness runQ
  have projP := projP.trans rowP
  have projQ := projQ.trans rowQ
  refine ⟨s, t, p, q, memP, memQ, ?_, projP, projQ⟩
  intro eq
  have different := congrArg (fun r => (Projection.project r).backedBefore) eq
  simp [projP, projQ] at different

end ConsensusCoverage.HistoryCollision
