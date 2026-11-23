module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.AckRead
import all ConsensusCoverage.AckAdvance
import all ConsensusCoverage.AckFamily
import all ConsensusCoverage.AckRead
import all ConsensusCoverage.EvidenceSupport
import all ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.JointWitnesses

namespace ConsensusCoverage.AckWitnesses

open ActionProfile Consensus Consensus.Model Consensus.Model.Node FrontierRows

set_option maxRecDepth 8192
set_option maxHeartbeats 0

-- The resolved replication capture, with the same two-node deployment and
-- bootstrap configuration. Every scheduled command must succeed.
private def replication : Run :=
  ⟨{0}, [0, 1], [
    .input 0 (.append [{content := .signature}]),
    .input 0 (.append [{content := .transaction 1 {configuration := some {0, 1}}}]),
    .input 0 (.append [{content := .signature}]),
    .input 1 (.initAsBackup [{term := 2, content := .transaction 0 {configuration := some {0}}},
      {term := 2, content := .signature}]),
    .deliver 0 1, .deliver 1 0, .input 0 (.sendEntries 1 4), .deliver 0 1, .deliver 1 0]⟩

private theorem valid : replication.valid := by
  change replication.cfg.Nonempty ∧ replication.nodes.Nodup
  decide

private def ackAt (i : Nat) : Option Step := do
  let steps ← JointWitnesses.recorded replication valid
  return (← steps[i]?).val

private def read (s : Step) : Option Bool := AckRead.success? s.cfg s.before s.act s.after s.past

private theorem check (advanced : Bool) :
    (ackAt (if advanced then 8 else 5)).map read = some (some advanced) := by
  cases advanced <;> decide +kernel

/-- Both values of the advancement arm occur in initialized node-only
acknowledgments. This is a lower bound, not a complete table. -/
public theorem advancement_occurs (advanced : Bool) :
    ∃ s : Step, AckFamily.test s.cfg s.before s.act s.after s.past = true ∧
      AckRead.success? s.cfg s.before s.act s.after s.past = some advanced ∧
      label s (.step .post_log_kind_ack) = true ∧
      label s (.step .advance_backed_advance_inr) = advanced := by
  obtain ⟨s, _, answer⟩ := Option.map_eq_some_iff.mp (check advanced)
  change AckRead.success? s.cfg s.before s.act s.after s.past = _ at answer
  have pass : AckFamily.test s.cfg s.before s.act s.after s.past = true := by
    unfold AckRead.success? at answer
    split at answer
    · assumption
    · contradiction
  have ack := AckRead.ack_kind_eq s pass
  rw [answer] at ack
  exact ⟨s, pass, answer, ack, AckRead.success_sound s answer⟩

-- Deliver the heartbeat ahead of the request carrying genesis. The NACK
-- makes the primary back up its send frontier without changing its log.
private def outOfOrder : Run :=
  ⟨{0, 1}, [0, 1],
    [.input 0 (.sendEntries 1 1), .input 0 (.sendEntries 1 1), .deliver 0 1, .deliver 1 0]⟩

private theorem outOfOrder_valid : outOfOrder.valid := by
  change outOfOrder.cfg.Nonempty ∧ outOfOrder.nodes.Nodup
  decide

private def retryStep : Option Step := do
  let steps ← JointWitnesses.recordedAt outOfOrder outOfOrder_valid [(2, 1)]
  return (← steps[3]?).val

private def retryCheck (s : Step) : Bool :=
  AckFamily.test s.cfg s.before s.act s.after s.past &&
    AckRead.mode? s.cfg s.before s.act s.after s.past == some .retry &&
    !(read s).isSome

public theorem retry_occurs :
    ∃ s : Step, AckFamily.test s.cfg s.before s.act s.after s.past = true ∧
      AckRead.mode? s.cfg s.before s.act s.after s.past = some .retry ∧
      label s (.step .post_log_kind_ack) = false := by
  have checked : retryStep.map retryCheck = some true := by decide +kernel
  obtain ⟨s, _, h⟩ := Option.map_eq_some_iff.mp checked
  obtain ⟨pre, no⟩ := Bool.and_eq_true_iff.mp h
  obtain ⟨pass, mode⟩ := Bool.and_eq_true_iff.mp pre
  exact ⟨s, pass, beq_iff_eq.mp mode, (AckRead.ack_kind_eq s pass).trans (by simpa [read] using no)⟩

private def genesisAck : Option Step := do
  let r : Run := {outOfOrder with schedule := [.input 0 (.sendEntries 1 1), .deliver 0 1, .deliver 1 0]}
  let steps ← JointWitnesses.recorded r outOfOrder_valid
  return (← steps[2]?).val

private def noAdvanceKey (s : Step) : Option (Option Bool × Bool) :=
  some (read s, (StateCoverage.read s.cfg s.before s.past).1)

/-- Even accepted replies with no index advance need an endpoint feature.
The same handler mode occurs both with and without a node at index zero. -/
public theorem no_advance_two_contexts :
    ∃ a b : Step,
      AckRead.success? a.cfg a.before a.act a.after a.past = some false ∧
      AckRead.success? b.cfg b.before b.act b.after b.past = some false ∧ label a ≠ label b := by
  have ga : genesisAck.bind noAdvanceKey = some (some false, true) := by decide +kernel
  have rb : (ackAt 5).bind noAdvanceKey = some (some false, false) := by decide +kernel
  obtain ⟨a, _, ak⟩ := Option.bind_eq_some_iff.mp ga
  obtain ⟨b, _, bk⟩ := Option.bind_eq_some_iff.mp rb
  have ⟨ar, az⟩ := Prod.mk.inj (Option.some.inj ak)
  have ⟨br, bz⟩ := Prod.mk.inj (Option.some.inj bk)
  refine ⟨a, b, ar, br, ?_⟩
  intro same
  have key := congrArg (fun p => (ActionFrontier.project p).1.zeroBefore) same
  rw [ActionFrontier.project_eq, ActionFrontier.project_eq] at key
  change (StateCoverage.read a.cfg a.before a.past).1 = (StateCoverage.read b.cfg b.before b.past).1 at key
  rw [az, bz] at key
  contradiction

end ConsensusCoverage.AckWitnesses
