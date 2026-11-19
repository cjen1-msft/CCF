module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.SignedQuiet
import all ConsensusCoverage.CommitKeys
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.InertProfile
import all ConsensusCoverage.LeaderEffect
import all ConsensusCoverage.StateCoverage
import all ConsensusCoverage.StutterProfile

namespace ConsensusCoverage.DropWitness

open Consensus Consensus.Model Consensus.Model.Node
open ActionProfile StutterProfile
open InertProfile (cfg nodes initial initialized queued heartbeat)

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192

private def heartbeatResult : Option Model.State :=
  (transitionSystem cfg nodes).step queued (.deliver heartbeat)

private theorem heartbeatEnabled : heartbeatResult.isSome := by decide +kernel

private def pendingAck : Model.State := heartbeatResult.get heartbeatEnabled

@[expose] public def ack : Model.Envelope := ⟨1, 0, .appendEntriesResponse ⟨BOOTSTRAP_TERM, true, 0⟩⟩

private def consumed : Model.State := {pendingAck with network := []}

private theorem receiveAck :
    (transitionSystem cfg nodes).step pendingAck (.deliver ack) = some consumed := by
  let idx := (initialNodeState cfg 0).matchIndex
  let withIndex (matchIndex : NodeID → Nat) : Model.State :=
    {consumed with nodes := consumed.nodes.map fun (n, st) =>
      (n, if n == 0 then {st with matchIndex} else st)}
  have same : CCF.Function.update idx 1 0 = idx := CCF.Function.update_eq_self 1 idx
  change some (withIndex (CCF.Function.update idx 1 0)) = some (withIndex idx)
  rw [same]

private def witnessStep : Step :=
  ⟨cfg, nodes, pendingAck, [queued, initial], .deliver ack, consumed,
    .step (.step (.initial initialized) (Option.some_get _).symm) (Option.some_get _).symm,
    receiveAck⟩

/-- Send an empty AppendEntries, deliver it, then deliver its successful
zero-index ACK to the primary. The last delivery erases the only queued
envelope and leaves both node records fixed. The previous reverse-membership
test rejects it; the new gate certifies all 457 answers. -/
public theorem ack_consumes_witness :
    ∃ s : Step, s.cfg = {0, 1} ∧ s.nodes = [0, 1] ∧ s.act = .deliver ack ∧
      s.before.network = [ack] ∧ s.after.network = [] ∧ s.after.nodes = s.before.nodes ∧
      s.before.network.all s.after.network.contains = false ∧
      SignedQuiet.gate s.cfg s.before s.act s.after s.past = true ∧
      label s = diagonal (ProofContexts.answers (true, false)) := by
  have passes : SignedQuiet.gate witnessStep.cfg witnessStep.before witnessStep.act
      witnessStep.after witnessStep.past = true := by decide +kernel
  have key : StateCoverage.read cfg pendingAck [queued, initial] = (true, false) := by decide +kernel
  exact ⟨witnessStep, rfl, rfl, rfl, rfl, rfl, rfl, rfl, passes,
    (SignedQuiet.gate_sound witnessStep passes).trans (congrArg (diagonal ∘ ProofContexts.answers) key)⟩

end ConsensusCoverage.DropWitness
