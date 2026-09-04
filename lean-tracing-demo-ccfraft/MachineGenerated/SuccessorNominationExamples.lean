-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.Runtime.Simulation

set_option autoImplicit false

namespace CCFRaft.SuccessorNominationExamples

open CCFRaft.Simulation

def node0 : Node := ⟨0, by decide⟩
def node1 : Node := ⟨1, by decide⟩
def node2 : Node := ⟨2, by decide⟩

/-- The initial leader may nominate any tied active bootstrap peer. -/
theorem canonicalLeaderCanProposeVote :
    let state := (initialState : State Node (Fin 1))
    Enabled state (.proposeVote node0 node1) := by
  decide

/-- Proposal sending records the leader's current term and explicit endpoints. -/
theorem proposeVotePacketIdentity :
    let before := (initialState : State Node (Fin 1))
    let after := next before (.proposeVote node0 node1)
    after.network node1 =
      [.proposeVoteRequest
        { term := TERM_ONE
          source := node0
          destination := node1 }] := by
  decide

/-- A same-term proposal consumes its packet and starts an ordinary election. -/
theorem sameTermProposalStartsCandidate :
    let proposed :=
      next (initialState : State Node (Fin 1))
        (.proposeVote node0 node1)
    let after := next proposed (.receive node0 node1)
    Enabled proposed (.receive node0 node1) /\
      after.network node1 = [] /\
      (after.nodes node1).role = .candidate /\
      (after.nodes node1).currentTerm = TERM_ONE + 1 /\
      (after.nodes node1).votedFor = some node1 /\
      (after.nodes node1).votesGranted = {node1} /\
      (after.nodes node1).preVotesGranted = ∅ := by
  decide

/-- A stale proposal is consumed without changing destination-local state. -/
theorem staleProposalIsConsumed :
    let request : ProposeVoteRequest Node :=
      { term := TERM_ONE
        source := node0
        destination := node1 }
    let newerFollower :=
      { (initialNodeState node1 : NodeState Node (Fin 1)) with
        currentTerm := TERM_ONE + 1 }
    let state : State Node (Fin 1) :=
      { (initialState : State Node (Fin 1)) with
        nodes := updateNode initialNodes node1 newerFollower
        network := enqueueNoDup (fun _ => []) (.proposeVoteRequest request) }
    let after := next state (.receive node0 node1)
    Enabled state (.receive node0 node1) /\
      after.network node1 = [] /\
      (after.nodes node1).role = newerFollower.role /\
      (after.nodes node1).currentTerm = newerFollower.currentTerm /\
      (after.nodes node1).votedFor = newerFollower.votedFor := by
  decide

/-- A terminal destination consumes and ignores the same-term proposal. -/
theorem retiredCommittedDestinationIgnoresProposal :
    let request : ProposeVoteRequest Node :=
      { term := TERM_ONE
        source := node0
        destination := node1 }
    let terminal :=
      { (initialNodeState node1 : NodeState Node (Fin 1)) with
        membershipState := .retiredCommitted }
    let state : State Node (Fin 1) :=
      { (initialState : State Node (Fin 1)) with
        nodes := updateNode initialNodes node1 terminal
        network := enqueueNoDup (fun _ => []) (.proposeVoteRequest request) }
    let after := next state (.receive node0 node1)
    Enabled state (.receive node0 node1) /\
      after.network node1 = [] /\
      (after.nodes node1).role = terminal.role /\
      (after.nodes node1).currentTerm = terminal.currentTerm /\
      (after.nodes node1).membershipState = .retiredCommitted := by
  decide

/-- Nomination replay text has stable rendering. -/
theorem runtimeActionRendering :
    renderAction (.proposeVote node0 node1) = "propose-vote,0,1" /\
      renderAction (.advanceCommitIndexAndProposeVote node0 node2) =
        "commit-propose,0,2" := by
  decide

run_cmd do
  if
      parseAction "propose-vote,0,1" !=
        some (.proposeVote node0 node1) then
    throwError "propose-vote parser coverage failed"
  if
      parseAction "commit-propose,0,2" !=
        some (.advanceCommitIndexAndProposeVote node0 node2) then
    throwError "commit-propose parser coverage failed"

end CCFRaft.SuccessorNominationExamples
