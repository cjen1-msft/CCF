-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.Runtime.NaiveFullStateWitness
import MachineGenerated.Runtime.TraceValidation

set_option autoImplicit false

namespace CCFRaft.RuntimeSuccessorNominationExamples

open CCFRaft.Simulation

def node0 : Node := ⟨0, by decide⟩
def node1 : Node := ⟨1, by decide⟩

/-- Implementation trace records expose proposal send and receive kinds. -/
theorem implementationEventKindsParse :
    TraceValidation.parseEventKind "step_down_and_nominate_successor" =
        .ok .proposeVote /\
      TraceValidation.parseEventKind "recv_propose_request_vote" =
        .ok .recvProposeVote := by
  constructor <;> rfl

run_cmd do
  let noMembers := List.replicate NODE_COUNT false
  let proposeAction : NaiveFullStateWitness.RawAction := {
    action := 1
    kind := "proposeVote"
    kindValue := 16
    source := 0
    destination := 1
    parameter := 0
    transaction := 0
    configurationMembership := noMembers
  }
  match NaiveFullStateWitness.decodeAction 1 proposeAction with
  | .ok (.proposeVote source destination) =>
      if source = node0 /\ destination = node1 then
        pure ()
      else
        throwError "full-state proposeVote action endpoints differ"
  | _ =>
      throwError "full-state proposeVote action decoder coverage failed"
  let terminalProposeAction : NaiveFullStateWitness.RawAction := {
    proposeAction with
    kind := "advanceCommitIndexAndProposeVote"
    kindValue := 17
  }
  match NaiveFullStateWitness.decodeAction 1 terminalProposeAction with
  | .ok (.advanceCommitIndexAndProposeVote source destination) =>
      if source = node0 /\ destination = node1 then
        pure ()
      else
        throwError "terminal proposal action endpoints differ"
  | _ =>
      throwError "terminal proposal action decoder coverage failed"
  let proposalSlot : NaiveFullStateWitness.RawQueueSlot := {
    slot := 0
    active := true
    tag := "proposeVoteRequest"
    tagValue := 7
    source := 0
    destination := 1
    term := TERM_ONE
    prevLogIndex := 0
    prevLogTerm := 0
    leaderCommit := 0
    entryPresent := false
    entryTerm := 0
    entryTag := "unused"
    entryTagValue := 0
    entryTransactionId := 0
    entryConfigurationMembership := noMembers
    entryRetiredMembership := noMembers
    responseSuccess := false
    responseLastLogIndex := 0
    voteLastCommittableTerm := 0
    voteLastCommittableIndex := 0
    voteGranted := false
  }
  match NaiveFullStateWitness.decodeQueueSlot "proposal" proposalSlot with
  | .ok (.proposeVoteRequest request) =>
      if request.term = TERM_ONE /\
          request.source = node0 /\
          request.destination = node1 /\
          NaiveFullStateWitness.messageTag
            (.proposeVoteRequest request) = 7 then
        pure ()
      else
        throwError "full-state ProposeVoteRequest fields differ"
  | _ =>
      throwError "full-state ProposeVoteRequest decoder coverage failed"

end CCFRaft.RuntimeSuccessorNominationExamples
