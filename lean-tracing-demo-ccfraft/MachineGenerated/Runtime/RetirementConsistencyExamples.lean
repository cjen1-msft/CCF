-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.Runtime.NaiveFullStateWitness
import MachineGenerated.Runtime.TraceValidation

set_option autoImplicit false

namespace CCFRaft.RuntimeRetirementConsistencyExamples

open CCFRaft.Simulation

def node0 : Node := ⟨0, by decide⟩
def node1 : Node := ⟨1, by decide⟩

def leaderReplicateObservation : TraceValidation.Observation := {
  line := 10
  kind := .replicate
  node := node0
  role := some .leader
  targetIndex := some 1
  committable := some false
}

def leaderConfigurationObservation : TraceValidation.Observation := {
  line := 11
  kind := .addConfiguration
  node := node0
  role := some .leader
  configuration := some ({node0, node1} : Finset Node)
  targetIndex := some 1
}

def followerReceiveObservation : TraceValidation.Observation := {
  line := 20
  kind := .recvAppendEntries
  node := node1
  peer := some node0
  role := some .follower
  packet := some {
    term := some TERM_ONE
    previousTerm := some 0
    leaderCommitIndex := some 0
    termOfIndex := some TERM_ONE
    index := some 1
    previousIndex := some 0
  }
}

def followerConfigurationObservation : TraceValidation.Observation := {
  line := 21
  kind := .addConfiguration
  node := node1
  role := some .follower
  configuration := some ({node0, node1} : Finset Node)
  targetIndex := some 1
}

def noNodes : List Bool :=
  List.replicate NODE_COUNT false

def encodedPreVotesFor (node : Node) : List Bool :=
  if node = node1 then
    NaiveFullStateWitness.encodePreVotesGranted
      { (freshNodeState : NodeState Node TxId) with
        preVotesGranted := {node0, node1} }
  else
    noNodes

def unusedEntrySlot
    (offset : Nat) :
    NaiveFullStateWitness.RawEntrySlot := {
  index := offset + 1
  active := false
  term := 0
  tag := "unused"
  tagValue := 0
  transactionId := 0
  configurationMembership := noNodes
  retiredMembership := noNodes
}

def rawNode (node : Node) : NaiveFullStateWitness.RawNode := {
  node := node.val
  role := if node = node0 then "leader" else "follower"
  roleValue := if node = node0 then 3 else 1
  currentTerm := TERM_ONE
  logLength := 0
  commitIndex := 0
  isNewFollower := true
  votedForHasValue := false
  votedForValue := 0
  votesGrantedMembership := noNodes
  preVotesGrantedMembership := encodedPreVotesFor node
  membershipState := "active"
  membershipStateValue := 0
  retirementIndexHasValue := false
  retirementIndexValue := 0
  retirementCommittableIndexHasValue := false
  retirementCommittableIndexValue := 0
  retiredCommittedIndexHasValue := false
  retiredCommittedIndexValue := 0
  retirementCompletedMembership := noNodes
  sentIndex := List.replicate NODE_COUNT 0
  matchIndex := List.replicate NODE_COUNT 0
  logCapacity := NaiveFullStateWitness.LOG_CAPACITY
  logSlots :=
    (List.range NaiveFullStateWitness.LOG_CAPACITY).map unusedEntrySlot
}

def unusedQueueSlot
    (slot : Nat) :
    NaiveFullStateWitness.RawQueueSlot := {
  slot
  active := false
  tag := "unused"
  tagValue := 0
  source := 0
  destination := 0
  term := 0
  prevLogIndex := 0
  prevLogTerm := 0
  leaderCommit := 0
  entryPresent := false
  entryTerm := 0
  entryTag := "unused"
  entryTagValue := 0
  entryTransactionId := 0
  entryConfigurationMembership := noNodes
  entryRetiredMembership := noNodes
  responseSuccess := false
  responseLastLogIndex := 0
  voteLastCommittableTerm := 0
  voteLastCommittableIndex := 0
  voteGranted := false
}

def rawQueue (destination : Node) : NaiveFullStateWitness.RawQueue := {
  destination := destination.val
  length := 0
  capacity := NaiveFullStateWitness.QUEUE_CAPACITY
  slots :=
    (List.range NaiveFullStateWitness.QUEUE_CAPACITY).map unusedQueueSlot
}

def rawInitialState : NaiveFullStateWitness.RawInitialState := {
  nodes := allNodes.map rawNode
  network := allNodes.map rawQueue
  submittedTransactionMembership :=
    List.replicate TX_COUNT false
  hasJoinedMembership := List.replicate NODE_COUNT true
  preVoteStatusEnabled :=
    NaiveFullStateWitness.encodePreVoteStatus fun node =>
      if node = node1 then .enabled else .capable
}

def activeVoteSlot
    (tag : String)
    (tagValue : Nat)
    (granted : Bool) :
    NaiveFullStateWitness.RawQueueSlot := {
  (unusedQueueSlot 0) with
  active := true
  tag
  tagValue
  source := node0.val
  destination := node1.val
  term := TERM_ONE
  voteGranted := granted
}

run_cmd do
  match
      TraceValidation.coalesceObservations
        [leaderReplicateObservation, leaderConfigurationObservation]
  with
  | .ok (observations, count) =>
      if observations = [leaderConfigurationObservation] /\ count = 1 then
        pure ()
      else
        throwError "leader configuration replicate was not coalesced"
  | .error message =>
      throwError "leader configuration coalescing failed: {message}"
  match
      TraceValidation.coalesceObservations
        [followerReceiveObservation, followerConfigurationObservation]
  with
  | .ok (observations, count) =>
      if observations = [followerReceiveObservation] /\ count = 1 then
        pure ()
      else
        throwError "follower configuration callback was not folded into receive"
  | .error message =>
      throwError "follower configuration folding failed: {message}"
  let completedLeader :=
    { (initialNodeState node0 : NodeState Node TxId) with
      membershipState := .retirementCompleted }
  let completedState : SimState :=
    { (initialState : SimState) with
      nodes := updateNode initialNodes node0 completedLeader
      retirementCompleted :=
        Function.update (fun _ => ∅) node0 {node1} }
  let completedReplicate : TraceValidation.Observation := {
    line := 30
    kind := .replicate
    node := node0
    role := some .leader
    membershipState := some .retirementCompleted
    targetIndex := some 1
    committable := some false
  }
  match TraceValidation.replicateCandidates completedReplicate completedState with
  | .ok [[.appendRetiredCommitted node]] =>
      if node = node0 then
        pure ()
      else
        throwError "retirement replicate selected the wrong node"
  | _ =>
      throwError "retirement replicate was not appendRetiredCommitted"
  match NaiveFullStateWitness.decodeInitialState rawInitialState with
  | .ok state =>
      if state.preVoteStatus node0 = .capable /\
          state.preVoteStatus node1 = .enabled /\
          (state.nodes node1).preVotesGranted =
            ({node0, node1} : Finset Node) then
        pure ()
      else
        throwError "full-state pre-vote fields did not round-trip"
  | .error message =>
      throwError "full-state pre-vote decode failed: {message}"
  match
      NaiveFullStateWitness.decodeQueueSlot
        "request-pre-vote"
        (activeVoteSlot "requestPreVote" 5 false)
  with
  | .ok (.requestPreVote request) =>
      if request.source = node0 /\
          request.destination = node1 /\
          NaiveFullStateWitness.messageTag (.requestPreVote request) = 5 then
        pure ()
      else
        throwError "RequestPreVote endpoints did not round-trip"
  | _ =>
      throwError "RequestPreVote queue decode failed"
  match
      NaiveFullStateWitness.decodeQueueSlot
        "request-pre-vote-response"
        (activeVoteSlot "requestPreVoteResponse" 6 true)
  with
  | .ok (.requestPreVoteResponse response) =>
      if response.source = node0 /\
          response.destination = node1 /\
          response.voteGranted = true /\
          NaiveFullStateWitness.messageTag
            (.requestPreVoteResponse response) = 6 then
        pure ()
      else
        throwError "RequestPreVoteResponse fields did not round-trip"
  | _ =>
      throwError "RequestPreVoteResponse queue decode failed"

end CCFRaft.RuntimeRetirementConsistencyExamples
