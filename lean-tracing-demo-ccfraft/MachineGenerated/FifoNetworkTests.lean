-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Model

set_option autoImplicit false

namespace CCFRaft.FifoNetworkTests

variable {N T : Type} [DecidableEq N] [DecidableEq T]

theorem repeated_send (network : N -> List (Message N T)) (message : Message N T) :
    enqueue (enqueue network message) message message.destination =
      network message.destination ++ [message, message] := by
  simp [enqueue, updateQueue, List.append_assoc]

theorem other_destination (network : N -> List (Message N T)) (message : Message N T)
    (other : N) (different : other ≠ message.destination) :
    enqueue network message other = network other := by
  simp [enqueue, updateQueue, different]

theorem request_vote_repeated [Bootstrap N] (state : State N T) (source destination : N) :
    ((next (next state (.requestVote source destination)) (.requestVote source destination)).network
      destination) =
      state.network destination ++
        [.requestVoteRequest (makeRequestVoteRequest state source destination),
         .requestVoteRequest (makeRequestVoteRequest state source destination)] := by
  simp [next, enqueue, updateQueue, makeRequestVoteRequest, Message.destination, List.append_assoc]

theorem request_pre_vote_repeated [Bootstrap N] (state : State N T) (source destination : N) :
    ((next (next state (.requestPreVote source destination)) (.requestPreVote source destination)).network
      destination) =
      state.network destination ++
        [.requestPreVote (makeRequestPreVote state source destination),
         .requestPreVote (makeRequestPreVote state source destination)] := by
  simp [next, enqueue, updateQueue, makeRequestPreVote, Message.destination, List.append_assoc]

private def node0 : Node := ⟨0, by decide⟩
private def node1 : Node := ⟨1, by decide⟩
private def heartbeatState : State Node Nat := initialState
private def sentOnce : State Node Nat := next heartbeatState (.appendEntries node0 node1 0)
private def sentTwice : State Node Nat := next sentOnce (.appendEntries node0 node1 0)

example : Enabled heartbeatState (.appendEntries node0 node1 0) := by decide
example : Enabled sentOnce (.appendEntries node0 node1 0) := by decide
example : (sentTwice.network node1).length = 2 := by decide
example : (sentTwice.network node1)[0]? = (sentTwice.network node1)[1]? := by decide

example : Enabled sentTwice (.receive node0 node1) := by decide
private def receivedOnce : State Node Nat := next sentTwice (.receive node0 node1)
example : (receivedOnce.network node1).length = 1 := by decide
example : Enabled receivedOnce (.receive node0 node1) := by decide
private def receivedTwice : State Node Nat := next receivedOnce (.receive node0 node1)
example : (receivedTwice.network node1).length = 0 := by decide
example : (receivedTwice.network node0).length = 2 := by decide
example : (receivedTwice.network node0)[0]? = (receivedTwice.network node0)[1]? := by decide

end CCFRaft.FifoNetworkTests

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.FifoNetworkTests).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
