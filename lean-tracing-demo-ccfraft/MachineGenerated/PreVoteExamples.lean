-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.ModelProofs

set_option autoImplicit false

namespace CCFRaft.PreVoteExamples

def node0 : Node := ⟨0, by decide⟩
def node1 : Node := ⟨1, by decide⟩
def node2 : Node := ⟨2, by decide⟩

def enabledBootstrap : Bootstrap Node where
  configuration := DEFAULT_BOOTSTRAP_CONFIGURATION
  leader := DEFAULT_BOOTSTRAP_LEADER
  leader_mem := by decide
  preVoteStatus := fun _ => .enabled

section Enabled

local instance : Bootstrap Node := enabledBootstrap

def successfulPreVoteActions : List (Action Node (Fin 1)) :=
  [
    .becomePreVoteCandidate node1,
    .requestPreVote node1 node0,
    .receive node1 node0,
    .receive node0 node1,
    .requestPreVote node1 node2,
    .receive node1 node2,
    .receive node2 node1,
    .becomeCandidate node1
  ]

/-- Becoming a pre-vote candidate keeps the current term and persistent vote. -/
theorem becomePreVoteCandidateIsSpeculative :
    let before := (initialState : State Node (Fin 1))
    let after := next before (.becomePreVoteCandidate node1)
    (after.nodes node1).role = .preVoteCandidate /\
      (after.nodes node1).currentTerm = (before.nodes node1).currentTerm /\
      (after.nodes node1).votedFor = (before.nodes node1).votedFor := by
  decide

/-- RequestPreVote remains distinct from RequestVote in the FIFO queue. -/
theorem requestPreVotePacketIdentity :
    let before :=
      next
        (initialState : State Node (Fin 1))
        (.becomePreVoteCandidate node1)
    let after := next before (.requestPreVote node1 node0)
    after.network node0 =
      [.requestPreVote (makeRequestPreVote before node1 node0)] := by
  decide

/-- A granted speculative request produces a RequestPreVote response packet. -/
theorem requestPreVoteResponsePacketIdentity :
    let preVoteState :=
      next
        (initialState : State Node (Fin 1))
        (.becomePreVoteCandidate node1)
    let requested :=
      next preVoteState (.requestPreVote node1 node0)
    let received :=
      next requested (.receive node1 node0)
    let response : RequestPreVoteResponse Node := {
      term := TERM_ONE
      voteGranted := true
      source := node0
      destination := node1
    }
    received.network node1 = [.requestPreVoteResponse response] := by
  decide

/-- Same-term AppendEntries needs one receive to step down and one to consume. -/
theorem equalTermAppendEntriesUsesTwoReceives :
    let before := (initialState : State Node (Fin 1))
    let preVoteState :=
      next
        before
        (.becomePreVoteCandidate node1)
    let sent := next preVoteState (.appendEntries node0 node1 0)
    let steppedDown := next sent (.receive node0 node1)
    let completed := next steppedDown (.receive node0 node1)
    Enabled before (.becomePreVoteCandidate node1) /\
      Enabled preVoteState (.appendEntries node0 node1 0) /\
      Enabled sent (.receive node0 node1) /\
      (steppedDown.nodes node1).role = .follower /\
      steppedDown.network node1 = sent.network node1 /\
      Enabled steppedDown (.receive node0 node1) /\
      completed.network node1 = [] := by
  decide

/-- A successful pre-vote advances the term only when regular candidacy starts. -/
theorem successfulPreVote :
    Exists fun final =>
      runActions (initialState : State Node (Fin 1))
          successfulPreVoteActions =
        some final /\
      (final.nodes node1).role = .candidate /\
      (final.nodes node1).currentTerm = TERM_ONE + 1 /\
      (final.nodes node1).votedFor = some node1 /\
      (final.nodes node1).votesGranted = {node1} := by
  decide

/-- Pre-vote-capable recipients grant speculative votes without persisting them. -/
theorem grantedPreVoteDoesNotPersist :
    let preVoteState :=
      next
        (initialState : State Node (Fin 1))
        (.becomePreVoteCandidate node1)
    let requested :=
      next preVoteState (.requestPreVote node1 node0)
    let received :=
      next requested (.receive node1 node0)
    (received.nodes node0).votedFor = none := by
  decide

end Enabled

section Capable

/-- `pre_vote_enabled = false` still starts a regular election on timeout. -/
theorem capableTimeoutBehavior :
    let state := (initialState : State Node (Fin 1))
    Enabled state (.timeout node1) /\
      ((next state (.timeout node1)).nodes node1).role = .candidate /\
      ((next state (.timeout node1)).nodes node1).currentTerm =
        TERM_ONE + 1 /\
      ((next state (.timeout node1)).nodes node1).votedFor = some node1 := by
  decide

end Capable

end CCFRaft.PreVoteExamples
